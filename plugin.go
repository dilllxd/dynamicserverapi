package dynamicserverapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Mutex for synchronizing server access
var (
	serverMutex  sync.Mutex
	serversFile  = "servers.json" // File to store server information
	adminServers = make(map[string]bool)
	authToken    = "" // Authorization token
)

// Plugin is a plugin that hosts a REST API to manage servers with persistence.
var Plugin = proxy.Plugin{
	Name: "DynamicServerAPI",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		// Get the logger for this plugin.
		logger := logr.FromContextOrDiscard(ctx)
		logger.Info("Hello from DynamicServerAPI plugin!")

		// Track initial admin-added servers.
		for _, server := range p.Servers() {
			serverInfo := server.ServerInfo()
			adminServers[serverInfo.Name()] = true
		}

		// Load servers from file and set the authorization token.
		if err := loadConfigFromFile(p); err != nil {
			logger.Error(err, "Failed to load servers from file")
			return err
		}

		// Start the REST API server.
		go func() {
			startAPIServer(logger, p)
		}()

		return nil
	},
}

// Server represents a server entry.
type Server struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// ConcreteServerInfo is a concrete implementation of ServerInfo.
type ConcreteServerInfo struct {
	name    string
	address net.Addr
}

func (c *ConcreteServerInfo) Name() string {
	return c.name
}

func (c *ConcreteServerInfo) Addr() net.Addr {
	return c.address
}

// startAPIServer starts the internal HTTP server.
func startAPIServer(logger logr.Logger, p *proxy.Proxy) {
	http.HandleFunc("/addserver", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var server Server
			if err := decodeJSONBody(r, &server); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := addServer(p, server.Name, server.Address); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Save the new server to the file
			if err := saveServersToFile(p, &server, nil); err != nil {
				http.Error(w, "Failed to save server", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/removeserver", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var server Server
			if err := decodeJSONBody(r, &server); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if adminServers[server.Name] {
				http.Error(w, "Cannot remove admin-added server", http.StatusForbidden)
				return
			}
			if err := removeServer(p, server.Name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Remove the server from the saved file
			if err := saveServersToFile(p, nil, &server); err != nil {
				http.Error(w, "Failed to save servers", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/listservers", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			servers, err := listServers(p)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(servers); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		}
	}))

	serverAddr := ":8080"
	logger.Info("Starting REST API server", "address", serverAddr)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		logger.Error(err, "Failed to start REST API server")
	}
}

// authMiddleware is a middleware function for checking the authorization token.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != authToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// decodeJSONBody decodes JSON body into the given struct.
func decodeJSONBody(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

// addServer adds a new server to the proxy.
func addServer(p *proxy.Proxy, name, address string) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	serverAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return fmt.Errorf("invalid address: %v", err)
	}

	serverInfo := &ConcreteServerInfo{name: name, address: serverAddr}

	result, err := p.Register(serverInfo) // Handle both return values
	if err != nil {
		return err
	}
	_ = result // Optionally use result
	return nil
}

func removeServer(p *proxy.Proxy, name string) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	servers := p.Servers()

	for _, server := range servers {
		serverInfo := server.ServerInfo()
		if serverInfo.Name() == name {
			// Unregister returns a boolean indicating success
			if success := p.Unregister(serverInfo); !success {
				return fmt.Errorf("failed to unregister server: server not found")
			}
			return nil
		}
	}

	return fmt.Errorf("server %s not found", name)
}

// saveServersToFile saves the servers to the file while preserving the auth token.
func saveServersToFile(p *proxy.Proxy, newServer *Server, removedServer *Server) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	var serverList []Server

	// Read existing servers from the file
	file, err := os.Open(serversFile)
	if err == nil {
		defer file.Close()
		var existingConfig struct {
			AuthToken string   `json:"auth_token"`
			Servers   []Server `json:"servers"`
		}
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&existingConfig); err == nil {
			// Preserve the existing servers list, but exclude the removed server
			for _, server := range existingConfig.Servers {
				if removedServer == nil || server.Name != removedServer.Name {
					// Ignore admin servers
					if !adminServers[server.Name] {
						serverList = append(serverList, server)
					}
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Add the new server to the list if provided
	if newServer != nil {
		// Ignore admin servers
		if !adminServers[newServer.Name] {
			serverList = append(serverList, *newServer)
		}
	} else {
		// If no new server is provided, update the list from the proxy servers
		servers := p.Servers()
		for _, server := range servers {
			serverInfo := server.ServerInfo()
			// Ignore admin servers
			if !adminServers[serverInfo.Name()] {
				serverList = append(serverList, Server{
					Name:    serverInfo.Name(),
					Address: serverInfo.Addr().String(),
				})
			}
		}
	}

	// Create the file and save the servers list with the auth token
	config := struct {
		AuthToken string   `json:"auth_token"`
		Servers   []Server `json:"servers"`
	}{
		AuthToken: authToken,
		Servers:   serverList,
	}

	file, err = os.Create(serversFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(config)
}

// loadConfigFromFile loads server list and auth token from a file.
func loadConfigFromFile(p *proxy.Proxy) error {
	file, err := os.Open(serversFile)
	if err != nil {
		if os.IsNotExist(err) {
			// If the file does not exist, create it with default values
			authToken = generateAuthToken() // Generate a new token
			return createDefaultConfigFile()
		}
		return err
	}
	defer file.Close()

	var config struct {
		AuthToken string   `json:"auth_token"`
		Servers   []Server `json:"servers"`
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	authToken = config.AuthToken

	for _, server := range config.Servers {
		if err := addServer(p, server.Name, server.Address); err != nil {
			return err
		}
	}

	return nil
}

// generateAuthToken generates a random authorization token.
func generateAuthToken() string {
	const tokenLength = 32
	tokenBytes := make([]byte, tokenLength)

	// Use crypto/rand for secure random bytes
	_, err := rand.Read(tokenBytes)
	if err != nil {
		// Handle error: log it, use a fallback token, or panic
		// Here, we'll use a predefined fallback token if an error occurs
		return "fallback-token-1234567890abcdef"
	}

	// Encode the bytes in base64
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	return token
}

// listServers lists all servers registered with the proxy.
func listServers(p *proxy.Proxy) ([]Server, error) {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	var serverList []Server
	servers := p.Servers()

	for _, server := range servers {
		serverInfo := server.ServerInfo() // Get the ServerInfo
		serverList = append(serverList, Server{
			Name:    serverInfo.Name(),
			Address: serverInfo.Addr().String(),
		})
	}

	return serverList, nil
}

// createDefaultConfigFile creates the default configuration file with an auth token and empty server list.
func createDefaultConfigFile() error {
	config := struct {
		AuthToken string   `json:"auth_token"`
		Servers   []Server `json:"servers"`
	}{
		AuthToken: authToken,
		Servers:   []Server{},
	}

	file, err := os.Create(serversFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(config)
}

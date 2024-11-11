package dynamicserverapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

const (
	CurrentVersion = "1.0.1"
)

// Mutex for synchronizing server access
var (
	serverMutex  sync.Mutex
	serversFile  = "servers.json" // File to store server information
	adminServers = make(map[string]bool)
	authToken    = ""        // Authorization token
	apiPort      = 8080      // Default port
	apiInterface = "0.0.0.0" // Default interface
)

// Plugin is a plugin that hosts a REST API to manage servers with persistence.
var Plugin = proxy.Plugin{
	Name: "DynamicServerAPI",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		// Get the logger for this plugin.
		logger := logr.FromContextOrDiscard(ctx)
		logger.Info(fmt.Sprintf("DynamicServerAPI: Hello from DynamicServerAPI! Version %s", CurrentVersion))

		// Check for updates.
		hasUpdate, latestVersion, err := CheckForUpdates()
		if err != nil {
			logger.Error(err, "DynamicServerAPI: Error checking for updates")
		} else if hasUpdate {
			logger.Info(fmt.Sprintf("DynamicServerAPI: A new version %s is available. Please update!", latestVersion))
		} else {
			logger.Info("DynamicServerAPI: You are using the latest version.")
		}

		// Track initial admin-added servers.
		for _, server := range p.Servers() {
			serverInfo := server.ServerInfo()
			adminServers[serverInfo.Name()] = true
		}

		// Load servers from file and set the authorization token.
		if err := loadConfigFromFile(p, logger); err != nil {
			logger.Error(err, "DynamicServerAPI: Failed to load servers from file")
			return err
		}

		// Register event handlers.
		event.Subscribe(p.Event(), 0, onPlayerChooseInitialServer(p, logger))
		event.Subscribe(p.Event(), 0, onKickedFromServer(p, logger))

		// Start the REST API server.
		go func() {
			startAPIServer(logger, p)
		}()

		return nil
	},
}

// Server represents a server entry.
type Server struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Fallback bool   `json:"fallback"`
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

type DisconnectKickResult struct {
	Message component.Component
}

// Function to check for updates.
func CheckForUpdates() (bool, string, error) {
	const versionURL = "https://raw.githubusercontent.com/dilllxd/dynamicserverapi/main/version"
	resp, err := http.Get(versionURL)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("DynamicServerAPI: failed to fetch version file: %s", resp.Status)
	}

	latestVersion, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	latestVersionStr := strings.TrimSpace(string(latestVersion))
	if !isValidSemver(latestVersionStr) {
		return false, "", fmt.Errorf("DynamicServerAPI: invalid version format: %s", latestVersionStr)
	}

	return isNewerVersion(latestVersionStr, CurrentVersion), latestVersionStr, nil
}

// Helper functions for version checking
func isValidSemver(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func isNewerVersion(latest, current string) bool {
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	for i := 0; i < 3; i++ {
		latestPart := latestParts[i]
		currentPart := currentParts[i]
		if latestPart > currentPart {
			return true
		} else if latestPart < currentPart {
			return false
		}
	}
	return false
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
			if err := addServer(p, server.Name, server.Address, server.Fallback); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := saveServersToFile(p, &server, nil); err != nil {
				http.Error(w, "DynamicServerAPI: Failed to save server, check your logs.", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "DynamicServerAPI: Invalid request method, you need to use POST.", http.StatusMethodNotAllowed)
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
				http.Error(w, "DynamicServerAPI: Cannot remove admin-added server, make sure your server is not already in config.yml.", http.StatusForbidden)
				return
			}
			if err := removeServer(p, server.Name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := saveServersToFile(p, nil, &server); err != nil {
				http.Error(w, "DynamicServerAPI: Failed to save servers, check your logs.", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "DynamicServerAPI: Invalid request method, you need to use POST.", http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/listservers", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			servers, err := listServers(p, logger) // Pass logger here
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(servers); err != nil {
				http.Error(w, "DynamicServerAPI: Failed to encode response to JSON, make sure you are using the proper format.", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "DynamicServerAPI: Invalid request method, you need to use GET.", http.StatusMethodNotAllowed)
		}
	}))

	serverAddr := fmt.Sprintf("%s:%d", apiInterface, apiPort)
	logger.Info("DynamicServerAPI: Starting REST API server at:", "address", serverAddr)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		logger.Error(err, "DynamicServerAPI: Failed to start REST API server")
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
func addServer(p *proxy.Proxy, name, address string, fallback bool) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	serverAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return fmt.Errorf("DynamicServerAPI: invalid address: %v", err)
	}

	serverInfo := &ConcreteServerInfo{name: name, address: serverAddr}

	result, err := p.Register(serverInfo)
	if err != nil {
		return err
	}
	_ = result // Optionally use result

	return nil
}

// removeServer removes a server from the proxy.
func removeServer(p *proxy.Proxy, name string) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	servers := p.Servers()

	for _, server := range servers {
		serverInfo := server.ServerInfo()
		if serverInfo.Name() == name {
			if success := p.Unregister(serverInfo); !success {
				return fmt.Errorf("DynamicServerAPI: failed to unregister server: server not found")
			}
			return nil
		}
	}

	return fmt.Errorf("DynamicServerAPI: server %s not found", name)
}

// saveServersToFile saves the servers to the file while preserving the auth token.
func saveServersToFile(p *proxy.Proxy, newServer *Server, removedServer *Server) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	var serverList []Server

	// Open the existing configuration file
	file, err := os.Open(serversFile)
	if err == nil {
		defer file.Close()
		var existingConfig struct {
			AuthToken     string   `json:"auth_token"`
			API_Port      int      `json:"api_port"`
			API_Interface string   `json:"api_interface"`
			Servers       []Server `json:"servers"`
		}
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&existingConfig); err == nil {
			// Preserve API settings
			apiPort = existingConfig.API_Port
			apiInterface = existingConfig.API_Interface

			// Add existing servers to the new list, excluding the removed server
			for _, server := range existingConfig.Servers {
				if removedServer == nil || server.Name != removedServer.Name {
					if !adminServers[server.Name] {
						serverList = append(serverList, server)
					}
				}
			}
		} else {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Add the new server if provided
	if newServer != nil {
		if !adminServers[newServer.Name] {
			// Check for duplicate entries before adding
			exists := false
			for _, srv := range serverList {
				if srv.Name == newServer.Name {
					exists = true
					break
				}
			}
			if !exists {
				serverList = append(serverList, *newServer)
			}
		}
	} else {
		// If no new server is being added, update with current servers
		servers := p.Servers()
		for _, server := range servers {
			serverInfo := server.ServerInfo()
			if !adminServers[serverInfo.Name()] {
				// Check for duplicate entries before adding
				exists := false
				for _, srv := range serverList {
					if srv.Name == serverInfo.Name() {
						exists = true
						break
					}
				}
				if !exists {
					serverList = append(serverList, Server{
						Name:     serverInfo.Name(),
						Address:  serverInfo.Addr().String(),
						Fallback: false, // Default value for fallback
					})
				}
			}
		}
	}

	config := struct {
		AuthToken     string   `json:"auth_token"`
		API_Port      int      `json:"api_port"`
		API_Interface string   `json:"api_interface"`
		Servers       []Server `json:"servers"`
	}{
		AuthToken:     authToken,
		API_Port:      apiPort,
		API_Interface: apiInterface,
		Servers:       serverList,
	}

	// Save the updated configuration with pretty-printing
	return writeConfigToFile(config)
}

// loadConfigFromFile loads server list and auth token from a file and validates/updates config if needed.
func loadConfigFromFile(p *proxy.Proxy, logger logr.Logger) error {
	file, err := os.Open(serversFile)
	if err != nil {
		if os.IsNotExist(err) {
			authToken = generateAuthToken() // Generate a new token
			return createDefaultConfigFile(logger)
		}
		return err
	}
	defer file.Close()

	var config struct {
		AuthToken     string   `json:"auth_token,omitempty"`
		API_Port      int      `json:"api_port,omitempty"`
		API_Interface string   `json:"api_interface,omitempty"`
		Servers       []Server `json:"servers,omitempty"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	// Validate and correct configuration
	if config.AuthToken == "" {
		config.AuthToken = generateAuthToken()
		logger.Info("DynamicServerAPI: Generated new authorization token due to invalid/blank token.", "token", config.AuthToken) // Log the generated token
	}

	if config.Servers == nil {
		config.Servers = []Server{}
	}

	if config.API_Port == 0 {
		config.API_Port = 8080 // Default port
	}

	if config.API_Interface == "" {
		config.API_Interface = "0.0.0.0" // Default interface
	}

	// Write the corrected config back to the file
	if err := writeConfigToFile(config); err != nil {
		return err
	}

	authToken = config.AuthToken
	apiPort = config.API_Port
	apiInterface = config.API_Interface

	for _, server := range config.Servers {
		if !adminServers[server.Name] {
			err := addServer(p, server.Name, server.Address, server.Fallback)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeConfigToFile writes the given config to the configuration file.
func writeConfigToFile(config interface{}) error {
	file, err := os.Create(serversFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty-print JSON with 2 spaces
	return encoder.Encode(config)
}

// createDefaultConfigFile creates a default config file with auth token and default values.
func createDefaultConfigFile(logger logr.Logger) error {
	config := struct {
		AuthToken     string   `json:"auth_token"`
		API_Port      int      `json:"api_port"`
		API_Interface string   `json:"api_interface"`
		Servers       []Server `json:"servers"`
	}{
		AuthToken:     generateAuthToken(),
		API_Port:      8080,
		API_Interface: "0.0.0.0",
		Servers:       []Server{}, // Ensure servers section is present
	}

	// Log the generated token
	logger.Info("DynamicServerAPI: Generated new authorization token due to config being generated.", "token", config.AuthToken)

	// Write the config to file
	return writeConfigToFile(config)
}

// generateAuthToken generates a new authorization token.
func generateAuthToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic("DynamicServerAPI: failed to generate random token")
	}
	return base64.StdEncoding.EncodeToString(b)
}

// listServers returns a list of servers.
func listServers(p *proxy.Proxy, logger logr.Logger) ([]Server, error) {
	var serverList []Server
	servers := p.Servers()

	if len(servers) == 0 {
		logger.Info("DynamicServerAPI: No servers found.")
	}

	for _, server := range servers {
		serverInfo := server.ServerInfo()
		fallback := isFallbackServer(serverInfo.Name())
		serverList = append(serverList, Server{
			Name:     serverInfo.Name(),
			Address:  serverInfo.Addr().String(),
			Fallback: fallback,
		})
	}
	return serverList, nil
}

// onPlayerChooseInitialServer handles the PlayerChooseInitialServerEvent to direct players.
func onPlayerChooseInitialServer(p *proxy.Proxy, log logr.Logger) func(*proxy.PlayerChooseInitialServerEvent) {
	return func(e *proxy.PlayerChooseInitialServerEvent) {
		handlePlayerJoin(p, e, log)
	}
}

var fallbackServersMap = make(map[proxy.Player][]proxy.RegisteredServer)

// handlePlayerJoin handles player join events and chooses the server.
func handlePlayerJoin(p *proxy.Proxy, event *proxy.PlayerChooseInitialServerEvent, log logr.Logger) {
	var fallbackServers []proxy.RegisteredServer

	servers := p.Servers()
	for _, server := range servers {
		serverInfo := server.ServerInfo()
		if isFallbackServer(serverInfo.Name()) {
			fallbackServers = append(fallbackServers, server)
		}
	}

	if len(fallbackServers) > 0 {
		// Set the initial server to the first fallback server
		event.SetInitialServer(fallbackServers[0])

		// Track player and fallback servers for redirection
		player := event.Player()
		fallbackServersMap[player] = fallbackServers
	} else {
		// No fallback servers available
		msg := "There are currently no available fallback servers. Please try again later."
		log.Info(msg)
		player := event.Player()
		player.Disconnect(&component.Text{Content: msg})
	}
}

func onKickedFromServer(p *proxy.Proxy, log logr.Logger) func(*proxy.KickedFromServerEvent) {
	return func(e *proxy.KickedFromServerEvent) {
		handlePlayerKick(p, e, log)
	}
}

var (
	redirectAttempts = make(map[proxy.Player]int)
	mu               sync.Mutex // Declare mutex here
)

func handlePlayerKick(p *proxy.Proxy, event *proxy.KickedFromServerEvent, log logr.Logger) {
	server := event.Server()
	player := event.Player()

	mu.Lock()
	attempts, exists := redirectAttempts[player]
	if !exists {
		attempts = 0
	}
	redirectAttempts[player] = attempts + 1
	mu.Unlock()

	// Retrieve fallback servers and exclude the current server
	var fallbackServers []proxy.RegisteredServer
	servers := p.Servers()
	for _, s := range servers {
		if isFallbackServer(s.ServerInfo().Name()) && s != server {
			fallbackServers = append(fallbackServers, s)
		}
	}

	// Check if there are any fallback servers available
	if len(fallbackServers) == 0 {
		// No fallback servers available, disconnect player
		msg := "Unable to connect to any fallback servers. You have been disconnected."
		log.Info(msg)
		event.SetResult(&proxy.DisconnectPlayerKickResult{
			Reason: &component.Text{Content: msg},
		})
		return
	}

	// Attempt to redirect to the next available fallback server
	if attempts < len(fallbackServers) {
		fallback := fallbackServers[attempts%len(fallbackServers)]
		result := &proxy.RedirectPlayerKickResult{
			Server: fallback,
		}
		log.Info("DynamicServerAPI: Attempting to redirect player to server " + fallback.ServerInfo().Name())
		event.SetResult(result)
		return
	}

	// If all attempts are exhausted or maximum attempts reached, disconnect the player
	msg := "Unable to connect to any fallback servers. You have been disconnected."
	log.Info(msg)
	event.SetResult(&proxy.DisconnectPlayerKickResult{
		Reason: &component.Text{Content: msg},
	})

	mu.Lock()
	delete(redirectAttempts, player) // Reset attempts after disconnect
	mu.Unlock()
}

// isFallbackServer checks if a server is a fallback server.
func isFallbackServer(name string) bool {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	// Retrieve server list from file or in-memory cache
	file, err := os.Open(serversFile)
	if err != nil {
		return false
	}
	defer file.Close()

	var config struct {
		Servers []Server `json:"servers"`
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return false
	}

	for _, server := range config.Servers {
		if server.Name == name {
			return server.Fallback
		}
	}
	return false
}

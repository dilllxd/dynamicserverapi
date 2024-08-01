# DynamicServerAPI for Gate

**DynamicServerAPI** is a plugin for the [Gate](https://gate.minekube.com/) proxy that allows you to dynamically add and remove servers from your proxy!

## Getting Started

### 1. Add the Package

Add the `dynamicserverapi` package to your Gate project:

```bash
go get github.com/dilllxd/dynamicserverapi
```

### 2. Register the Plugin

Include the plugin in your `main()` function:

```go
func main() {
    proxy.Plugins = append(proxy.Plugins,
        // your plugins
        dynamicserverapi.Plugin,
    )
    gate.Execute()
}
```

### 3. Configure the Plugin

After starting your server, a new file named `servers.json` will be created. You can add servers using the Web API or you can add them manually:

```json
[{"name":"server1","address":"localhost:25566"},{"name":"server2","address":"localhost:25567"},{"name":"exampleserver1","address":"127.0.0.1:25566"},{"name":"exampleserver2","address":"127.0.0.1:25567"}]
```

## API Documentation

The plugin exposes a REST API to manage servers dynamically.

### 1. Add a Server

**Endpoint:** `/addserver`  
**Method:** `POST`  
**Description:** Adds a new server to the proxy.

**Request Body:**
```json
{
    "name": "serverName",
    "address": "serverAddress"
}
```

**Example Request:**
```bash
http POST http://localhost:8080/addserver name="NewServer" address="127.0.0.1:25565"
```

### 2. Remove a Server

**Endpoint:** `/removeserver`  
**Method:** `POST`  
**Description:** Removes a server from the proxy. Servers added by the admin (before the plugin initializes) cannot be removed.

**Request Body:**
```json
{
    "name": "serverName"
}
```

**Example Request:**
```bash
http POST http://localhost:8080/removeserver name="NewServer"
```

### 3. List Servers

**Endpoint:** `/listservers`  
**Method:** `GET`  
**Description:** Lists all servers currently registered with the proxy.

**Example Request:**
```bash
http GET http://localhost:8080/listservers
```

**Response:**
```json
[
    {"name":"server1","address":"localhost:25566"},
    {"name":"server2","address":"localhost:25567"},
    {"name":"NewServer","address":"127.0.0.1:25565"}
]
```

## Notes

- **Admin-Added Servers:** Servers that were added to the proxy before the plugin initializes are marked as admin-added. These servers cannot be removed using the REST API to ensure they remain in the proxy unless explicitly managed by the admin.

---

Feel free to reach out if you have any questions or need further assistance with setting up the DynamicServerAPI plugin for Gate.

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

After starting your server, a new file named `servers.json` will be created. This will include a Authorization token that is randomly generated that you can use to add servers using the REST API. You can also choose to add servers manually using this file format:

```json
{
  "auth_token": "your_generated_token",
  "api_port": 8080,
  "api_interface": "0.0.0.0",
  "servers": [
    {"name":"exampleserver1","address":"127.0.0.1:25566","fallback": true},
    {"name":"exampleserver2","address":"127.0.0.1:25567","fallback": false}
  ]
}
```

## API Documentation

The plugin exposes a REST API to manage servers dynamically.

### 1. Add a Server

**Endpoint:** `/addserver`  
**Method:** `POST`  
**Description:** Adds a new server to the proxy.

**Request Headers:**
```
Authorization: your_generated_token
```

**Request Body:**
```json
{
    "name": "serverName",
    "address": "serverAddress",
    "fallback": true
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/addserver \
  -H "Authorization: your_generated_token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "NewServer",
    "address": "127.0.0.1:25565",
    "fallback": true
  }'

```

### 2. Remove a Server

**Endpoint:** `/removeserver`  
**Method:** `POST`  
**Description:** Removes a server from the proxy. Servers added by the admin (before the plugin initializes) cannot be removed.

**Request Headers:**
```
Authorization: your_generated_token
```

**Request Body:**
```json
{
    "name": "serverName"
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/removeserver \
  -H "Content-Type: application/json" \
  -H "Authorization: your_generated_token" \
  -d '{"name": "NewServer"}'
```

### 3. List Servers

**Endpoint:** `/listservers`  
**Method:** `GET`  
**Description:** Lists all servers currently registered with the proxy.

**Request Headers:**
```
Authorization: your_generated_token
```

**Example Request:**
```bash
curl -X GET http://localhost:8080/listservers \
  -H "Authorization: your_generated_token"
```

**Response:**
```json
[
    {"name":"server1","address":"localhost:25566","fallback": true},
    {"name":"server2","address":"localhost:25567","fallback": false},
    {"name":"NewServer","address":"127.0.0.1:25565","fallback": true}
]
```

## Notes

- **Admin-Added Servers:** Servers that were added to the proxy before the plugin initializes are marked as admin-added. These servers cannot be removed using the REST API to ensure they remain in the proxy unless explicitly managed by the admin.
- **Authorization Token:** Ensure you keep your `auth_token` secure and update the `servers.json` file if you need to change it.
- **Server Persistence:** When a server is added through the REST API, it is saved to the `servers.json` file. Upon each server restart, the plugin reads the `servers.json` file and registers all non-admin servers listed. Admin-added servers (those present before the plugin initializes) are preserved but not modified by the plugin.
- **REST API:** REST API port and address are fully configurable now as of v1.0.0.
---

Feel free to reach out if you have any questions or need further assistance with setting up the DynamicServerAPI plugin for Gate.

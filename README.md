# Nanika

Android tunnel client with three protocols: SSH over WebSocket, VLESS and VMess.

## Features
- SSH WebSocket with custom payload, proxy host, TLS / SNI or plain port 80
- VLESS and VMess over WebSocket
- Server list fetched from the server-list endpoint (server address, login and UUID only)
- Encrypted `.anika` configuration files, JSON and link import / export, protection options
- HTML banner and message rendering with safe links
- In-app updater and HWID lock
- Sharenet: share the tunnel with other devices on the same network (HTTP / SOCKS5 proxy, PAC file, hotspot)
- Live upload / download speed graph

## Build
```
./gradlew assembleDebug
```
Set `API_TOKEN` in `servers/ServerList.java` to the token your server-list host expects.

 # Pictures
 https://github.com/Andreaz254/nanika/blob/main/image.png

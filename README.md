# Nexus Proxy

A SOCKS5 proxy server with UDP ASSOCIATE support for HTTP/3 QUIC and gaming traffic.

## About

This project was created to test UDP proxy support in [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge), a WinDivert-based Windows transparent proxy client.

## Features

- **TCP CONNECT**: Standard TCP proxying
- **UDP ASSOCIATE**: Full bidirectional UDP relay with persistent sockets
- **HTTP/3 QUIC Support**: Maintains stable 5-tuple for QUIC connections
- **CLI Arguments**: Configurable host, port, and authentication
- **Optional Authentication**: Username/password support (RFC 1929)

## Installation

```bash
npm install
```

## Usage

### Basic

```bash
node script.js
```

Default: `127.0.0.1:1080` with no authentication

### With Options

```bash
# Listen on all interfaces
node script.js --host 0.0.0.0 --port 1080

# With authentication
node script.js --username user --password pass

# Show help
node script.js --help
```

### CLI Options

- `--host, -h`: Bind IP address (default: 127.0.0.1)
- `--port, -p`: Listen port (default: 1080)
- `--username, -u`: Username for authentication (optional)
- `--password, -P`: Password for authentication (optional)

## Testing

Configure your application to use SOCKS5 proxy at the configured address.

For HTTP/3 testing with ProxyBridge, this server provides the necessary UDP ASSOCIATE support with persistent relay sockets required for QUIC connections.

## License

MIT

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
npm install -g nexus-proxy
```

Or for development:

```bash
git clone https://github.com/InterceptSuite/nexus-proxy.git
cd nexus-proxy
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
- `--username, -u`: Username for authentication (optional, must be given together with `--password`)
- `--password, -P`: Password for authentication (optional, must be given together with `--username`)
- `--verbose, -v`: Log connections and UDP destinations
- `--max-per-ip <n>`: Maximum simultaneous connections from one client address (default: 500). Every UDP association keeps one
  TCP control connection open, so a client that opens many UDP flows needs a higher value. Refused connections are logged as `[LIMIT]`.

## Behaviour worth knowing

- **UDP ASSOCIATE** serves only the client that asked for it (RFC 1928): datagrams from any other address are ignored, so the
  UDP relay port cannot be used by third parties even though it listens on every interface. Replies are told apart from client
  packets by where they come from, not by their first bytes. IPv4 and IPv6 destinations (and host names) work through one
  dual-stack socket; where the host has no IPv6 an IPv4 socket is used.
- A datagram that cannot be delivered (unknown host, port 0, ...) is dropped on its own; it never ends the association or the server.
- **TCP half-close** is passed on: a client that has finished sending and shut down its side still receives the answer.
- The handshake may arrive in pieces or together with the request; both work.
- Connection failures are reported with the matching SOCKS5 code (refused, network or host unreachable, TTL expired) instead of
  always "connection refused".
- With `--username` the proxy requires `--password` too (otherwise it would silently run open).

## Testing

```bash
node --test               # Node.js 18 or newer, no dependencies (or: npm test)
```

The tests start the proxy on a free port and cover the handshake (split, coalesced, authenticated), TCP forwarding, half-close,
error codes, the per-address limit, and UDP (IPv4, IPv6, host names, large datagrams, answers that begin with two zero bytes,
strangers, undeliverable datagrams, port 0, closing the control connection).

To use it with an application, configure the application's SOCKS5 proxy setting to the configured address. For HTTP/3 testing with
[ProxyBridge](https://github.com/InterceptSuite/ProxyBridge), this server provides the UDP ASSOCIATE support with persistent relay
sockets that QUIC connections need.

## License

MIT

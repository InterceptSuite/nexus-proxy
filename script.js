const net = require('net');
const dgram = require('dgram');

const args = process.argv.slice(2);
const config = {
  host: '127.0.0.1',
  port: 1080,
  username: null,
  password: null,
  verbose: false
};

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--host' || args[i] === '-h') {
    config.host = args[++i];
  } else if (args[i] === '--port' || args[i] === '-p') {
    config.port = parseInt(args[++i]);
  } else if (args[i] === '--username' || args[i] === '-u') {
    config.username = args[++i];
  } else if (args[i] === '--password' || args[i] === '-P') {
    config.password = args[++i];
  } else if (args[i] === '--verbose' || args[i] === '-v') {
    config.verbose = true;
  } else if (args[i] === '--help') {
    console.log(`Usage: node script.js [options]
Options:
  -h, --host <ip>        Bind IP address (default: 127.0.0.1)
  -p, --port <port>      SOCKS5 port (default: 1080)
  -u, --username <user>  Authentication username (optional)
  -P, --password <pass>  Authentication password (optional)
  -v, --verbose          Enable detailed logging
  --help                 Show this help message`);
    process.exit(0);
  }
}

class SOCKS5Server {
  constructor(config) {
    this.config = config;
    this.server = net.createServer();
    this.server.maxConnections = 10000; // Prevent resource exhaustion
    this.activeConnections = 0;
    this.udpClients = new Map();
    this.connectionsByIP = new Map(); // Track connections per IP
    this.server.on('connection', this.handleConnection.bind(this));

    // Cleanup stale UDP clients every 5 minutes
    setInterval(() => this.cleanupStaleUDPClients(), 300000);
  }

  cleanupStaleUDPClients() {
    const now = Date.now();
    for (const [key, client] of this.udpClients.entries()) {
      // Remove if socket is destroyed or last activity > 15 min
      if (client.socket.destroyed || (now - (client.lastActivity || 0)) > 900000) {
        if (client.udpRelay) client.udpRelay.close();
        if (client.remoteMap) client.remoteMap.clear();
        this.udpClients.delete(key);
      }
    }
  }

  handleConnection(socket) {
    const ip = socket.remoteAddress;

    // Rate limiting: max 500 connections per IP
    const ipCount = this.connectionsByIP.get(ip) || 0;
    if (ipCount >= 500) {
      socket.destroy();
      return;
    }

    this.activeConnections++;
    this.connectionsByIP.set(ip, ipCount + 1);

    if (this.config.verbose) {
      console.log(`[TCP] ${ip}:${socket.remotePort} (active: ${this.activeConnections})`);
    }

    socket.setTimeout(60000); // 60s timeout for handshake
    socket.once('data', (data) => {
      socket.setTimeout(0); // Clear timeout after successful handshake
      this.handleAuthNegotiation(socket, data);
    });

    socket.on('error', (err) => {
      // Ignore common errors but log critical ones
      if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
        console.error(`[ERR] ${err.code}`);
      }
    });

    socket.on('close', () => {
      this.activeConnections--;
      const count = this.connectionsByIP.get(ip) || 1;
      if (count <= 1) {
        this.connectionsByIP.delete(ip);
      } else {
        this.connectionsByIP.set(ip, count - 1);
      }
    });
  }

  handleAuthNegotiation(socket, data) {
    if (data.length < 3 || data[0] !== 0x05) {
      socket.end();
      return;
    }

    const authRequired = this.config.username && this.config.password;

    if (authRequired) {
      const methods = Array.from(data.slice(2, 2 + data[1]));
      if (!methods.includes(0x02)) {
        socket.write(Buffer.from([0x05, 0xFF]));
        socket.end();
        return;
      }
      socket.write(Buffer.from([0x05, 0x02]));
      socket.once('data', (authData) => {
        this.handleAuth(socket, authData);
      });
    } else {
      socket.write(Buffer.from([0x05, 0x00]));
      socket.once('data', (data) => {
        this.handleRequest(socket, data);
      });
    }
  }

  handleAuth(socket, data) {
    if (data.length < 3 || data[0] !== 0x01) {
      socket.end();
      return;
    }

    const usernameLen = data[1];
    const username = data.slice(2, 2 + usernameLen).toString();
    const passwordLen = data[2 + usernameLen];
    const password = data.slice(3 + usernameLen, 3 + usernameLen + passwordLen).toString();

    if (username === this.config.username && password === this.config.password) {
      socket.write(Buffer.from([0x01, 0x00]));
      socket.once('data', (data) => {
        this.handleRequest(socket, data);
      });
    } else {
      socket.write(Buffer.from([0x01, 0x01]));
      socket.end();
    }
  }

  handleRequest(socket, data) {
    if (data.length < 4 || data[0] !== 0x05) {
      socket.end();
      return;
    }

    const cmd = data[1];
    const atyp = data[3];
    let host, port;

    if (atyp === 0x01) {
      if (data.length < 10) {
        socket.end();
        return;
      }
      host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
      port = data.readUInt16BE(8);
    } else if (atyp === 0x03) {
      if (data.length < 5) {
        socket.end();
        return;
      }
      const domainLength = data[4];
      if (data.length < 5 + domainLength + 2) {
        socket.end();
        return;
      }
      host = domainLength === 0 ? '0.0.0.0' : data.slice(5, 5 + domainLength).toString();
      port = data.readUInt16BE(5 + domainLength);
    } else if (atyp === 0x04) {
      if (data.length < 22) {
        socket.end();
        return;
      }
      const ipv6Parts = [];
      for (let i = 0; i < 16; i += 2) {
        ipv6Parts.push(data.readUInt16BE(4 + i).toString(16));
      }
      host = ipv6Parts.join(':');
      port = data.readUInt16BE(20);
    } else {
      socket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
      return;
    }

    if (cmd === 0x01) {
      this.handleConnect(socket, host, port);
    } else if (cmd === 0x03) {
      this.handleUDPAssociate(socket, host, port);
    } else {
      socket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
    }
  }

  isBroadcastIP(host) {
    const ipv4Regex = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    const match = host.match(ipv4Regex);
    if (!match) {
      // IPv6 - check for multicast (ff00::/8)
      return host.toLowerCase().startsWith('ff');
    }
    const [, a, , , d] = match.map(Number);
    return d === 255 || (a === 255) || a >= 224;
  }

  isHTTP3Port(port) {
    // Common HTTP/3 ports: 443 (HTTPS), 80 (HTTP), 8080, 8443
    return port === 443 || port === 80 || port === 8080 || port === 8443;
  }

  detectQUICPacket(data) {
    // QUIC packets start with specific header flags
    // Long header: 1xxx xxxx (0x80-0xFF)
    // Short header: 0xxx xxxx (0x00-0x7F)
    if (data.length < 1) return false;

    const firstByte = data[0];
    // Check for QUIC long header (version negotiation, initial, 0-RTT, handshake)
    if ((firstByte & 0x80) !== 0) {
      // Long header detected - likely QUIC
      return true;
    }
    // Short header (1-RTT) packets are harder to detect reliably
    // But we can check for common patterns
    return false;
  }

  handleConnect(socket, host, port) {
    if (this.isBroadcastIP(host)) {
      socket.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
      return;
    }

    // Performance: larger buffers and disable Nagle's algorithm
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 60000);

    const targetSocket = net.createConnection(port, host);
    targetSocket.setNoDelay(true);
    targetSocket.setKeepAlive(true, 60000);

    targetSocket.on('connect', () => {
      if (this.config.verbose) {
        console.log(`[CONNECT] ${host}:${port}`);
      }
      socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

      // Backpressure handling: pause if buffers fill
      socket.pipe(targetSocket).on('drain', () => socket.resume());
      targetSocket.pipe(socket).on('drain', () => targetSocket.resume());

      socket.on('error', () => {
        targetSocket.destroy();
      });
    });

    targetSocket.on('error', (err) => {
      if (!socket.destroyed) {
        socket.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        socket.end();
      }
    });

    targetSocket.on('close', () => {
      if (!socket.destroyed) socket.end();
    });

    socket.on('close', () => {
      if (!targetSocket.destroyed) targetSocket.destroy();
    });
  }

  handleUDPAssociate(socket, host, port) {
    const udpRelay = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: false, recvBufferSize: 212992, sendBufferSize: 212992 });
    const clientKey = `${socket.remoteAddress}:${socket.remotePort}`;
    const remoteMap = new Map();
    let cleanupTimer = null;
    const requestedDest = `${host}:${port}`;

    udpRelay.on('error', () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
    });

    udpRelay.on('message', (msg, rinfo) => {
      this.handleUDPMessage(msg, rinfo, udpRelay, remoteMap);
    });

    udpRelay.bind(0, '0.0.0.0', () => {
      const udpPort = udpRelay.address().port;

      this.udpClients.set(clientKey, {
        socket,
        address: socket.remoteAddress,
        port: socket.remotePort,
        udpRelay,
        remoteMap,
        lastActivity: Date.now()
      });

      const serverLocalAddress = socket.localAddress.replace('::ffff:', '');
      const serverIpParts = serverLocalAddress.split('.');
      const response = Buffer.alloc(10);
      response[0] = 0x05;
      response[1] = 0x00;
      response[2] = 0x00;
      response[3] = 0x01;
      response[4] = parseInt(serverIpParts[0] || 127);
      response[5] = parseInt(serverIpParts[1] || 0);
      response[6] = parseInt(serverIpParts[2] || 0);
      response[7] = parseInt(serverIpParts[3] || 1);
      response.writeUInt16BE(udpPort, 8);
      socket.write(response);

      if (this.config.verbose) {
        console.log(`[UDP] ${clientKey} → relay ${serverLocalAddress}:${udpPort}`);
      }

      cleanupTimer = setInterval(() => {
        const now = Date.now();
        for (const [key, info] of remoteMap.entries()) {
          if (now - info.lastActivity > 600000) {
            remoteMap.delete(key);
          }
        }
      }, 300000);

      socket.on('close', () => {
        if (cleanupTimer) clearInterval(cleanupTimer);
        this.udpClients.delete(clientKey);
        remoteMap.clear();
        udpRelay.close();
      });

      socket.on('error', () => {
        if (cleanupTimer) clearInterval(cleanupTimer);
        this.udpClients.delete(clientKey);
        remoteMap.clear();
        udpRelay.close();
      });
    });
  }

  handleUDPMessage(msg, rinfo, udpRelay, remoteMap) {
    const isFromClient = msg.length >= 10 && msg[0] === 0x00 && msg[1] === 0x00;

    if (isFromClient) {
      this.handleClientToRemote(msg, rinfo, udpRelay, remoteMap);
    } else {
      this.handleRemoteToClient(msg, rinfo, udpRelay, remoteMap);
    }
  }

  handleClientToRemote(msg, rinfo, udpRelay, remoteMap) {
    if (msg.length < 10 || msg[0] !== 0x00 || msg[1] !== 0x00 || msg[2] !== 0x00) return;

    // Update activity for UDP client tracking
    for (const client of this.udpClients.values()) {
      if (client.udpRelay === udpRelay) {
        client.lastActivity = Date.now();
        break;
      }
    }

    const atyp = msg[3];
    let host, port, dataStart;

    if (atyp === 0x01) {
      host = `${msg[4]}.${msg[5]}.${msg[6]}.${msg[7]}`;
      port = msg.readUInt16BE(8);
      dataStart = 10;
    } else if (atyp === 0x03) {
      const domainLength = msg[4];
      host = msg.slice(5, 5 + domainLength).toString();
      port = msg.readUInt16BE(5 + domainLength);
      dataStart = 7 + domainLength;
    } else if (atyp === 0x04) {
      if (msg.length < 22) return;
      const ipv6Parts = [];
      for (let i = 0; i < 16; i += 2) {
        ipv6Parts.push(msg.readUInt16BE(4 + i).toString(16));
      }
      host = ipv6Parts.join(':');
      port = msg.readUInt16BE(20);
      dataStart = 22;
    } else {
      return;
    }

    if (this.isBroadcastIP(host)) return;

    const data = msg.slice(dataStart);
    const remoteKey = `${host}:${port}`;

    const isNewDestination = !remoteMap.has(remoteKey);
    const isHTTP3Likely = this.isHTTP3Port(port);
    const isQUIC = this.detectQUICPacket(data);

    remoteMap.set(remoteKey, {
      clientAddr: rinfo.address,
      clientPort: rinfo.port,
      lastActivity: Date.now(),
      isHTTP3: isHTTP3Likely || isQUIC
    });

    if (isNewDestination && this.config.verbose) {
      let protocol = '';
      if (isQUIC) {
        protocol = ' [HTTP/3 QUIC detected]';
      } else if (isHTTP3Likely) {
        protocol = ' [likely HTTP/3]';
      }
      console.log(`  └─> ${host}:${port}${protocol}`);
    }

    udpRelay.send(data, port, host);
  }

  handleRemoteToClient(msg, rinfo, udpRelay, remoteMap) {
    const remoteKey = `${rinfo.address}:${rinfo.port}`;
    const clientInfo = remoteMap.get(remoteKey);

    if (!clientInfo) return;

    clientInfo.lastActivity = Date.now();

    // Detect if IPv4 or IPv6
    const isIPv6 = rinfo.address.includes(':');
    let responsePacket;

    if (isIPv6) {
      // IPv6 response packet
      responsePacket = Buffer.allocUnsafe(22 + msg.length);
      responsePacket[0] = 0x00;
      responsePacket[1] = 0x00;
      responsePacket[2] = 0x00;
      responsePacket[3] = 0x04; // ATYP for IPv6
      
      const ipv6Parts = rinfo.address.split(':');
      for (let i = 0; i < 8; i++) {
        const part = ipv6Parts[i] || '0';
        responsePacket.writeUInt16BE(parseInt(part, 16), 4 + i * 2);
      }
      responsePacket.writeUInt16BE(rinfo.port, 20);
      msg.copy(responsePacket, 22);
    } else {
      // IPv4 response packet
      responsePacket = Buffer.allocUnsafe(10 + msg.length);
      responsePacket[0] = 0x00;
      responsePacket[1] = 0x00;
      responsePacket[2] = 0x00;
      responsePacket[3] = 0x01; // ATYP for IPv4

      const ipParts = rinfo.address.split('.');
      responsePacket[4] = parseInt(ipParts[0]);
      responsePacket[5] = parseInt(ipParts[1]);
      responsePacket[6] = parseInt(ipParts[2]);
      responsePacket[7] = parseInt(ipParts[3]);
      responsePacket.writeUInt16BE(rinfo.port, 8);
      msg.copy(responsePacket, 10);
    }

    udpRelay.send(responsePacket, clientInfo.clientPort, clientInfo.clientAddr);
  }

  listen(port, host, callback) {
    this.server.listen(port, host, callback);
  }
}

const proxy = new SOCKS5Server(config);
proxy.listen(config.port, config.host, () => {
  console.log(`SOCKS5 proxy server listening on ${config.host}:${config.port}`);
  if (config.username) {
    console.log(`Authentication: enabled (username: ${config.username})`);
  } else {
    console.log('Authentication: disabled');
  }
});

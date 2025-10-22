const net = require('net');
const dgram = require('dgram');

const args = process.argv.slice(2);
const config = {
  host: '127.0.0.1',
  port: 1080,
  username: null,
  password: null
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
  } else if (args[i] === '--help') {
    console.log(`Usage: node script.js [options]
Options:
  -h, --host <ip>        Bind IP address (default: 127.0.0.1)
  -p, --port <port>      SOCKS5 port (default: 1080)
  -u, --username <user>  Authentication username (optional)
  -P, --password <pass>  Authentication password (optional)
  --help                 Show this help message`);
    process.exit(0);
  }
}

class SOCKS5Server {
  constructor(config) {
    this.config = config;
    this.server = net.createServer();
    this.udpClients = new Map();
    this.server.on('connection', this.handleConnection.bind(this));
  }

  handleConnection(socket) {
    console.log(`[TCP] ${socket.remoteAddress}:${socket.remotePort}`);
    socket.once('data', (data) => {
      this.handleAuthNegotiation(socket, data);
    });

    socket.on('error', () => {});
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
      socket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
      return;
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
    if (!match) return false;
    const [, a, , , d] = match.map(Number);
    return d === 255 || (a === 255) || a >= 224;
  }

  handleConnect(socket, host, port) {
    if (this.isBroadcastIP(host)) {
      socket.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
      return;
    }

    const targetSocket = net.createConnection(port, host);

    targetSocket.on('connect', () => {
      console.log(`[CONNECT] ${host}:${port}`);
      socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.pipe(targetSocket);
      targetSocket.pipe(socket);
    });

    targetSocket.on('error', () => {
      socket.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      socket.end();
    });
  }

  handleUDPAssociate(socket, host, port) {
    const udpRelay = dgram.createSocket('udp4');
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
        remoteMap
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
      console.log(`[UDP] Client ${clientKey} → UDP relay ${serverLocalAddress}:${udpPort}`);

      cleanupTimer = setInterval(() => {
        const now = Date.now();
        for (const [key, info] of remoteMap.entries()) {
          if (now - info.lastActivity > 600000) {
            remoteMap.delete(key);
          }
        }
      }, 60000);

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
    } else {
      return;
    }

    if (this.isBroadcastIP(host)) return;

    const data = msg.slice(dataStart);
    const remoteKey = `${host}:${port}`;

    const isNewDestination = !remoteMap.has(remoteKey);

    remoteMap.set(remoteKey, {
      clientAddr: rinfo.address,
      clientPort: rinfo.port,
      lastActivity: Date.now()
    });

    if (isNewDestination) {
      console.log(`  └─> ${host}:${port}`);
    }

    udpRelay.send(data, port, host);
  }

  handleRemoteToClient(msg, rinfo, udpRelay, remoteMap) {
    const remoteKey = `${rinfo.address}:${rinfo.port}`;
    const clientInfo = remoteMap.get(remoteKey);

    if (!clientInfo) return;

    clientInfo.lastActivity = Date.now();

    const responsePacket = Buffer.alloc(10 + msg.length);
    responsePacket[0] = 0x00;
    responsePacket[1] = 0x00;
    responsePacket[2] = 0x00;
    responsePacket[3] = 0x01;

    const ipParts = rinfo.address.split('.');
    responsePacket[4] = parseInt(ipParts[0]);
    responsePacket[5] = parseInt(ipParts[1]);
    responsePacket[6] = parseInt(ipParts[2]);
    responsePacket[7] = parseInt(ipParts[3]);
    responsePacket.writeUInt16BE(rinfo.port, 8);
    msg.copy(responsePacket, 10);

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

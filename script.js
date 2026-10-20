const net = require('net');
const dgram = require('dgram');
const dns = require('dns');

// ---- command line -------------------------------------------------------------------------------------------------------------

const HELP = `Usage: node script.js [options]
Options:
  -h, --host <ip>        Bind IP address (default: 127.0.0.1)
  -p, --port <port>      SOCKS5 port (default: 1080)
  -u, --username <user>  Authentication username (optional, needs --password)
  -P, --password <pass>  Authentication password (optional, needs --username)
  -v, --verbose          Enable detailed logging
  --max-per-ip <n>       Maximum simultaneous connections from one client address (default: 500)
  --help                 Show this help message`;

function parseArgs(args) {
  const config = {
    host: '127.0.0.1',
    port: 1080,
    username: null,
    password: null,
    verbose: false,
    maxPerIp: 500
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
    } else if (args[i] === '--max-per-ip') {
      config.maxPerIp = parseInt(args[++i]);
    } else if (args[i] === '--help') {
      config.help = true;
    }
  }

  // Authentication needs both values: with only one of them the proxy would silently run open.
  if ((config.username === null) !== (config.password === null)) {
    throw new Error('--username and --password must be given together');
  }
  if (!Number.isInteger(config.maxPerIp) || config.maxPerIp < 1) {
    throw new Error('--max-per-ip must be a positive number');
  }
  return config;
}

// ---- addresses ----------------------------------------------------------------------------------------------------------------

// '::ffff:1.2.3.4' (an IPv4 address seen through a dual-stack socket) -> '1.2.3.4'
function stripMapped(address) {
  return typeof address === 'string' ? address.replace(/^::ffff:/i, '') : address;
}

function ipv4ToBuffer(address) {
  return Buffer.from(address.split('.').map(Number));
}

// Any textual IPv6 address ('::1', '2606:4700::6810:7b60', '::ffff:1.2.3.4', 'fe80::1%eth0') -> 16 bytes
function ipv6ToBuffer(address) {
  address = address.split('%')[0];
  let tail = null;
  const dot = address.lastIndexOf('.');
  if (dot !== -1) {                                     // embedded IPv4 in the last 32 bits
    const colon = address.lastIndexOf(':');
    tail = ipv4ToBuffer(address.slice(colon + 1));
    address = address.slice(0, colon + 1) + '0:0';
  }
  const halves = address.split('::');
  const parse = (s) => (s === '' ? [] : s.split(':').map((p) => parseInt(p, 16)));
  const head = parse(halves[0]);
  const rest = halves.length > 1 ? parse(halves[1]) : [];
  const groups = halves.length > 1 ? head.concat(new Array(8 - head.length - rest.length).fill(0), rest) : head;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) out.writeUInt16BE((groups[i] || 0) & 0xffff, i * 2);
  if (tail) tail.copy(out, 12);
  return out;
}

function bufferToIPv6(buf) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(i).toString(16));
  return parts.join(':');
}

// The one text form of an address that is used as a map key: IPv4 as dotted decimal (also when it arrives as ::ffff:a.b.c.d),
// IPv6 compressed (RFC 5952, lower case), which is also how Node reports the source of a datagram
function canonicalAddress(address) {
  address = stripMapped(address);
  if (net.isIPv4(address)) return address;
  const groups = [];
  const b = ipv6ToBuffer(address);
  for (let i = 0; i < 16; i += 2) groups.push(b.readUInt16BE(i));
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

// SOCKS5 address field for an IP address string: { atyp, bytes }
function encodeAddress(address) {
  address = stripMapped(address);
  if (net.isIPv4(address)) return { atyp: 0x01, bytes: ipv4ToBuffer(address) };
  return { atyp: 0x04, bytes: ipv6ToBuffer(address) };
}

// Length of the ATYP + ADDR + PORT part of a request starting at data[3], or 0 when more bytes are needed, or -1 when the
// address type is unknown
function addressLength(data) {
  if (data.length < 4) return 0;
  const atyp = data[3];
  if (atyp === 0x01) return data.length >= 10 ? 7 : 0;
  if (atyp === 0x04) return data.length >= 22 ? 19 : 0;
  if (atyp === 0x03) {
    if (data.length < 5) return 0;
    return data.length >= 5 + data[4] + 2 ? 4 + data[4] : 0;
  }
  return -1;
}

// Parses ATYP/ADDR/PORT at data[start...]: { host, port, end } (end: index after the port)
function parseAddress(data, start) {
  const atyp = data[start];
  if (atyp === 0x01) {
    return { host: `${data[start + 1]}.${data[start + 2]}.${data[start + 3]}.${data[start + 4]}`, port: data.readUInt16BE(start + 5), end: start + 7 };
  }
  if (atyp === 0x03) {
    const len = data[start + 1];
    return { host: len === 0 ? '0.0.0.0' : data.slice(start + 2, start + 2 + len).toString(), port: data.readUInt16BE(start + 2 + len), end: start + 4 + len };
  }
  return { host: bufferToIPv6(data.slice(start + 1, start + 17)), port: data.readUInt16BE(start + 17), end: start + 19 };
}

// SOCKS5 reply codes for a failed outgoing connection
function replyCodeFor(err) {
  switch (err && err.code) {
    case 'ECONNREFUSED': return 0x05;
    case 'ENETUNREACH': return 0x03;
    case 'EHOSTUNREACH': case 'ENOTFOUND': case 'EAI_AGAIN': case 'ENODATA': return 0x04;
    case 'ETIMEDOUT': return 0x06;
    default: return 0x01;
  }
}

function reply(code, address, port) {
  const a = address ? encodeAddress(address) : { atyp: 0x01, bytes: Buffer.alloc(4) };
  const out = Buffer.alloc(4 + a.bytes.length + 2);
  out[0] = 0x05;
  out[1] = code;
  out[3] = a.atyp;
  a.bytes.copy(out, 4);
  out.writeUInt16BE(port || 0, 4 + a.bytes.length);
  return out;
}

// ---- QUIC ---------------------------------------------------------------------------------------------------------------------

// A long-header QUIC packet (RFC 9000): form bit and fixed bit set, a version that is known or greased (0x?a?a?a?a), or a
// Version Negotiation packet (version 0). Anything else (DNS, game traffic, ...) is not reported as QUIC.
function detectQUICPacket(data) {
  if (data.length < 7) return false;
  const first = data[0];
  if ((first & 0x80) === 0) return false;
  const version = data.readUInt32BE(1);
  if (version === 0) return true;
  if ((first & 0x40) === 0) return false;
  return version === 1 || version === 0x6b3343cf || (version >>> 8) === 0xff0000 || (version & 0x0f0f0f0f) === 0x0a0a0a0a;
}

// UDP port 443 is what HTTP/3 uses; 8443 is the usual alternative
function isHTTP3Port(port) {
  return port === 443 || port === 8443;
}

// the address form the relay socket needs: an IPv4 destination on a dual-stack socket is written as ::ffff:a.b.c.d
function relayAddress(address, udpRelay) {
  if (udpRelay.relayFamily === 6 && net.isIPv4(address)) return '::ffff:' + address;
  return address;
}

// ---- the server ---------------------------------------------------------------------------------------------------------------

class SOCKS5Server {
  constructor(config) {
    this.config = config;
    // allowHalfOpen: a client that has sent everything and shut down its sending side must still receive the answer
    this.server = net.createServer({ allowHalfOpen: true });
    this.server.maxConnections = 10000; // Prevent resource exhaustion
    this.activeConnections = 0;
    this.udpClients = new Map();
    this.connectionsByIP = new Map(); // Track connections per IP
    this.lastLimitLog = 0;
    this.server.on('connection', this.handleConnection.bind(this));

    // Cleanup stale UDP clients every 5 minutes
    this.cleanupTimer = setInterval(() => this.cleanupStaleUDPClients(), 300000);
    this.cleanupTimer.unref();
  }

  log(text) {
    if (this.config.verbose) console.log(text);
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

    // Rate limiting: a limited number of connections per client address
    const ipCount = this.connectionsByIP.get(ip) || 0;
    if (ipCount >= this.config.maxPerIp) {
      const now = Date.now();
      if (now - this.lastLimitLog > 5000) {
        this.lastLimitLog = now;
        console.error(`[LIMIT] ${ip} already has ${ipCount} connections (--max-per-ip ${this.config.maxPerIp}): refusing`);
      }
      socket.destroy();
      return;
    }

    this.activeConnections++;
    this.connectionsByIP.set(ip, ipCount + 1);

    this.log(`[TCP] ${ip}:${socket.remotePort} (active: ${this.activeConnections})`);

    socket.setTimeout(60000); // 60s timeout for the whole handshake
    socket.on('timeout', () => socket.destroy());
    this.readHandshake(socket);

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

  // TCP is a byte stream: a message may arrive in pieces, and several messages may arrive together. The handshake therefore
  // collects bytes until the message of the current step is complete.
  readHandshake(socket) {
    const authRequired = this.config.username !== null && this.config.password !== null;
    let buf = Buffer.alloc(0);
    let step = 'greeting';

    const fail = () => {
      socket.removeListener('data', onData);
      socket.removeListener('end', onEnd);
      socket.end();
    };
    // half-open sockets stay open after the client's FIN until we end them: a client that leaves in the middle of the handshake
    const onEnd = () => fail();
    socket.once('end', onEnd);

    const advance = () => {
      for (;;) {
        if (step === 'greeting') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x05) return fail();
          const need = 2 + buf[1];
          if (buf.length < need) return;
          const methods = Array.from(buf.slice(2, need));
          buf = buf.slice(need);
          if (authRequired) {
            if (!methods.includes(0x02)) {
              socket.write(Buffer.from([0x05, 0xFF]));
              return fail();
            }
            socket.write(Buffer.from([0x05, 0x02]));
            step = 'auth';
          } else {
            if (!methods.includes(0x00)) {
              socket.write(Buffer.from([0x05, 0xFF]));
              return fail();
            }
            socket.write(Buffer.from([0x05, 0x00]));
            step = 'request';
          }
        } else if (step === 'auth') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x01) return fail();
          const ulen = buf[1];
          if (buf.length < 2 + ulen + 1) return;
          const plen = buf[2 + ulen];
          const need = 3 + ulen + plen;
          if (buf.length < need) return;
          const username = buf.slice(2, 2 + ulen).toString();
          const password = buf.slice(3 + ulen, need).toString();
          buf = buf.slice(need);
          if (username === this.config.username && password === this.config.password) {
            socket.write(Buffer.from([0x01, 0x00]));
            step = 'request';
          } else {
            socket.write(Buffer.from([0x01, 0x01]));
            return fail();
          }
        } else {
          if (buf.length < 4) return;
          if (buf[0] !== 0x05) return fail();
          const alen = addressLength(buf);
          if (alen === 0) return;
          if (alen < 0) {
            socket.write(reply(0x08));
            return fail();
          }
          const { host, port } = parseAddress(buf, 3);
          const cmd = buf[1];
          const rest = buf.slice(3 + alen);
          socket.removeListener('data', onData);
          socket.removeListener('end', onEnd);
          socket.pause();
          socket.setTimeout(0);
          this.handleRequest(socket, cmd, host, port, rest);
          return;
        }
      }
    };

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 1024) return fail();             // longer than any handshake can be
      advance();
    };
    socket.on('data', onData);
  }

  handleRequest(socket, cmd, host, port, rest) {
    if (cmd === 0x01) {
      this.handleConnect(socket, host, port, rest);
    } else if (cmd === 0x03) {
      this.handleUDPAssociate(socket, host, port);
      socket.resume();
    } else {
      socket.write(reply(0x07));
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
    return isHTTP3Port(port);
  }

  detectQUICPacket(data) {
    return detectQUICPacket(data);
  }

  handleConnect(socket, host, port, rest) {
    if (this.isBroadcastIP(host)) {
      socket.write(reply(0x02));
      socket.end();
      return;
    }

    // Performance: disable Nagle's algorithm
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 60000);

    // allowHalfOpen on both sides: when one side stops sending, the other side is told (pipe forwards the end) but can still
    // answer until it has finished too
    let targetSocket;
    try {
      targetSocket = net.createConnection({ port, host, allowHalfOpen: true });
    } catch (e) {                                        // for instance an unusable port
      socket.write(reply(0x01));
      socket.end();
      return;
    }
    targetSocket.setNoDelay(true);
    targetSocket.setKeepAlive(true, 60000);
    let connected = false;

    targetSocket.on('connect', () => {
      connected = true;
      this.log(`[CONNECT] ${host}:${port}`);
      socket.write(reply(0x00, targetSocket.localAddress, targetSocket.localPort));
      if (rest && rest.length) targetSocket.write(rest);
      socket.pipe(targetSocket);
      targetSocket.pipe(socket);
      socket.resume();
    });

    targetSocket.on('error', (err) => {
      if (!connected && !socket.destroyed) {
        socket.write(reply(replyCodeFor(err)));
        socket.end();
      } else {
        socket.destroy();
      }
    });

    targetSocket.on('close', () => {
      if (!socket.destroyed) socket.end();
    });

    socket.on('error', () => {
      targetSocket.destroy();
    });

    socket.on('close', () => {
      if (!targetSocket.destroyed) targetSocket.destroy();
    });
  }

  // The socket that carries UDP for one association. Dual-stack, so that one socket reaches IPv4 and IPv6 destinations; IPv4
  // destinations are then addressed as ::ffff:a.b.c.d. Where the host has no IPv6 an IPv4 socket is used instead.
  createRelay(onError, callback) {
    const make = (type) => {
      const relay = dgram.createSocket({ type, reuseAddr: true, ipv6Only: false, recvBufferSize: 4 << 20, sendBufferSize: 4 << 20 });
      relay.relayFamily = type === 'udp6' ? 6 : 4;
      relay.on('error', onError);
      return relay;
    };
    let relay = make('udp6');
    const onBindError = (err) => {
      if (err.code === 'EAFNOSUPPORT' || err.code === 'EADDRNOTAVAIL' || err.code === 'EPROTONOSUPPORT') {
        relay.removeListener('error', onError);
        relay.close();
        relay = make('udp4');
        relay.bind(0, '0.0.0.0', () => callback(relay));
      }
    };
    relay.once('error', onBindError);
    relay.bind(0, '::', () => {
      relay.removeListener('error', onBindError);
      callback(relay);
    });
  }

  handleUDPAssociate(socket, host, port) {
    const clientKey = `${socket.remoteAddress}:${socket.remotePort}`;
    const clientIp = canonicalAddress(socket.remoteAddress);
    // RFC 1928: the relay serves the client that asked for it. A port in the request (when not 0) narrows that further.
    const expectedPort = port || 0;
    const remoteMap = new Map();
    let cleanupTimer = null;
    let closed = false;

    const failAssociation = () => {
      if (closed) return;
      closed = true;
      if (cleanupTimer) clearInterval(cleanupTimer);
      this.udpClients.delete(clientKey);
      remoteMap.clear();
      try { socket.write(reply(0x01)); } catch (e) { /* the control connection is gone already */ }
      socket.end();
    };

    this.createRelay(failAssociation, (udpRelay) => {
      if (closed || socket.destroyed) {
        udpRelay.close();
        return;
      }
      udpRelay.on('message', (msg, rinfo) => {
        this.handleUDPMessage(msg, rinfo, udpRelay, remoteMap, clientIp, expectedPort);
      });
      const udpPort = udpRelay.address().port;

      this.udpClients.set(clientKey, {
        socket,
        address: socket.remoteAddress,
        port: socket.remotePort,
        udpRelay,
        remoteMap,
        lastActivity: Date.now()
      });

      const serverLocalAddress = stripMapped(socket.localAddress);
      socket.write(reply(0x00, serverLocalAddress, udpPort));

      this.log(`[UDP] ${clientKey} → relay ${serverLocalAddress}:${udpPort}`);

      cleanupTimer = setInterval(() => {
        const now = Date.now();
        for (const [key, info] of remoteMap.entries()) {
          if (now - info.lastActivity > 600000) {
            remoteMap.delete(key);
          }
        }
      }, 300000);
      cleanupTimer.unref();

      const cleanup = () => {
        if (cleanupTimer) clearInterval(cleanupTimer);
        closed = true;
        this.udpClients.delete(clientKey);
        remoteMap.clear();
        try { udpRelay.close(); } catch (e) { /* already closed */ }
      };
      socket.on('close', cleanup);
      socket.on('error', cleanup);
      socket.on('end', () => socket.end());              // the client closed the control connection: the association is over
      udpRelay.removeListener('error', failAssociation);
      udpRelay.on('error', () => { /* a failed send never ends the association */ });
    });
  }

  handleUDPMessage(msg, rinfo, udpRelay, remoteMap, clientIp, expectedPort) {
    const from = canonicalAddress(rinfo.address);
    // Who sent it is decided by where it came from, not by what it starts with: a reply of a remote host may begin with any
    // bytes, including 00 00. Remotes are the addresses this association has sent to; the client is the host that opened the
    // association. Anything else is not served (this is not an open relay).
    if (remoteMap.has(`${from}:${rinfo.port}`)) {
      this.handleRemoteToClient(msg, rinfo, udpRelay, remoteMap);
    } else if (from === clientIp && (expectedPort === 0 || rinfo.port === expectedPort)) {
      this.handleClientToRemote(msg, rinfo, udpRelay, remoteMap);
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

    const alen = addressLength(msg);
    if (alen <= 0) return;
    const { host, port, end } = parseAddress(msg, 3);

    if (this.isBroadcastIP(host)) return;
    if (port < 1) return;                                // dgram.send() throws for port 0

    const data = msg.slice(end);
    const isHTTP3Likely = isHTTP3Port(port);
    const isQUIC = detectQUICPacket(data);

    this.resolveForRelay(host, (err, address) => {
      if (err) return;
      const remoteKey = `${canonicalAddress(address)}:${port}`;
      const isNewDestination = !remoteMap.has(remoteKey);

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

      // a datagram that cannot be delivered is that datagram's problem, not the association's (and never the server's)
      try {
        udpRelay.send(data, port, relayAddress(address, udpRelay), () => {});
      } catch (e) { /* closed relay or an address the socket cannot use */ }
    });
  }

  // host name or address from the client -> the address to send to
  resolveForRelay(host, callback) {
    if (net.isIP(host)) return callback(null, host);
    dns.lookup(host, { family: 0 }, (err, address) => callback(err, address));
  }

  handleRemoteToClient(msg, rinfo, udpRelay, remoteMap) {
    const remoteKey = `${canonicalAddress(rinfo.address)}:${rinfo.port}`;
    const clientInfo = remoteMap.get(remoteKey);

    if (!clientInfo) return;

    clientInfo.lastActivity = Date.now();

    const a = encodeAddress(rinfo.address);
    const header = Buffer.alloc(4 + a.bytes.length + 2);
    header[3] = a.atyp;                                  // RSV, RSV, FRAG are 0
    a.bytes.copy(header, 4);
    header.writeUInt16BE(rinfo.port, 4 + a.bytes.length);

    try {
      udpRelay.send(Buffer.concat([header, msg]), clientInfo.clientPort, clientInfo.clientAddr, () => {});
    } catch (e) { /* the relay was closed in the meantime */ }
  }

  listen(port, host, callback) {
    this.server.listen(port, host, callback);
  }

  close(callback) {
    clearInterval(this.cleanupTimer);
    for (const client of this.udpClients.values()) {
      try { client.udpRelay.close(); } catch (e) { /* already closed */ }
    }
    this.server.close(callback);
  }
}

module.exports = {
  SOCKS5Server, parseArgs, detectQUICPacket, isHTTP3Port, ipv6ToBuffer, bufferToIPv6, stripMapped, canonicalAddress, encodeAddress, replyCodeFor
};

if (require.main === module) {
  let config;
  try {
    config = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
  if (config.help) {
    console.log(HELP);
    process.exit(0);
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
}

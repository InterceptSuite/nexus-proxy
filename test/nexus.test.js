// Tests for Nexus Proxy. Built-in test runner, no dependencies:   node --test test/
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const dgram = require('dgram');
const {
  SOCKS5Server, parseArgs, detectQUICPacket, isHTTP3Port, ipv6ToBuffer, bufferToIPv6, replyCodeFor
} = require('../script.js');

const quiet = { host: '127.0.0.1', port: 0, username: null, password: null, verbose: false, maxPerIp: 500 };

async function startProxy(overrides = {}) {
  const proxy = new SOCKS5Server({ ...quiet, ...overrides });
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  proxy.port = proxy.server.address().port;
  return proxy;
}
const stopProxy = (proxy) => new Promise((resolve) => { proxy.server.closeAllConnections?.(); proxy.close(resolve); });

// ---- a SOCKS5 client written for the tests -----------------------------------------------------------------------------------

function readExactly(socket, n) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        socket.removeListener('data', onData);
        socket.removeListener('error', reject);
        socket.pause();
        socket.unshift(buf.slice(n));
        resolve(buf.slice(0, n));
      }
    };
    socket.on('data', onData);
    socket.once('error', reject);
    socket.once('close', () => reject(new Error('closed before ' + n + ' bytes (got ' + buf.length + ')')));
    socket.resume();
  });
}

function addressBytes(host, port) {
  const p = Buffer.alloc(2);
  p.writeUInt16BE(port);
  if (net.isIPv4(host)) return Buffer.concat([Buffer.from([0x01]), Buffer.from(host.split('.').map(Number)), p]);
  if (net.isIPv6(host)) return Buffer.concat([Buffer.from([0x04]), ipv6ToBuffer(host), p]);
  return Buffer.concat([Buffer.from([0x03, host.length]), Buffer.from(host), p]);
}

async function connectClient(proxy, { auth } = {}) {
  const s = net.connect({ port: proxy.port, host: '127.0.0.1', allowHalfOpen: true });
  await new Promise((resolve, reject) => { s.once('connect', resolve); s.once('error', reject); });
  s.write(Buffer.from(auth ? [5, 1, 2] : [5, 1, 0]));
  const method = await readExactly(s, 2);
  assert.strictEqual(method[0], 5);
  if (auth) {
    assert.strictEqual(method[1], 2);
    s.write(Buffer.concat([Buffer.from([1, auth[0].length]), Buffer.from(auth[0]), Buffer.from([auth[1].length]), Buffer.from(auth[1])]));
    const r = await readExactly(s, 2);
    return { s, authStatus: r[1] };
  }
  assert.strictEqual(method[1], 0);
  return { s };
}

// sends a request and reads the reply: { code, atyp, host, port }
async function request(s, cmd, host, port) {
  s.write(Buffer.concat([Buffer.from([5, cmd, 0]), addressBytes(host, port)]));
  const head = await readExactly(s, 4);
  const len = head[3] === 1 ? 6 : head[3] === 4 ? 18 : 0;
  const tail = await readExactly(s, len);
  return { code: head[1], atyp: head[3], tail };
}

function echoServer() {
  return new Promise((resolve) => {
    const server = net.createServer((c) => c.pipe(c));
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

// ---- pure functions ----------------------------------------------------------------------------------------------------------

test('--username without --password is refused instead of running open', () => {
  assert.throws(() => parseArgs(['-u', 'a']), /together/);
  assert.throws(() => parseArgs(['-P', 'x']), /together/);
  assert.deepStrictEqual(
    [parseArgs(['-u', 'a', '-P', 'b']).username, parseArgs([]).username],
    ['a', null]);
  assert.strictEqual(parseArgs(['--max-per-ip', '9000']).maxPerIp, 9000);
  assert.throws(() => parseArgs(['--max-per-ip', '0']), /positive/);
});

test('IPv6 addresses are converted correctly, compressed forms included', () => {
  assert.strictEqual(ipv6ToBuffer('::1').toString('hex'), '00000000000000000000000000000001');
  assert.strictEqual(ipv6ToBuffer('2606:4700::6810:7b60').toString('hex'), '260647000000000000000000 68107b60'.replace(' ', ''));
  assert.strictEqual(ipv6ToBuffer('2001:db8:0:0:0:0:0:1').toString('hex'), '20010db8000000000000000000000001');
  assert.strictEqual(ipv6ToBuffer('::ffff:1.2.3.4').toString('hex'), '00000000000000000000ffff01020304');
  assert.strictEqual(ipv6ToBuffer('fe80::1%eth0').toString('hex'), 'fe800000000000000000000000000001');
  assert.strictEqual(ipv6ToBuffer('::').toString('hex'), '0'.repeat(32));
  assert.strictEqual(bufferToIPv6(ipv6ToBuffer('2606:4700::6810:7b60')), '2606:4700:0:0:0:0:6810:7b60');
});

test('QUIC is recognised only where it really is QUIC', () => {
  const longHeader = (version, first = 0xc3) => {
    const b = Buffer.alloc(1200);
    b[0] = first;
    b.writeUInt32BE(version, 1);
    return b;
  };
  assert.ok(detectQUICPacket(longHeader(1)), 'QUIC v1 Initial');
  assert.ok(detectQUICPacket(longHeader(0x6b3343cf)), 'QUIC v2');
  assert.ok(detectQUICPacket(longHeader(0xff00001d)), 'draft-29');
  assert.ok(detectQUICPacket(longHeader(0x1a2a3a4a)), 'greased version');
  assert.ok(detectQUICPacket(longHeader(0, 0x8f)), 'Version Negotiation');
  assert.ok(!detectQUICPacket(longHeader(1, 0x43)), 'short header form bit');
  assert.ok(!detectQUICPacket(longHeader(1, 0x83)), 'fixed bit missing');
  assert.ok(!detectQUICPacket(longHeader(0x12345678)), 'unknown version');
  // a DNS query/answer with a high transaction id must not be called QUIC
  assert.ok(!detectQUICPacket(Buffer.from('b3c0010000010000000000000377777707657861' + '6d706c6503636f6d0000010001', 'hex')));
  assert.ok(!detectQUICPacket(Buffer.from('hello')));
  assert.ok(isHTTP3Port(443) && isHTTP3Port(8443) && !isHTTP3Port(80) && !isHTTP3Port(8080) && !isHTTP3Port(53));
});

test('addresses get one canonical text form', () => {
  const { canonicalAddress } = require('../script.js');
  assert.strictEqual(canonicalAddress('0:0:0:0:0:0:0:1'), '::1');
  assert.strictEqual(canonicalAddress('2606:4700:0:0:0:0:6810:7b60'), '2606:4700::6810:7b60');
  assert.strictEqual(canonicalAddress('2001:DB8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');
  assert.strictEqual(canonicalAddress('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1');   // a single zero group is not compressed
  assert.strictEqual(canonicalAddress('::ffff:10.0.0.1'), '10.0.0.1');
  assert.strictEqual(canonicalAddress('::'), '::');
  assert.strictEqual(canonicalAddress('127.0.0.1'), '127.0.0.1');
});

test('connect failures map to the right SOCKS5 reply codes', () => {
  assert.strictEqual(replyCodeFor({ code: 'ECONNREFUSED' }), 5);
  assert.strictEqual(replyCodeFor({ code: 'ENETUNREACH' }), 3);
  assert.strictEqual(replyCodeFor({ code: 'EHOSTUNREACH' }), 4);
  assert.strictEqual(replyCodeFor({ code: 'ENOTFOUND' }), 4);
  assert.strictEqual(replyCodeFor({ code: 'ETIMEDOUT' }), 6);
  assert.strictEqual(replyCodeFor({ code: 'EWHATEVER' }), 1);
});

// ---- TCP ---------------------------------------------------------------------------------------------------------------------

test('CONNECT carries data both ways', async () => {
  const echo = await echoServer(), proxy = await startProxy();
  const { s } = await connectClient(proxy);
  const r = await request(s, 1, '127.0.0.1', echo.address().port);
  assert.strictEqual(r.code, 0);
  s.write('hello nexus');
  assert.strictEqual((await readExactly(s, 11)).toString(), 'hello nexus');
  s.destroy();
  echo.close();
  await stopProxy(proxy);
});

test('a handshake that arrives one byte at a time works', async () => {
  const echo = await echoServer(), proxy = await startProxy();
  const s = net.connect({ port: proxy.port, host: '127.0.0.1' });
  await new Promise((r) => s.once('connect', r));
  const message = Buffer.concat([Buffer.from([5, 1, 0]), Buffer.from([5, 1, 0]), addressBytes('127.0.0.1', echo.address().port)]);
  s.write(message.slice(0, 3));
  assert.deepStrictEqual([...(await readExactly(s, 2))], [5, 0]);
  const req = message.slice(3);
  for (let i = 0; i < req.length; i++) {
    s.write(req.slice(i, i + 1));
    await new Promise((r) => setTimeout(r, 5));
  }
  const head = await readExactly(s, 4);
  assert.strictEqual(head[1], 0);
  await readExactly(s, head[3] === 1 ? 6 : 18);
  s.write('x');
  assert.strictEqual((await readExactly(s, 1)).toString(), 'x');
  s.destroy();
  echo.close();
  await stopProxy(proxy);
});

test('greeting, request and the first payload bytes sent together are all honoured', async () => {
  const echo = await echoServer(), proxy = await startProxy();
  const s = net.connect({ port: proxy.port, host: '127.0.0.1' });
  await new Promise((r) => s.once('connect', r));
  s.write(Buffer.concat([Buffer.from([5, 1, 0]), Buffer.from([5, 1, 0]), addressBytes('127.0.0.1', echo.address().port), Buffer.from('early')]));
  assert.deepStrictEqual([...(await readExactly(s, 2))], [5, 0]);
  const head = await readExactly(s, 4);
  assert.strictEqual(head[1], 0);
  await readExactly(s, head[3] === 1 ? 6 : 18);
  assert.strictEqual((await readExactly(s, 5)).toString(), 'early');
  s.destroy();
  echo.close();
  await stopProxy(proxy);
});

test('half-close: a client that shut down its sending side still gets the answer', async () => {
  // a server that answers only after the client has finished sending (like an HTTP/1.0 exchange or `nc` with a closed stdin)
  const server = net.createServer({ allowHalfOpen: true }, (c) => {
    let got = '';
    c.on('data', (d) => { got += d; });
    c.on('end', () => { c.end('answer to: ' + got); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const proxy = await startProxy();
  const { s } = await connectClient(proxy);
  assert.strictEqual((await request(s, 1, '127.0.0.1', server.address().port)).code, 0);
  s.end('request');                                       // FIN: nothing more to send
  let answer = '';
  s.on('data', (d) => { answer += d; });
  s.resume();
  await new Promise((r) => s.once('close', r));
  assert.strictEqual(answer, 'answer to: request');
  server.close();
  await stopProxy(proxy);
});

test('username/password authentication', async () => {
  const echo = await echoServer(), proxy = await startProxy({ username: 'alice', password: 's3cret' });
  const bad = await connectClient(proxy, { auth: ['alice', 'wrong'] });
  assert.notStrictEqual(bad.authStatus, 0);
  bad.s.destroy();
  const none = net.connect({ port: proxy.port, host: '127.0.0.1' });
  await new Promise((r) => none.once('connect', r));
  none.write(Buffer.from([5, 1, 0]));                      // only "no authentication" offered
  assert.deepStrictEqual([...(await readExactly(none, 2))], [5, 0xff]);
  none.destroy();
  const good = await connectClient(proxy, { auth: ['alice', 's3cret'] });
  assert.strictEqual(good.authStatus, 0);
  assert.strictEqual((await request(good.s, 1, '127.0.0.1', echo.address().port)).code, 0);
  good.s.destroy();
  echo.close();
  await stopProxy(proxy);
});

test('connect errors report the real reason', async () => {
  const proxy = await startProxy();
  const free = await new Promise((r) => { const t = net.createServer().listen(0, '127.0.0.1', () => { const p = t.address().port; t.close(() => r(p)); }); });
  let c = await connectClient(proxy);
  assert.strictEqual((await request(c.s, 1, '127.0.0.1', free)).code, 5, 'refused');
  c.s.destroy();
  c = await connectClient(proxy);
  assert.strictEqual((await request(c.s, 1, 'no-such-host.invalid', 80)).code, 4, 'host not found');
  c.s.destroy();
  c = await connectClient(proxy);
  assert.strictEqual((await request(c.s, 1, '255.255.255.255', 80)).code, 2, 'broadcast not allowed');
  c.s.destroy();
  c = await connectClient(proxy);
  c.s.write(Buffer.from([5, 2, 0, 1, 1, 2, 3, 4, 0, 80]));  // BIND is not supported
  assert.strictEqual((await readExactly(c.s, 10))[1], 7);
  c.s.destroy();
  await stopProxy(proxy);
});

test('the per-address connection limit is configurable', async () => {
  const proxy = await startProxy({ maxPerIp: 3 });
  const sockets = [];
  for (let i = 0; i < 3; i++) sockets.push((await connectClient(proxy)).s);
  const fourth = net.connect({ port: proxy.port, host: '127.0.0.1' });
  await new Promise((r) => fourth.once('connect', r));
  fourth.on('error', () => {});
  await new Promise((r) => fourth.once('close', r));         // refused: closed without a word
  assert.ok(fourth.destroyed);
  sockets.forEach((s) => s.destroy());
  await stopProxy(proxy);
});

// ---- UDP ---------------------------------------------------------------------------------------------------------------------

function udpHeader(host, port) {
  return Buffer.concat([Buffer.from([0, 0, 0]), addressBytes(host, port)]);
}

// decodes a SOCKS5 UDP datagram: { host, port, data }
function decodeUdp(msg) {
  assert.deepStrictEqual([...msg.slice(0, 3)], [0, 0, 0]);
  if (msg[3] === 1) return { host: [...msg.slice(4, 8)].join('.'), port: msg.readUInt16BE(8), data: msg.slice(10) };
  return { host: bufferToIPv6(msg.slice(4, 20)), port: msg.readUInt16BE(20), data: msg.slice(22) };
}

async function udpAssociate(proxy) {
  const { s } = await connectClient(proxy);
  s.write(Buffer.concat([Buffer.from([5, 3, 0]), addressBytes('0.0.0.0', 0)]));
  const head = await readExactly(s, 4);
  assert.strictEqual(head[1], 0, 'UDP ASSOCIATE accepted');
  const tail = await readExactly(s, head[3] === 1 ? 6 : 18);
  const relayPort = tail.readUInt16BE(tail.length - 2);
  const udp = dgram.createSocket('udp4');
  await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  return { s, udp, relayPort };
}

const recvOnce = (udp, ms = 2000) => new Promise((resolve) => {
  const t = setTimeout(() => { udp.removeAllListeners('message'); resolve(null); }, ms);
  udp.once('message', (m, r) => { clearTimeout(t); resolve({ m, r }); });
});

function udpEcho(type, address, transform = (d) => d) {
  return new Promise((resolve) => {
    const server = dgram.createSocket(type);
    server.received = 0;
    server.on('message', (m, r) => { server.received++; server.send(transform(m), r.port, r.address); });
    server.bind(0, address, () => resolve(server));
  });
}

test('UDP: datagrams to an IPv4 destination are relayed and answered', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('ping')]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp);
  assert.ok(got, 'an answer came back');
  const d = decodeUdp(got.m);
  assert.deepStrictEqual([d.host, d.port, d.data.toString()], ['127.0.0.1', echo.address().port, 'ping']);
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: an answer that starts with two zero bytes is still an answer', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1', (m) => Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), m]));
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('zz')]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp);
  assert.ok(got, 'the answer was delivered');
  assert.strictEqual(decodeUdp(got.m).data.length, 14);
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: an IPv6 destination, answer address decoded correctly', async (t) => {
  let echo;
  try { echo = await udpEcho('udp6', '::1'); } catch (e) { return t.skip('no IPv6 loopback'); }
  if (!echo.address || echo.address().address !== '::1') return t.skip('no IPv6 loopback');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('::1', echo.address().port), Buffer.from('six')]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp);
  assert.ok(got, 'an answer came back');
  const d = decodeUdp(got.m);
  assert.deepStrictEqual([d.host, d.port, d.data.toString()], ['0:0:0:0:0:0:0:1', echo.address().port, 'six']);
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: a destination given as a host name', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('localhost', echo.address().port), Buffer.from('named')]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp);
  assert.ok(got && decodeUdp(got.m).data.toString() === 'named');
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: large datagrams', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  const big = Buffer.alloc(59904, 0x5a);
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), big]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp, 3000);
  assert.ok(got && decodeUdp(got.m).data.equals(big));
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: the relay is not open to other hosts', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  // a stranger: another local address than the one that opened the association
  const stranger = dgram.createSocket('udp4');
  await new Promise((r) => stranger.bind(0, '127.0.0.2', r));
  stranger.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('intruder')]), a.relayPort, '127.0.0.1');
  assert.strictEqual(await recvOnce(stranger, 600), null, 'the stranger gets no answer');
  assert.strictEqual(echo.received, 0, 'and nothing was forwarded on its behalf');
  // the real client still works
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('owner')]), a.relayPort, '127.0.0.1');
  assert.ok(await recvOnce(a.udp));
  assert.strictEqual(echo.received, 1);
  stranger.close(); a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: one undeliverable datagram does not end the association', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('no-such-host.invalid', 9), Buffer.from('lost')]), a.relayPort, '127.0.0.1');
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', 0), Buffer.from('port zero')]), a.relayPort, '127.0.0.1');
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('still alive')]), a.relayPort, '127.0.0.1');
  const got = await recvOnce(a.udp);
  assert.ok(got && decodeUdp(got.m).data.toString() === 'still alive');
  assert.ok(!a.s.destroyed, 'the control connection is still open');
  a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('a datagram or a request for port 0 cannot take the server down', async () => {
  const echo = await udpEcho('udp4', '127.0.0.1');
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', 0), Buffer.from('zero')]), a.relayPort, '127.0.0.1');
  a.udp.send(Buffer.concat([udpHeader('127.0.0.1', echo.address().port), Buffer.from('fine')]), a.relayPort, '127.0.0.1');
  assert.ok(await recvOnce(a.udp), 'the server is still serving');
  const c = await connectClient(proxy);
  const r = await request(c.s, 1, '127.0.0.1', 0);
  assert.notStrictEqual(r.code, 0, 'CONNECT to port 0 is refused, not fatal');
  c.s.destroy(); a.s.destroy(); a.udp.close(); echo.close();
  await stopProxy(proxy);
});

test('UDP: closing the control connection ends the association', async () => {
  const proxy = await startProxy();
  const a = await udpAssociate(proxy);
  assert.strictEqual(proxy.udpClients.size, 1);
  a.s.end();
  for (let i = 0; i < 40 && proxy.udpClients.size; i++) await new Promise((r) => setTimeout(r, 25));
  assert.strictEqual(proxy.udpClients.size, 0);
  a.udp.close();
  await stopProxy(proxy);
});

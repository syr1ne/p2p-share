'use strict';
// signaling + static server. files and notes never touch this process:
// it only checks pins and relays webrtc handshakes between browsers.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { WebSocketServer } = require('ws');

const PORT = +process.env.PORT || 8080;
// behind a proxy, which request header carries the real client ip:
// "1" = rightmost x-forwarded-for entry, or a header name such as "cf-connecting-ip"
const TRUST_PROXY = (process.env.TRUST_PROXY || '').toLowerCase();
const ORIGIN_HOST = process.env.ORIGIN_HOST || ''; // e.g. "share.example.com"; defaults to the Host header
const ICE = JSON.parse(process.env.ICE_SERVERS || '[{"urls":"stun:stun.l.google.com:19302"},{"urls":"stun:stun.cloudflare.com:3478"}]');
if (!Array.isArray(ICE)) throw new Error('ICE_SERVERS must be a json array');

const ROOM_TTL = 30 * 864e5;   // a name stays reserved 30 days after its owner was last online
const MAX_ROOMS = 100000;
const MAX_GUESTS = 16;         // guests mid-handshake per room
const MAX_CONN_IP = 32;
const RELAY = process.env.RELAY !== '0';               // fallback when browsers can't connect directly
const RELAY_RATE = (+process.env.RELAY_MBPS || 10) * 1e6; // bytes/s per connection
const SLUG = /^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$/;
const PIN = /^\d{7}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const RESERVED = new Set(['ws', 'api', 'app', 'admin', 'static', 'assets', 'index', 'healthz', 'robots', 'favicon']);

// ---- static ---------------------------------------------------------------

const PUB = path.join(__dirname, 'public');
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";
const SEC = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };

// files are read and compressed once, and again whenever they change on disk
// (so editing the app needs no restart)
const assets = {};
function load() {
  for (const f of ['index.html', 'app.js', 'qr.js', 'style.css', 'robots.txt']) {
    const file = path.join(PUB, f);
    if (!fs.existsSync(file)) { delete assets['/' + f]; continue; }
    const body = fs.readFileSync(file);
    if (assets['/' + f] && assets['/' + f].body.equals(body)) continue;
    assets['/' + f] = {
      body,
      br: zlib.brotliCompressSync(body, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } }),
      gz: zlib.gzipSync(body, { level: 9 }),
      etag: 'W/"' + crypto.createHash('sha256').update(body).digest('base64url').slice(0, 16) + '"',
      headers: { ...SEC, 'Content-Type': TYPES[path.extname(f)], 'Cache-Control': 'no-cache', Vary: 'Accept-Encoding' },
    };
  }
}
load();
let reload;
try { fs.watch(PUB, () => { clearTimeout(reload); reload = setTimeout(load, 100); }).unref(); } catch {}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { ...SEC, Allow: 'GET, HEAD' });
    return res.end();
  }
  const p = (req.url || '/').split('?')[0];
  if (p === '/healthz') {
    res.writeHead(200, { ...SEC, 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    return res.end('ok');
  }
  const share = validSlug(p.slice(1));
  const a = assets[p] || ((p === '/' || share) && assets['/index.html']);
  if (!a) {
    res.writeHead(404, { ...SEC, 'Content-Type': 'text/plain' });
    return res.end('not found');
  }
  // share pages are private: keep them out of search engines
  const extra = share ? { 'X-Robots-Tag': 'noindex, nofollow' } : {};
  if (req.headers['if-none-match'] === a.etag) {
    res.writeHead(304, { ...a.headers, ...extra, ETag: a.etag });
    return res.end();
  }
  const ae = req.headers['accept-encoding'] || '';
  const [body, enc] = /\bbr\b/.test(ae) ? [a.br, 'br'] : /\bgzip\b/.test(ae) ? [a.gz, 'gzip'] : [a.body];
  res.writeHead(200, { ...a.headers, ...extra, ETag: a.etag, 'Content-Length': body.length, ...(enc && { 'Content-Encoding': enc }) });
  res.end(req.method === 'HEAD' ? undefined : body);
});
server.headersTimeout = 10e3;
server.requestTimeout = 15e3;

// ---- helpers --------------------------------------------------------------

function validSlug(s) { return typeof s === 'string' && SLUG.test(s) && !RESERVED.has(s); }
const hash = s => crypto.createHash('sha256').update(s).digest();
const same = (a, b) => a && b && a.length === b.length && crypto.timingSafeEqual(a, b);
const send = (ws, m) => ws && ws.readyState === 1 && ws.send(JSON.stringify(m));

// only the configured header is trusted, so clients can't spoof their ip
function ipOf(req) {
  if (TRUST_PROXY === '1') {
    const h = (req.headers['x-forwarded-for'] || '').split(',').pop().trim();
    if (h) return h;
  } else if (TRUST_PROXY) {
    const h = String(req.headers[TRUST_PROXY] || '').trim();
    if (h) return h;
  }
  return req.socket.remoteAddress || '?';
}

function originOk(req) {
  try { return new URL(req.headers.origin).host === (ORIGIN_HOST || req.headers.host); } catch { return false; }
}

// fixed-window counters: { n, until }
function hit(map, key, win) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || e.until < now) map.set(key, e = { n: 0, until: now + win });
  return ++e.n;
}
function count(map, key) {
  const e = map.get(key);
  return e && e.until > Date.now() ? e.n : 0;
}

const rooms = new Map();    // slug -> { slug, tok, pin, host, guests: Map(id -> ws), seen }
const conns = new Map();    // ip -> open sockets
const ipFails = new Map();  // wrong pins per ip      (5 / 15 min)
const roomFails = new Map();// wrong pins per room    (50 / hour)
const claims = new Map();   // new names per ip       (20 / hour)

// ---- signaling ------------------------------------------------------------

const wss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024, perMessageDeflate: false });

server.on('upgrade', (req, sock, head) => {
  sock.on('error', () => {});
  const ip = ipOf(req);
  if (req.url !== '/ws' || !originOk(req) || (conns.get(ip) || 0) >= MAX_CONN_IP) {
    sock.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return;
  }
  wss.handleUpgrade(req, sock, head, ws => {
    ws.ip = ip;
    conns.set(ip, (conns.get(ip) || 0) + 1);
    wss.emit('connection', ws);
  });
});

wss.on('connection', ws => {
  ws.alive = true;
  ws.tokens = 100;
  ws.last = Date.now();
  ws.bytes = RELAY_RATE * 2;
  ws.bytesAt = Date.now();
  ws.on('pong', () => { ws.alive = true; });
  ws.on('error', () => ws.terminate()); // oversized or malformed frames; never crash the process
  ws.on('message', (data, binary) => {
    // token bucket: 100 burst, 50 msg/s sustained
    const now = Date.now();
    ws.tokens = Math.min(100, ws.tokens + (now - ws.last) / 20);
    ws.last = now;
    if (binary) return ws.room ? relay(ws, data) : ws.close(1008);
    if (--ws.tokens < 0) return ws.close(1008);
    let m;
    try { m = JSON.parse(data); } catch { return ws.close(1003); }
    if (m && typeof m.t === 'string') handle(ws, m);
  });
  ws.on('close', () => {
    const n = conns.get(ws.ip) - 1;
    n > 0 ? conns.set(ws.ip, n) : conns.delete(ws.ip);
    leave(ws);
  });
  send(ws, { t: 'hi', ice: ICE, hb: 1 }); // hb: answers pings (see 'ping')
});

// encrypted guest <-> host frames, for when a direct connection is impossible.
// the server sees only ciphertext. normally each relayed guest has its own
// "pipe" socket to the host, so a slow guest can't hold up signaling or other
// guests; without one, frames to/from the host's main socket carry the 12-char guest id.
function relay(ws, data) {
  const r = ws.room;
  if (!RELAY || !r || !Buffer.isBuffer(data)) return;
  let to, out;
  if (ws.role === 'guest' && ws.pipe) {
    to = ws.pipe;
    out = data;
  } else if (ws.role === 'guest') {
    to = r.host;
    out = Buffer.concat([Buffer.from(ws.id, 'latin1'), data]);
  } else if (ws.role === 'pipe') {
    to = ws.guest;
    out = data;
  } else if (ws.role === 'host' && data.length > 12) {
    to = r.guests.get(data.toString('latin1', 0, 12));
    out = data.subarray(12);
  }
  if (!to || to.readyState !== 1) return;
  to.send(out);
  // throttle the sender instead of dropping: pause reading until the
  // receiver drains and the byte budget refills
  refill(ws);
  ws.bytes -= out.length;
  if ((ws.bytes > 0 && to.bufferedAmount < 1 << 20) || ws.isPaused) return;
  ws.pause();
  const check = () => {
    if (ws.readyState !== 1) return;
    refill(ws);
    if (to.readyState !== 1 || (ws.bytes > 0 && to.bufferedAmount < 256 << 10)) ws.resume();
    else setTimeout(check, 25);
  };
  setTimeout(check, 25);
}
function refill(ws) {
  const now = Date.now();
  ws.bytes = Math.min(RELAY_RATE * 2, ws.bytes + (now - ws.bytesAt) * RELAY_RATE / 1e3);
  ws.bytesAt = now;
}

function unpipe(g) {
  const p = g.pipe;
  g.pipe = null;
  if (p) p.close(1000);
}

function leave(ws) {
  const r = ws.room, role = ws.role;
  ws.room = ws.role = null;
  if (!r) return;
  if (role === 'pipe') {
    // the host's side of a relay is gone: drop the guest so it reconnects
    const g = ws.guest;
    ws.guest = null;
    if (g && g.pipe === ws) { g.pipe = null; g.close(1001); }
  } else if (r.host === ws) {
    r.host = null;
    r.seen = Date.now();
    for (const g of r.guests.values()) { send(g, { t: 'err', e: 'offline' }); g.room = g.role = null; unpipe(g); }
    r.guests.clear();
  } else if (r.guests.get(ws.id) === ws) {
    r.guests.delete(ws.id);
    unpipe(ws);
    send(r.host, { t: 'left', id: ws.id });
  }
}

// table full: drop the offline name that has been away the longest
function evict() {
  let old = null;
  for (const r of rooms.values()) if (!r.host && (!old || r.seen < old.seen)) old = r;
  if (old) rooms.delete(old.slug);
}

function kickGuests(r, why) {
  for (const g of r.guests.values()) { send(g, { t: why }); g.room = g.role = null; unpipe(g); }
  r.guests.clear();
}

function handle(ws, m) {
  const r = ws.room;
  switch (m.t) {
    case 'host': {
      const { slug, token, pin } = m;
      if (ws.role || !validSlug(slug) || !TOKEN.test(token) || !PIN.test(pin)) return send(ws, { t: 'err', e: 'bad' });
      let room = rooms.get(slug);
      const tok = hash(token);
      if (room && !same(room.tok, tok)) return send(ws, { t: 'err', e: 'taken' });
      if (!room) {
        if (hit(claims, ws.ip, 36e5) > 20) return send(ws, { t: 'err', e: 'limit' });
        if (rooms.size >= MAX_ROOMS) evict();
        rooms.set(slug, room = { slug, tok, pin: null, host: null, guests: new Map(), seen: Date.now() });
      }
      if (room.host) { send(room.host, { t: 'err', e: 'replaced' }); leave(room.host); }
      const pinHash = hash(slug + ':' + pin);
      if (room.pin && !same(room.pin, pinHash)) kickGuests(room, 'revoked');
      room.pin = pinHash;
      room.host = ws;
      ws.room = room;
      ws.role = 'host';
      return send(ws, { t: 'hosted', slug });
    }
    case 'join': {
      const { slug, pin } = m;
      if (ws.role || !validSlug(slug) || !PIN.test(pin)) return send(ws, { t: 'err', e: 'bad' });
      const room = rooms.get(slug);
      if (!room) return send(ws, { t: 'err', e: 'nf' });
      if (count(ipFails, ws.ip) >= 5 || count(roomFails, slug) >= 50) return send(ws, { t: 'err', e: 'limit' });
      if (!same(room.pin, hash(slug + ':' + pin))) {
        hit(ipFails, ws.ip, 15 * 6e4);
        hit(roomFails, slug, 36e5);
        return send(ws, { t: 'err', e: 'pin' });
      }
      if (!room.host) return send(ws, { t: 'err', e: 'offline' });
      if (room.guests.size >= MAX_GUESTS) return send(ws, { t: 'err', e: 'full' });
      ws.id = crypto.randomBytes(9).toString('base64url');
      ws.room = room;
      ws.role = 'guest';
      room.guests.set(ws.id, ws);
      return send(ws, { t: 'joined' });
    }
    case 'pipe': {
      // an extra host socket that carries one relayed guest's frames
      const room = validSlug(m.slug) && rooms.get(m.slug);
      const g = room && typeof m.id === 'string' && room.guests.get(m.id);
      if (ws.role || !RELAY || !g || g.pipe || !room.host || !TOKEN.test(m.token) || !same(room.tok, hash(m.token))) return send(ws, { t: 'err', e: 'bad' });
      g.pipe = ws;
      ws.guest = g;
      ws.room = room;
      ws.role = 'pipe';
      return send(ws, { t: 'piped' });
    }
    case 'ping': // browsers check now and then that the socket still works (after sleep, a network switch)
      return send(ws, { t: 'pong' });
    case 'peek': {
      // does a share exist / is its owner online? (names are public anyway: see 'host')
      if (!validSlug(m.slug)) return send(ws, { t: 'err', e: 'bad' });
      const room = rooms.get(m.slug);
      return send(ws, { t: 'peeked', exists: !!room, live: !!(room && room.host) });
    }
    case 'sig': {
      if (!r || !m.data || typeof m.data !== 'object') return;
      if (ws.role === 'guest') return send(r.host, { t: 'sig', from: ws.id, data: m.data });
      if (ws.role === 'host') return send(r.guests.get(m.to), { t: 'sig', data: m.data });
      return;
    }
    case 'pin': {
      if (ws.role !== 'host' || !PIN.test(m.pin)) return;
      r.pin = hash(r.slug + ':' + m.pin);
      roomFails.delete(r.slug); // a fresh pin ends any brute-force lockout
      kickGuests(r, 'revoked');
      return send(ws, { t: 'pinned' });
    }
    case 'end': {
      if (ws.role !== 'host') return;
      kickGuests(r, 'ended');
      rooms.delete(r.slug);
      ws.room = ws.role = null;
      return send(ws, { t: 'ended' });
    }
  }
}

// ---- housekeeping ---------------------------------------------------------

const beat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false;
    ws.ping();
  }
}, 30e3);

const sweep = setInterval(() => {
  const now = Date.now();
  for (const [k, r] of rooms) if (!r.host && now - r.seen > ROOM_TTL) rooms.delete(k);
  for (const map of [ipFails, roomFails, claims]) for (const [k, e] of map) if (e.until < now) map.delete(k);
}, 10 * 6e4);

server.listen(PORT, () => console.log(`listening on :${PORT}`));

function shutdown() {
  clearInterval(beat);
  clearInterval(sweep);
  for (const ws of wss.clients) ws.close(1001);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3e3).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

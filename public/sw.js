'use strict';
// streamed downloads: the page hands a file's bytes to this worker over a
// MessageChannel, and the browser saves them as an ordinary download, straight to
// disk. the stream pulls: each chunk is asked for when the browser wants more, and
// the page only asks the other side for more bytes when it is, so nothing piles up.
// this worker does nothing else: no caching, and every other request goes to the
// network untouched.

const pending = new Map(); // id -> { port, name, size, zip, at }
const ID = /^[a-z0-9]{24}$/;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('message', e => {
  const m = e.data;
  if (!m || typeof m !== 'object') return;
  if (m.t !== 'dl' || !ID.test(m.id) || !e.ports[0]) return; // (pings just keep this worker awake)
  const now = Date.now();
  for (const [k, d] of pending) if (now - d.at > 6e4) pending.delete(k); // asked for but never fetched
  pending.set(m.id, {
    port: e.ports[0],
    name: typeof m.name === 'string' && m.name ? m.name.slice(0, 255) : 'download',
    size: Number.isSafeInteger(m.size) && m.size >= 0 ? m.size : null,
    zip: m.zip === true,
    at: now,
  });
});

// rfc 5987 / 6266: utf-8 name, plus a plain fallback for old clients
function disposition(name) {
  name = name.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd');
  const star = encodeURIComponent(name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const plain = name.replace(/[^\x20-\x7e]|["\\%]/g, '_');
  return `attachment; filename="${plain}"; filename*=UTF-8''${star}`;
}

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  const m = u.origin === self.location.origin && /^\/dl\/([a-z0-9]{24})\/[^/]*$/.exec(u.pathname);
  const d = m && pending.get(m[1]);
  if (!d) return; // not ours: no respondWith, the network answers
  pending.delete(m[1]);
  const { port } = d;
  // an answer to the pull in progress; an abort may also come between pulls
  let wait = null, early = null;
  port.onmessage = ev => { const w = wait; wait = null; if (w) w(ev.data); else early = ev.data; };
  const body = new ReadableStream({
    // one chunk per pull: the page answers with data, the end, or an abort
    pull: ctl => new Promise(res => {
      if (early) { ctl.error(new Error('download cancelled')); return res(); }
      wait = x => {
        if (x && x.t === 'data' && x.buf instanceof ArrayBuffer) ctl.enqueue(new Uint8Array(x.buf));
        else if (x && x.t === 'end') ctl.close();
        else ctl.error(new Error('download cancelled'));
        res();
      };
      port.postMessage({ t: 'pull' });
    }),
    // the download was cancelled in the browser's own ui
    cancel: () => port.postMessage({ t: 'cancel' }),
  }, { highWaterMark: 4 });
  const headers = {
    'Content-Type': d.zip ? 'application/zip' : 'application/octet-stream',
    'Content-Disposition': disposition(d.name),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  if (d.size != null) headers['Content-Length'] = String(d.size);
  e.respondWith(new Response(body, { headers }));
});

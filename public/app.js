'use strict';
// p2p: files, folders and notes go browser to browser over an encrypted webrtc
// data channel. the server only checks the pin and relays the handshake.
(() => {
  const SLUG = /^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$/;
  const ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
  // send buffer: refill below LOW, pause above HIGH (chrome closes a channel past 16 MB).
  // MSG: largest data channel message we send, when the other side accepts it
  const LOW = 2 << 20, HIGH = 8 << 20, PART = 8000, MSG = 256 << 10;
  const TITLE_MAX = 100, NOTE_MAX = 100000, NOTES_MAX = 200;
  const ZIP_MAX = 0xffffffff; // no zip64: 4 GB per folder download
  const app = document.getElementById('app');

  // ---- utils --------------------------------------------------------------

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v != null && v !== false) e.setAttribute(k, v === true ? '' : v);
    }
    e.append(...kids.flat().filter(k => k != null && k !== false));
    return e;
  }
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
    del(k) { try { localStorage.removeItem(k); } catch {} },
  };
  // theme: follows the system until a choice is made
  const themeBtn = document.getElementById('theme');
  const darkMq = matchMedia('(prefers-color-scheme: dark)');
  const isDark = () => document.documentElement.dataset.theme ? document.documentElement.dataset.theme === 'dark' : darkMq.matches;
  function setTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    themeBtn.textContent = isDark() ? 'light' : 'dark';
    // the phone's browser bar follows the page
    const forced = document.documentElement.dataset.theme;
    document.querySelectorAll('meta[name=theme-color]').forEach(m => { m.content = (forced ? forced === 'dark' : /dark/.test(m.media)) ? '#000' : '#fff'; });
  }
  setTheme(store.get('p2p:theme'));
  if (darkMq.addEventListener) darkMq.addEventListener('change', () => setTheme());
  themeBtn.addEventListener('click', () => {
    const t = isDark() ? 'light' : 'dark';
    store.set('p2p:theme', t);
    setTheme(t);
  });

  function rnd(n) {
    const a = new Uint32Array(1), lim = 2 ** 32 - (2 ** 32 % n);
    do crypto.getRandomValues(a); while (a[0] >= lim);
    return a[0] % n;
  }
  const newPin = () => String(rnd(1e7)).padStart(7, '0');
  const newSlug = () => Array.from({ length: 5 }, () => ABC[rnd(ABC.length)]).join('');
  const newId = () => Array.from({ length: 12 }, () => ABC[rnd(ABC.length)]).join('');
  const newToken = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const size = b => b < 1024 ? b + ' B' : b < 1 << 20 ? (b / 1024).toFixed(1) + ' KB' : b < 1 << 30 ? (b / 1048576).toFixed(1) + ' MB' : (b / 1073741824).toFixed(2) + ' GB';
  const pct = (a, b) => (b ? Math.floor(a / b * 100) : 100) + '%';
  const arr = a => Array.isArray(a) ? a : [];
  function copy(text, btn) {
    const done = () => {
      if (!btn.dataset.label) btn.dataset.label = btn.textContent;
      btn.textContent = 'copied';
      setTimeout(() => { btn.textContent = btn.dataset.label; }, 1200);
    };
    if (navigator.clipboard) return navigator.clipboard.writeText(text).then(done, () => {});
    // plain-http pages have no clipboard api
    const t = el('textarea', { readonly: true, class: 'offscreen' }, text);
    document.body.append(t);
    t.select();
    try { if (document.execCommand('copy')) done(); } catch {}
    t.remove();
  }
  // relative, no "..", no control chars
  function clean(p) {
    if (typeof p !== 'string') return null;
    const parts = p.replace(/\\/g, '/').split('/').map(s => s.replace(/[\x00-\x1f\x7f]/g, '').trim()).filter(s => s && s !== '.' && s !== '..');
    const out = parts.join('/');
    return out && out.length <= 1024 && parts.length <= 32 ? out : null;
  }
  function mkNote(title, text, id) {
    if (typeof title !== 'string' || typeof text !== 'string' || text.length > NOTE_MAX) return null;
    return { id: id || newId(), title: title.trim().slice(0, TITLE_MAX) || 'untitled', text, t: Date.now() };
  }
  // big transfers: fold received chunks into a blob every 16 MB so the
  // browser can page them to disk instead of holding everything in ram (phones)
  function collect(t, buf) {
    t.parts.push(buf);
    t.mem = (t.mem || 0) + buf.byteLength;
    if (t.mem < 16 << 20) return;
    t.parts = [new Blob(t.parts)];
    t.mem = 0;
  }
  // sha-256 in plain js: crypto.subtle is missing on plain-http pages, and this
  // reads big files in slices instead of loading them whole into memory
  const K256 = Uint32Array.from('428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2'.split(' '), h => parseInt(h, 16));
  async function sha256(blob, prog) {
    // native when available and the file fits comfortably in memory (less of it on
    // phones): many times faster, and keeps the main thread free for transfers
    if (subtle && blob.size <= (coarse() ? 64 : 256) << 20) {
      const d = new Uint8Array(await subtle.digest('SHA-256', await blob.arrayBuffer()));
      if (prog) prog(blob.size);
      return [...d].map(x => x.toString(16).padStart(2, '0')).join('');
    }
    const H = Uint32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19), W = new Uint32Array(64);
    const blocks = u => {
      for (let o = 0; o < u.length; o += 64) {
        for (let i = 0; i < 16; i++) W[i] = u[o + i * 4] << 24 | u[o + i * 4 + 1] << 16 | u[o + i * 4 + 2] << 8 | u[o + i * 4 + 3];
        for (let i = 16; i < 64; i++) {
          const x = W[i - 15], y = W[i - 2];
          W[i] = ((x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ x >>> 3) + W[i - 7] + ((y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ y >>> 10) + W[i - 16];
        }
        let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (let i = 0; i < 64; i++) {
          const t1 = h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (e & f ^ ~e & g) + K256[i] + W[i] | 0;
          const t2 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ a & c ^ b & c) | 0;
          h = g; g = f; f = e; e = d + t1 | 0; d = c; c = b; b = a; a = t1 + t2 | 0;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
      }
    };
    let o = 0;
    for (let left; (left = blob.size - o) >= 64; o += left) {
      left = Math.min(4 << 20, left - left % 64);
      blocks(new Uint8Array(await blob.slice(o, o + left).arrayBuffer()));
      if (prog) await prog(o + left); // may hold the hashing up for a while
    }
    // last partial block, then 0x80, zeros and the length in bits
    const tail = new Uint8Array(await blob.slice(o).arrayBuffer()), pad = new Uint8Array(tail.length < 56 ? 64 : 128), v = new DataView(pad.buffer);
    pad.set(tail);
    pad[tail.length] = 0x80;
    v.setUint32(pad.length - 8, Math.floor(blob.size / 2 ** 29));
    v.setUint32(pad.length - 4, blob.size % 2 ** 29 * 8);
    blocks(pad);
    return [...H].map(x => x.toString(16).padStart(8, '0')).join('');
  }
  const HASH = /^[0-9a-f]{64}$/;
  // small confirm bubble beside a button, instead of a browser dialog.
  // no() runs when it is dismissed any way other than "yes"
  function ask(btn, question, yes, no) {
    document.querySelectorAll('.pop').forEach(p => p.close());
    const close = ok => {
      if (!pop.isConnected) return;
      pop.remove();
      removeEventListener('pointerdown', outside, true);
      removeEventListener('keydown', esc);
      if (ok) yes(); else if (no) no();
    };
    const outside = e => !pop.contains(e.target) && close();
    const esc = e => e.key === 'Escape' && close();
    const noBtn = el('button', { class: 'link', onclick: () => close() }, 'no');
    const pop = el('span', { class: 'pop', role: 'alertdialog' }, question,
      el('button', { onclick: () => close(true) }, 'yes'), noBtn);
    pop.close = () => close();
    btn.parentElement.append(pop);
    addEventListener('pointerdown', outside, true);
    addEventListener('keydown', esc);
    noBtn.focus();
  }
  // qr code as svg, drawn from public/qr.js (qrcode-generator, MIT).
  // always dark on white with a quiet zone, so phone cameras can read it
  function qrSvg(text) {
    const q = window.qrcode(0, 'M'), NS = 'http://www.w3.org/2000/svg', svg = (t, a) => {
      const e = document.createElementNS(NS, t);
      for (const k in a) e.setAttribute(k, a[k]);
      return e;
    };
    q.addData(text);
    q.make();
    const n = q.getModuleCount();
    let d = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
    const s = svg('svg', { viewBox: `0 0 ${n + 8} ${n + 8}`, class: 'qr', role: 'img', 'aria-label': 'qr code: ' + text });
    s.append(svg('rect', { width: '100%', height: '100%', fill: '#fff' }), svg('path', { d, fill: '#000' }));
    return s;
  }
  function save(blob, name) {
    const u = URL.createObjectURL(blob);
    const a = el('a', { href: u, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 6e4);
  }
  // run fn over items, n at a time; takes no new ones once sig is aborted
  async function pool(items, n, fn, sig) {
    let i = 0;
    const worker = async () => { while (i < items.length && !sig.aborted) { const k = i++; await fn(items[k], k); } };
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
    if (sig.aborted) throw sig.reason;
  }
  const clock = s => s < 60 ? Math.ceil(s) + 's' : s < 3600 ? Math.floor(s / 60) + 'm ' + String(Math.floor(s % 60)).padStart(2, '0') + 's' : Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm';
  const coarse = () => matchMedia('(pointer: coarse)').matches; // touch screen

  // ---- staying connected in the background ----------------------------------

  // back in front, back online or unfrozen: check connections now instead of
  // waiting on timers the browser slowed down while the page was hidden
  const wake = new Set();
  const woke = () => wake.forEach(f => f());
  document.addEventListener('visibilitychange', () => document.visibilityState === 'visible' && woke());
  document.addEventListener('resume', woke);
  addEventListener('online', woke);
  addEventListener('pageshow', e => e.persisted && woke());

  // a held web lock keeps chrome from freezing the tab while it is in the background
  function hold() {
    let gone = false, free = () => { gone = true; };
    if (navigator.locks) navigator.locks.request('p2p:' + newId(), () => gone ? null : new Promise(r => { free = r; })).catch(() => {});
    return () => free();
  }

  // while files are moving: keep the screen on (a phone that locks pauses the page
  // and drops the connection), no pull-to-refresh, and ask before leaving the page
  const busy = (() => {
    const on = new Set();
    let lock = null, asking = false;
    const leave = e => { e.preventDefault(); e.returnValue = ''; };
    async function sync() {
      const want = on.size > 0;
      document.documentElement.classList.toggle('busy', want);
      want ? addEventListener('beforeunload', leave) : removeEventListener('beforeunload', leave);
      if (!want && lock) { const l = lock; lock = null; l.release().catch(() => {}); }
      if (!want || lock || asking || !navigator.wakeLock || document.visibilityState !== 'visible') return;
      asking = true;
      try {
        const l = lock = await navigator.wakeLock.request('screen');
        l.addEventListener('release', () => { if (lock === l) lock = null; });
      } catch {}
      asking = false;
      if (!on.size) sync(); // finished while asking
    }
    document.addEventListener('visibilitychange', sync); // the browser drops the lock whenever the page is hidden
    const set = (key, yes) => { yes ? on.add(key) : on.delete(key); sync(); };
    set.clear = () => { on.clear(); sync(); };
    return set;
  })();

  // ---- storage (survives reloads) -------------------------------------------

  // shares this browser owns: { slug: { slug, token, pin, mode } }
  // (only well-formed entries: localStorage is not trusted to be intact)
  function hosts() {
    const h = store.get('p2p:hosts'), out = {};
    for (const s of Object.values(h && typeof h === 'object' ? h : {})) {
      if (s && SLUG.test(s.slug) && /^[\w-]{43}$/.test(s.token) && /^\d{7}$/.test(s.pin)) out[s.slug] = { slug: s.slug, token: s.token, pin: s.pin, mode: s.mode === 'ro' ? 'ro' : 'rw' };
    }
    return out;
  }
  function setHost(sess) {
    const h = hosts(), { fresh, ...s } = sess;
    h[s.slug] = s;
    store.set('p2p:hosts', h);
  }
  function delHost(slug) {
    const h = hosts();
    delete h[slug];
    store.set('p2p:hosts', h);
  }
  const joined = () => {
    const out = [];
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k.startsWith('p2p:g:') && SLUG.test(k.slice(6))) out.push(k.slice(6)); } } catch {}
    return out.sort();
  };

  // indexeddb, keyed [share, path] / [share, note id]
  const idb = (() => {
    let p;
    const open = () => p || (p = new Promise((res, rej) => {
      const r = indexedDB.open('p2p', 2);
      r.onupgradeneeded = () => {
        const d = r.result;
        for (const n of [...d.objectStoreNames]) d.deleteObjectStore(n);
        d.createObjectStore('files', { keyPath: ['slug', 'path'] });
        d.createObjectStore('notes', { keyPath: ['slug', 'id'] });
      };
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    }));
    const run = async (name, mode, fn) => {
      const d = await open();
      return new Promise((res, rej) => {
        const t = d.transaction(name, mode);
        const q = fn(t.objectStore(name));
        t.oncomplete = () => res(q && q.result);
        t.onerror = t.onabort = () => rej(t.error || new Error('storage error'));
      });
    };
    // one share's view of the stores
    return slug => {
      const every = IDBKeyRange.bound([slug], [slug, []]);
      return {
        all: s => run(s, 'readonly', o => o.getAll(every)),
        get: (s, k) => run(s, 'readonly', o => o.get([slug, k])),
        put: (s, v) => run(s, 'readwrite', o => o.put({ ...v, slug })),
        del: (s, k) => run(s, 'readwrite', o => o.delete([slug, k])),
        // read, check and write in one transaction, so a newer put can't be overwritten
        patch: (s, k, fn) => run(s, 'readwrite', o => { const q = o.get([slug, k]); q.onsuccess = () => { const v = q.result && fn(q.result); if (v) o.put(v); }; }),
        delPrefix: (s, pre) => run(s, 'readwrite', o => o.delete(IDBKeyRange.bound([slug, pre], [slug, pre + '\uffff']))),
        clear: () => Promise.all(['files', 'notes'].map(s => run(s, 'readwrite', o => o.delete(every)))),
      };
    };
  })();

  // ---- wire format --------------------------------------------------------
  // json messages are strings (split into parts when large).
  // binary frames are [u32 request id][bytes].

  function tx(dc, m) {
    if (!dc || dc.readyState !== 'open') return;
    const s = JSON.stringify(m);
    if (s.length <= PART) return dc.send(s);
    for (let i = 0; i < s.length; i += PART) dc.send(JSON.stringify({ t: '+', d: s.slice(i, i + PART), end: i + PART >= s.length }));
  }
  function rx(st, raw) {
    let m;
    try { m = JSON.parse(raw); } catch { return null; }
    if (!m || typeof m !== 'object') return null;
    if (m.t !== '+') return m;
    if (typeof m.d !== 'string') return null;
    st.buf = (st.buf || '') + m.d;
    if (st.buf.length > 32e6) st.buf = '';
    if (!m.end) return null;
    const s = st.buf;
    st.buf = '';
    try { return JSON.parse(s); } catch { return null; }
  }
  // wait for room in the send buffer. the relay has no event for that, and a channel
  // closed along with its connection doesn't always fire one either
  const drain = dc => new Promise(r => {
    const done = () => {
      clearInterval(t);
      if (!dc.relay) { dc.removeEventListener('bufferedamountlow', done); dc.removeEventListener('close', done); }
      r();
    };
    const t = setInterval(() => (dc.readyState !== 'open' || dc.bufferedAmount < LOW) && done(), dc.relay ? 25 : 1000);
    if (!dc.relay) { dc.addEventListener('bufferedamountlow', done); dc.addEventListener('close', done); }
  });
  // send blob from byte off on. the file is read 2 MB at a time, the next slice while
  // this one goes out, in the largest messages the other side takes. prog gets the
  // bytes that left the send buffer. true when all was sent, false when stop() said
  // to quit; throws if the connection goes
  async function stream(pc, dc, req, blob, prog, stop, off = 0) {
    const n = Math.min(MSG, (pc.sctp && pc.sctp.maxMessageSize) || 65536) - 4;
    const step = Math.max(1, Math.floor((2 << 20) / n)) * n;
    const read = o => { const p = blob.slice(o, o + step).arrayBuffer(); p.catch(() => {}); return p; };
    let next = off < blob.size ? read(off) : null;
    for (let o = off; o < blob.size; o += step) {
      const buf = new Uint8Array(await next);
      next = o + step < blob.size ? read(o + step) : null;
      for (let i = 0; i < buf.length; i += n) {
        if (dc.bufferedAmount > HIGH) await drain(dc);
        if (stop && stop()) return false;
        if (dc.readyState !== 'open') throw new Error('disconnected');
        const part = buf.subarray(i, i + n), frame = new Uint8Array(part.length + 4);
        new DataView(frame.buffer).setUint32(0, req);
        frame.set(part, 4);
        dc.send(frame);
        if (prog) prog(Math.max(0, o + i + part.length - dc.bufferedAmount));
      }
    }
    return true;
  }

  // ---- relay ---------------------------------------------------------------
  // fallback for when the browsers can't reach each other directly: frames go
  // through the signaling server, end-to-end encrypted with aes-gcm under a key
  // from an ecdh exchange done during the handshake. the server only sees
  // ciphertext. quacks like an RTCDataChannel so the rest of the code doesn't care.

  const subtle = window.crypto && crypto.subtle;
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  const RELAY_PC = { sctp: { maxMessageSize: 65536 } }; // + headers, well under the server's 128 KB cap
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = u8 => btoa(String.fromCharCode(...u8));
  async function keypair() {
    if (!subtle) return null;
    const kp = await subtle.generateKey(ECDH, false, ['deriveBits']);
    return { priv: kp.privateKey, pub: b64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey))) };
  }
  async function shared(kp, pub) {
    const k = await subtle.importKey('raw', Uint8Array.from(atob(pub), c => c.charCodeAt(0)), ECDH, false, []);
    const bits = await subtle.deriveBits({ name: 'ECDH', public: k }, kp.priv, 256);
    const ikm = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('p2p relay v1') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  // nonce = [sender side][0 0 0][u64 counter]: never reused, and the receiver
  // only accepts the exact next counter, so frames can't be replayed,
  // reordered or silently dropped by the server
  const nonce = (side, n) => {
    const iv = new Uint8Array(12), v = new DataView(iv.buffer);
    iv[0] = side;
    v.setUint32(4, Math.floor(n / 2 ** 32));
    v.setUint32(8, n >>> 0);
    return iv;
  };
  class Relay {
    // side: 0 guest, 1 host
    constructor(key, side, out, buffered) {
      Object.assign(this, { key, side, out, buffered, relay: true, readyState: 'open', queued: 0, sent: 0, got: 0, tx: Promise.resolve(), rx: Promise.resolve(), onmessage: null, onclose: null });
    }
    get bufferedAmount() { return this.queued + this.buffered(); }
    send(data) {
      if (this.readyState !== 'open') return;
      const str = typeof data === 'string';
      const body = str ? enc.encode(data) : new Uint8Array(data.buffer || data, data.byteOffset || 0, data.byteLength);
      const frame = new Uint8Array(body.length + 1);
      frame[0] = str ? 0 : 1;
      frame.set(body, 1);
      this.queued += frame.length;
      this.tx = this.tx.then(async () => {
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce(this.side, this.sent++) }, this.key, frame));
        this.queued -= frame.length;
        if (this.readyState === 'open') this.out(ct);
      }).catch(() => this.close());
    }
    receive(buf) {
      this.rx = this.rx.then(async () => {
        if (this.readyState !== 'open') return;
        const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce(1 - this.side, this.got++) }, this.key, buf));
        if (this.onmessage) this.onmessage({ data: pt[0] ? pt.slice(1).buffer : dec.decode(pt.subarray(1)) });
      }).catch(() => this.close()); // tampered or wrong key
    }
    close() {
      if (this.readyState === 'closed') return;
      this.readyState = 'closed';
      if (this.onclose) this.onclose();
    }
  }

  // ---- zip (store only) for folder downloads ------------------------------

  const CRC = new Int32Array(256).map((_, n) => { for (let k = 0; k < 8; k++) n = n & 1 ? 0xEDB88320 ^ (n >>> 1) : n >>> 1; return n; });
  async function zip(entries) {
    if (entries.length > 0xffff || entries.reduce((s, e) => s + e.blob.size + 30 + e.name.length * 3, 0) > ZIP_MAX) {
      throw new Error('folder too big to zip (4 GB or 65,535 files) — get the files one by one');
    }
    const out = [], cd = [];
    let off = 0;
    for (const { name, blob, mtime } of entries) {
      let c = -1;
      for (let o = 0; o < blob.size; o += 1 << 20) {
        const u = new Uint8Array(await blob.slice(o, o + (1 << 20)).arrayBuffer());
        for (let i = 0; i < u.length; i++) c = CRC[(c ^ u[i]) & 255] ^ (c >>> 8);
      }
      c = ~c >>> 0;
      const d = new Date(Math.max(mtime || Date.now(), 315532800000));
      const time = d.getHours() << 11 | d.getMinutes() << 5 | d.getSeconds() >> 1;
      const date = (d.getFullYear() - 1980) << 9 | (d.getMonth() + 1) << 5 | d.getDate();
      const nm = enc.encode(name);
      const lh = new DataView(new ArrayBuffer(30));
      const ch = new DataView(new ArrayBuffer(46));
      [[lh, 0x04034b50, 4], [ch, 0x02014b50, 6]].forEach(([v, sig, b]) => {
        v.setUint32(0, sig, true);
        if (b === 6) v.setUint16(4, 20, true);
        v.setUint16(b, 20, true);
        v.setUint16(b + 2, 0x0800, true); // utf-8 names
        v.setUint16(b + 6, time, true);
        v.setUint16(b + 8, date, true);
        v.setUint32(b + 10, c, true);
        v.setUint32(b + 14, blob.size, true);
        v.setUint32(b + 18, blob.size, true);
        v.setUint16(b + 22, nm.length, true);
      });
      ch.setUint32(42, off, true);
      out.push(lh, nm, blob);
      cd.push(ch, nm);
      off += 30 + nm.length + blob.size;
    }
    const cdSize = cd.reduce((s, p) => s + p.byteLength, 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, entries.length, true);
    end.setUint16(10, entries.length, true);
    end.setUint32(12, cdSize, true);
    end.setUint32(16, off, true);
    return new Blob([...out, ...cd, end], { type: 'application/zip' });
  }

  // ---- dropped folders ----------------------------------------------------

  async function walk(entry, pre, out) {
    if (entry.isFile) out.push([await new Promise((r, j) => entry.file(r, j)), pre + entry.name]);
    else if (entry.isDirectory) {
      const rd = entry.createReader();
      let batch;
      do {
        batch = await new Promise((r, j) => rd.readEntries(r, j));
        for (const e of batch) await walk(e, pre + entry.name + '/', out);
      } while (batch.length);
    }
  }

  // ---- signaling ----------------------------------------------------------

  function signal(onmsg, onopen) {
    let ws = null, stop = false, delay = 1000, retry = null, hb = false, pingAt = 0, heard = 0;
    const api = {
      ice: [],
      onbin: null,
      send: m => ws && ws.readyState === 1 && ws.send(JSON.stringify(m)),
      bin: b => ws && ws.readyState === 1 && ws.send(b),
      buffered: () => ws ? ws.bufferedAmount : 0,
      close: () => { stop = true; clearTimeout(retry); clearInterval(beat); wake.delete(check); if (ws) ws.close(); },
    };
    // a socket can die without saying so (laptop sleep, wifi to mobile data): ping the
    // server, and replace a socket that stopped answering
    const ping = () => { pingAt = Date.now(); api.send({ t: 'ping' }); };
    const quiet = () => hb && pingAt > heard;
    function dead(s) {
      if (ws !== s) return;
      s.onclose = s.onmessage = null;
      s.close();
      lost();
    }
    function lost() {
      ws = null;
      if (stop) return;
      onmsg({ t: 'down' });
      if (stop) return; // closed by whoever heard about it
      retry = setTimeout(connect, delay * (.8 + Math.random() * .4));
      delay = Math.min(delay * 1.6, 15000);
    }
    const beat = setInterval(() => {
      if (!ws || ws.readyState !== 1 || !hb) return;
      if (quiet() && Date.now() - pingAt > 1e4) return dead(ws);
      ping();
    }, 2e4);
    // back in front or online: reconnect now, or make sure the socket still works
    function check() {
      if (stop) return;
      if (!ws) { clearTimeout(retry); delay = 1000; return connect(); }
      if (ws.readyState !== 1 || !hb) return;
      const s = ws;
      ping();
      setTimeout(() => quiet() && dead(s), 5000);
    }
    wake.add(check);
    function connect() {
      if (stop) return;
      const s = ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
      hb = false;
      s.binaryType = 'arraybuffer';
      s.onmessage = e => {
        heard = Date.now();
        if (typeof e.data !== 'string') return api.onbin && api.onbin(e.data);
        let m;
        try { m = JSON.parse(e.data); } catch { return; }
        if (!m || typeof m.t !== 'string' || m.t === 'pong') return;
        if (m.t !== 'hi') return onmsg(m);
        delay = 1000;
        hb = m.hb === 1; // older servers don't answer pings
        api.ice = arr(m.ice);
        onopen();
      };
      s.onclose = () => ws === s && lost();
    }
    connect();
    return api;
  }

  // ---- the panel: notes + files, shared by host and guest -----------------
  // src: { files, notes, writable(), get(path, prog, signal), put(blob, path, mtime, prog, hash, signal), rm(path, dir), note(title, text, id), unnote(id) }

  let dropTo = null, pasteTo = null;
  function panel(src, say, statusEl) {
    const status = t => view === out && say(t); // quiet once this panel is gone
    const open = new Set();
    const notesEl = el('ul', { class: 'ls' });
    const filesEl = el('ul', { class: 'ls' });
    const crumbs = el('div', { class: 'row grow' });
    const title = el('input', { class: 'grow', placeholder: 'title', maxlength: String(TITLE_MAX), 'aria-label': 'note title' });
    const text = el('textarea', { placeholder: 'paste or type anything…', 'aria-label': 'note text', maxlength: String(NOTE_MAX) });
    let editing = null; // id of the note being edited, null for a new one
    const closeNote = () => { noteForm.hidden = true; editing = null; title.value = text.value = ''; };
    const openNote = n => {
      editing = n ? n.id : null;
      title.value = n ? n.title : '';
      text.value = n ? n.text : '';
      noteForm.hidden = false;
      (n ? text : title).focus();
    };
    const noteForm = el('form', { hidden: true, onsubmit: e => {
      e.preventDefault();
      if (!text.value.trim()) return text.focus();
      src.note(title.value, text.value, editing);
      closeNote();
    } }, el('div', { class: 'row' }, title), text, el('div', { class: 'row' }, el('button', { type: 'submit' }, 'save'), el('button', { type: 'button', class: 'link', onclick: closeNote }, 'cancel')));
    const addNote = el('button', { onclick: () => openNote(null) }, '+ note');
    const fileIn = el('input', { type: 'file', multiple: true, onchange: () => { upload([...fileIn.files].map(f => [f, f.name])); fileIn.value = ''; } });
    const dirIn = el('input', { type: 'file', webkitdirectory: true, onchange: () => { upload([...dirIn.files].map(f => [f, f.webkitRelativePath || f.name])); dirIn.value = ''; } });
    // labels don't open their file picker from the keyboard on their own
    const pick = (label, input) => el('label', { class: 'btn', tabindex: '0', onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } } }, label, input);
    const tools = el('span', { class: 'row' }, pick('+ files', fileIn), pick('+ folder', dirIn));

    const cwd = () => { try { return clean(decodeURIComponent(location.hash.slice(1))) || ''; } catch { return ''; } };
    const cd = p => { location.hash = p ? encodeURIComponent(p).replace(/%2F/g, '/') : ''; };
    const fail = e => status('error: ' + (e && e.message || e));

    // transfers in progress, each with an AbortController: "cancel" stops them all
    const running = new Set(), title0 = document.title, me = {};
    const bar = el('progress', { class: 'bar', max: '1', value: '0', hidden: true });
    const cancelBtn = el('button', { class: 'link', hidden: true, onclick: () => running.forEach(c => c.abort()) }, 'cancel');
    const foot = el('div', { class: 'foot' }, el('div', { class: 'row' }, statusEl, cancelBtn), bar);
    const track = () => { const c = new AbortController(); running.add(c); idle(); return c; };
    const untrack = c => { running.delete(c); idle(); };
    function idle() {
      cancelBtn.hidden = !running.size;
      busy(me, running.size > 0);
      if (running.size) return;
      bar.hidden = true;
      foot.classList.remove('live');
      if (view === out) document.title = title0;
    }
    // progress on the status line, bar and tab title: at most 5 updates a second, with speed and time left
    function meter(total, label) {
      let drawn = 0, rate = 0, t0 = performance.now(), b0 = 0, prev = t0;
      return b => {
        const now = performance.now();
        if (now - prev > 1500) { t0 = now; b0 = b; } // after a pause (reconnecting): don't average it in
        prev = now;
        if (now - t0 >= 1000) {
          const r = (b - b0) / (now - t0) * 1e3;
          rate = Math.max(0, rate ? rate * .6 + r * .4 : r);
          t0 = now;
          b0 = b;
        }
        if ((now - drawn < 200 && b < total) || view !== out) return;
        drawn = now;
        const left = rate && b < total ? (total - b) / rate : 0;
        say(`${label()} ${pct(b, total)}${rate ? ` · ${size(Math.round(rate))}/s` : ''}${left >= 1 ? ` · ${clock(left)} left` : ''}`);
        bar.value = total ? b / total : 1;
        bar.hidden = false;
        foot.classList.add('live');
        document.title = `${pct(b, total)} · ${title0}`;
      };
    }

    // upload batches run one after another, each into the folder that was open when it was added
    let queue = Promise.resolve();
    function upload(items) {
      if (!src.writable() || !items.length) return;
      const base = cwd() ? cwd() + '/' : '', ctl = track();
      queue = queue.then(() => send(items, base, ctl)).finally(() => untrack(ctl));
    }
    // yes/no bubble on the status line (the cancel button lives there, even while hidden)
    const sure = q => new Promise(r => ask(cancelBtn, q, () => r(true), () => r(false)));
    const short = s => `"${s.length > 40 ? s.slice(0, 18) + '…' + s.slice(-18) : s}"`;
    async function send(items, base, ctl) {
      const sig = ctl.signal;
      let done = 0, skipped = 0;
      try {
        if (sig.aborted) throw sig.reason;
        // same content as a file already here, or earlier in this batch? only files
        // whose size matches another one get hashed, so most uploads skip this
        const have = new Map(), sizes = new Map(), dups = new Map();
        for (const f of src.files.values()) if (f.hash) { have.set(f.hash, [f.path, false]); sizes.set(f.size, 1); }
        for (const [f] of items) sizes.set(f.size, (sizes.get(f.size) || 0) + 1);
        for (const it of items) {
          const [f, rel] = it;
          if (sizes.get(f.size) < 2) continue;
          it.hash = await sha256(f, b => status(`checking ${rel} ${pct(b, f.size)}`));
          if (have.has(it.hash)) dups.set(it, have.get(it.hash));
          else have.set(it.hash, [clean(base + rel), true]);
        }
        if (dups.size) {
          const [[[, rel], [at, batch]]] = dups, same = at === clean(base + rel);
          status('');
          const ok = await sure(dups.size > 1 ? `${dups.size} of these files already exist. upload them anyway?`
            : batch ? `${short(rel)} is the same file as ${short(at)}. upload both?`
            : `${short(rel)} already exists${same ? '' : ' as ' + short(at)}. upload anyway?`);
          if (!ok) { skipped = dups.size; items = items.filter(it => !dups.has(it)); }
        }
        if (sig.aborted) throw sig.reason;
        items = items.filter(([, rel]) => clean(base + rel));
        const total = items.reduce((s, [f]) => s + f.size, 0);
        let sent = 0;
        const show = meter(total, () => items.length === 1 ? `↑ ${items[0][1]}` : `↑ ${done}/${items.length}`);
        // a few at once, so small files don't each wait out a round trip
        await pool(items, 3, async it => {
          const [f, rel] = it;
          let last = 0;
          const step = b => { sent += b - last; last = b; show(sent); };
          await src.put(f, clean(base + rel), f.lastModified, step, it.hash, sig);
          done++;
          step(f.size);
        }, sig);
        status(!done && skipped ? 'not uploaded — already here' : `↑ ${done} file${done === 1 ? '' : 's'} added${skipped ? ` · ${skipped} duplicate${skipped === 1 ? '' : 's'} skipped` : ''}`);
      } catch (e) {
        const stopped = sig.aborted;
        ctl.abort(); // a failed file stops the rest of its batch
        stopped ? status(`↑ cancelled${done ? ` · ${done} file${done === 1 ? '' : 's'} added` : ''}`) : fail(e);
      }
    }
    async function get(path, isDir) {
      const name = path.split('/').pop(), ctl = track(), sig = ctl.signal;
      try {
        if (!isDir) {
          const f = src.files.get(path);
          const blob = await src.get(path, meter(f ? f.size : 0, () => `↓ ${name}`), sig);
          if (sig.aborted) throw sig.reason;
          save(blob, name);
          return status(`↓ ${name} done`);
        }
        const list = [...src.files.values()].filter(f => f.path.startsWith(path + '/'));
        const total = list.reduce((s, f) => s + f.size, 0), entries = [];
        let got = 0, done = 0;
        const show = meter(total, () => `↓ ${name}/ ${done}/${list.length}`);
        await pool(list, 4, async (f, k) => {
          let last = 0;
          const step = b => { got += b - last; last = b; show(got); };
          const blob = await src.get(f.path, step, sig);
          done++;
          step(f.size);
          entries[k] = { name: f.path.slice(path.length - name.length), blob, mtime: f.mtime };
        }, sig);
        status(`zipping ${name}…`);
        save(await zip(entries), name + '.zip');
        status(`↓ ${name}.zip done`);
      } catch (e) {
        const stopped = sig.aborted;
        ctl.abort(); // a failed file stops the rest of the folder
        stopped ? status(`↓ ${name} cancelled`) : fail(e);
      } finally {
        untrack(ctl);
      }
    }

    function row(label, meta, acts) {
      return el('li', {}, label, el('span', { class: 'mute meta' }, meta), el('span', { class: 'acts' }, acts));
    }
    function refresh() {
      const w = src.writable();
      addNote.hidden = tools.hidden = !w;
      if (!w || (editing && !src.notes.has(editing))) closeNote();

      const notes = [...src.notes.values()].sort((a, b) => b.t - a.t);
      notesEl.replaceChildren(...notes.map(n => {
        const li = row(
          el('button', { class: 'link', 'aria-expanded': String(open.has(n.id)), onclick: () => { open.has(n.id) ? open.delete(n.id) : open.add(n.id); refresh(); } }, n.title),
          new Date(n.t).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }),
          [el('button', { onclick: e => copy(n.text, e.target) }, 'copy'), w && el('button', { onclick: () => openNote(n) }, 'edit'), w && el('button', { onclick: e => ask(e.target, 'delete this note?', () => src.unnote(n.id)) }, 'del')],
        );
        if (open.has(n.id)) li.append(el('pre', {}, n.text));
        return li;
      }));
      if (!notes.length) notesEl.append(el('li', { class: 'empty' }, 'no notes'));

      const dir = cwd(), pre = dir ? dir + '/' : '';
      const dirs = new Map(), files = [];
      for (const f of src.files.values()) {
        if (!f.path.startsWith(pre)) continue;
        const rest = f.path.slice(pre.length), i = rest.indexOf('/');
        if (i < 0) { files.push(f); continue; }
        const d = dirs.get(rest.slice(0, i)) || { n: 0, size: 0 };
        d.n++;
        d.size += f.size;
        dirs.set(rest.slice(0, i), d);
      }
      const segs = dir ? dir.split('/') : [];
      crumbs.replaceChildren(el('button', { class: 'link', onclick: () => cd('') }, '/'),
        ...segs.flatMap((s, i) => [' ', el('button', { class: 'link', onclick: () => cd(segs.slice(0, i + 1).join('/')) }, s), ' /']));
      const byName = (a, b) => a.localeCompare(b, undefined, { numeric: true });
      filesEl.replaceChildren(
        ...[...dirs.keys()].sort(byName).map(d => row(
          el('button', { class: 'link', onclick: () => cd(pre + d) }, d + '/'),
          `${dirs.get(d).n} · ${size(dirs.get(d).size)}`,
          [el('button', { onclick: () => get(pre + d, true) }, 'get'), w && el('button', { onclick: e => ask(e.target, `delete ${d}/ and all inside?`, () => src.rm(pre + d, true)) }, 'del')],
        )),
        ...files.sort((a, b) => byName(a.path, b.path)).map(f => {
          const name = f.path.slice(pre.length);
          return row(el('span', {}, name), size(f.size),
            [el('button', { onclick: () => get(f.path) }, 'get'), w && el('button', { onclick: e => ask(e.target, 'delete this file?', () => src.rm(f.path)) }, 'del')]);
        }),
      );
      if (!dirs.size && !files.length) filesEl.append(el('li', { class: 'empty' }, !w ? 'empty' : coarse() ? 'empty — tap + files to add some' : 'empty — drop files or folders, or paste an image, anywhere on the page'));
    }

    dropTo = async e => {
      if (!src.writable()) return;
      const entries = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
      const items = [];
      try {
        if (entries.length) for (const en of entries) await walk(en, '', items);
        else for (const f of e.dataTransfer.files) items.push([f, f.name]);
      } catch (err) { return fail(err); }
      upload(items);
    };

    // pasted screenshots are all called "image.png": give them a unique name
    pasteTo = list => {
      if (!src.writable()) return;
      const d = new Date(), z = n => String(n).padStart(2, '0');
      const t = `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())} ${z(d.getHours())}.${z(d.getMinutes())}.${z(d.getSeconds())}`;
      // two pastes in the same second would overwrite each other: number the later ones
      const base = cwd() ? cwd() + '/' : '', used = new Set();
      upload(list.map(f => {
        if (f.name && !/^image\.\w+$/i.test(f.name)) return [f, f.name];
        const ext = (f.type.split('/')[1] || 'png').replace(/\W.*/, '');
        let name = `pasted ${t}.${ext}`;
        for (let n = 2; used.has(name) || src.files.has(clean(base + name)); n++) name = `pasted ${t} (${n}).${ext}`;
        used.add(name);
        return [f, name];
      }));
    };

    const el_ = [
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', { class: 'grow' }, 'notes'), addNote), noteForm, notesEl),
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', {}, 'files'), crumbs, tools), filesEl),
    ];
    const out = { els: el_, refresh, foot };
    refresh();
    return out;
  }

  let view = null;
  let cleanup = null;
  addEventListener('hashchange', () => view && view.refresh());
  addEventListener('dragover', e => {
    if (!dropTo || ![...e.dataTransfer.types].includes('Files')) return;
    e.preventDefault();
    document.body.classList.add('drag');
  });
  addEventListener('dragleave', e => { if (!e.relatedTarget) document.body.classList.remove('drag'); });
  addEventListener('drop', e => {
    document.body.classList.remove('drag');
    if (!dropTo) return;
    e.preventDefault();
    dropTo(e);
  });
  // paste an image or copied files anywhere (except into a text field) to upload them
  addEventListener('paste', e => {
    const t = e.target, cd = e.clipboardData;
    if (!pasteTo || !cd) return;
    if (t && (t.tagName === 'TEXTAREA' || t.isContentEditable || (t.tagName === 'INPUT' && !/^(file|button|submit|reset|checkbox|radio|range|color)$/.test(t.type)))) return;
    // some browsers leave .files empty and only expose pasted images through .items
    let list = [...(cd.files || [])];
    if (!list.length) list = [...(cd.items || [])].filter(i => i.kind === 'file').map(i => i.getAsFile()).filter(Boolean);
    if (!list.length) return;
    e.preventDefault();
    pasteTo(list);
  });

  // ---- which shares are live in this browser's tabs -------------------------

  const bc = 'BroadcastChannel' in window ? new BroadcastChannel('p2p') : null;
  let hosting = null, onTabs = null, onKill = null;
  const announce = t => bc && hosting && bc.postMessage({ t, slug: hosting });
  if (bc) bc.onmessage = e => {
    const m = e.data || {};
    if (m.t === 'who') announce('here');
    else if (m.t === 'kill') { if (m.slug === hosting && onKill) onKill(); }
    else if (onTabs && typeof m.slug === 'string') onTabs(m);
  };
  addEventListener('pagehide', () => announce('gone'));

  // ---- landing ------------------------------------------------------------

  // ask the server whether a share exists and is online: { exists, live }
  const peek = slug => new Promise(res => {
    const done = v => { clearTimeout(t); s.close(); res(v); };
    const t = setTimeout(() => done({ exists: true, live: false }), 4000); // unknown: don't block joining
    const s = signal(m => m.t === 'peeked' && done(m), () => s.send({ t: 'peek', slug }));
  });

  // claim a share we own just long enough to release it on the server
  const freeName = sess => new Promise(res => {
    const done = () => { clearTimeout(t); s.close(); res(); };
    const t = setTimeout(done, 4000);
    const s = signal(
      m => m.t === 'hosted' ? s.send({ t: 'end' }) : (m.t === 'ended' || m.t === 'err') && done(),
      () => s.send({ t: 'host', slug: sess.slug, token: sess.token, pin: sess.pin }));
  });

  function landing(msg) {
    document.title = 'p2p';
    const name = el('input', { class: 'name', placeholder: newSlug(), maxlength: '24', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'name' });
    const other = el('input', { class: 'name', placeholder: 'name', maxlength: '24', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'open a share' });
    const err = el('p', { class: 'status' }, msg || '');
    const live = new Set();
    const mine = Object.keys(hosts()).sort(), theirs = joined().filter(s => !mine.includes(s));
    const mineEl = el('ul', { class: 'ls' }), theirsEl = el('ul', { class: 'ls' });
    const draw = () => {
      mineEl.replaceChildren(...mine.map(s => el('li', {},
        el('a', { href: '/' + s }, '/' + s),
        el('span', { class: 'mute meta' }, live.has(s) ? '● live in a tab' : 'offline · open to share'),
        el('span', { class: 'acts' }, el('button', { onclick: e => copy(location.origin + '/' + s, e.target) }, 'copy link'), el('button', { onclick: e => ask(e.target, 'delete it all & free the name?', () => kill(s)) }, 'kill')))));
      theirsEl.replaceChildren(...theirs.map(s => el('li', {},
        el('a', { href: '/' + s }, '/' + s),
        el('span', { class: 'mute meta' }, 'joined'),
        el('span', { class: 'acts' }, el('button', { onclick: () => { store.del('p2p:g:' + s); theirs.splice(theirs.indexOf(s), 1); draw(); } }, 'forget')))));
    };
    // end a share: disconnect everyone, delete its files and notes, free the name.
    // if a tab is hosting it, that tab does the work; otherwise do it from here.
    async function kill(s) {
      const sess = hosts()[s];
      if (live.has(s)) bc.postMessage({ t: 'kill', slug: s });
      else if (sess) await freeName(sess);
      delHost(s);
      await idb(s).clear().catch(() => {});
      mine.splice(mine.indexOf(s), 1);
      draw();
      err.textContent = `/${s} killed`;
    }
    draw();
    onTabs = m => { m.t === 'gone' ? live.delete(m.slug) : live.add(m.slug); draw(); };
    if (bc) bc.postMessage({ t: 'who' });
    app.replaceChildren(...[
      el('h1', {}, 'p2p'),
      el('p', { class: 'mute' }, 'share files, folders and notes straight from your browser to someone else\'s. peer to peer and encrypted. no accounts, nothing stored on a server. a share stays live while your tab is open.'),
      el('section', { class: 'panel' }, el('h2', {}, 'start sharing'),
        el('form', { class: 'row', onsubmit: e => {
          e.preventDefault();
          const slug = (name.value.trim().toLowerCase() || name.placeholder);
          if (!SLUG.test(slug)) return (err.textContent = '3–24 characters: a–z, 0–9 and dashes');
          if (hosts()[slug]) return nav('/' + slug);
          host({ slug, token: newToken(), pin: newPin(), mode: 'rw', fresh: true });
        } }, el('span', { class: 'mute' }, location.host + '/'), name, el('button', { type: 'submit' }, 'create'))),
      mine.length > 0 && el('section', { class: 'panel' }, el('h2', {}, 'your shares'), mineEl,
        el('p', { class: 'mute' }, 'each share is live while its tab is open. open several tabs to share several at once.')),
      theirs.length > 0 && el('section', { class: 'panel' }, el('h2', {}, 'joined'), theirsEl),
      el('section', { class: 'panel' }, el('h2', {}, 'open a share'),
        el('form', { class: 'row', onsubmit: e => {
          e.preventDefault();
          const slug = other.value.trim().toLowerCase();
          if (SLUG.test(slug)) nav('/' + slug);
        } }, el('span', { class: 'mute' }, location.host + '/'), other, el('button', { type: 'submit' }, 'open'))),
      err,
    ].filter(Boolean));
    if (!coarse()) name.focus(); // on phones that would pop the keyboard over the page
  }

  // ---- host ---------------------------------------------------------------

  async function host(sess) {
    document.title = sess.slug + ' · p2p';
    if (location.pathname !== '/' + sess.slug) history.replaceState(null, '', '/' + sess.slug);
    current = location.pathname;
    const files = new Map(), notes = new Map(), peers = new Map(), db = idb(sess.slug);
    try {
      for (const f of await db.all('files')) files.set(f.path, { path: f.path, size: f.size, mtime: f.mtime, hash: HASH.test(f.hash) ? f.hash : null });
      for (const n of await db.all('notes')) notes.set(n.id, { id: n.id, title: n.title, text: n.text, t: n.t });
    } catch {}
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    const kp = await keypair().catch(() => null);
    if (location.pathname !== '/' + sess.slug) return; // navigated away while loading
    const unhold = hold();

    const persist = () => setHost(sess);
    // v 2: gets take an offset and puts can resume, so guests pick up after a reconnect
    const ls = () => ({ t: 'ls', v: 2, mode: sess.mode, files: [...files.values()], notes: [...notes.values()] });
    let lsTimer;
    const changed = () => {
      clearTimeout(lsTimer);
      lsTimer = setTimeout(() => { const m = ls(); for (const p of peers.values()) if (p.open) tx(p.dc, m); }, 80);
      v.refresh();
    };
    const src = {
      files, notes,
      writable: () => true,
      get: async path => (await db.get('files', path)).blob,
      // hash: when the uploader already worked it out here; guest uploads get hashed by fill()
      put: async (blob, path, mtime, prog, hash) => {
        const f = { path, size: blob.size, mtime: Number.isSafeInteger(mtime) ? mtime : Date.now(), hash: HASH.test(hash) ? hash : null };
        await db.put('files', { ...f, blob });
        files.set(path, f);
        changed();
        if (!f.hash) fill();
      },
      rm: async (path, dir) => {
        if (dir) {
          await db.delPrefix('files', path + '/');
          for (const k of files.keys()) if (k.startsWith(path + '/')) files.delete(k);
        } else {
          await db.del('files', path);
          files.delete(path);
        }
        changed();
      },
      // new note, or an edit when id names an existing one
      note: async (title, text, id) => {
        const n = mkNote(title, text, notes.has(id) ? id : null);
        if (!n || (!notes.has(n.id) && notes.size >= NOTES_MAX)) return;
        await db.put('notes', n);
        notes.set(n.id, n);
        changed();
      },
      unnote: async id => {
        await db.del('notes', id);
        notes.delete(id);
        changed();
      },
    };

    // every file gets a sha-256 so uploads of the same content can be flagged.
    // done in the background for guest uploads and files stored before hashes existed,
    // and held off while guests are transferring: hashing a big file in js would halve their speed
    let filling = false, again = false, serving = 0;
    const hot = () => serving > 0 || [...peers.values()].some(p => p.ups.size > 0);
    const cool = async () => { while (hot()) await new Promise(r => setTimeout(r, 1000)); };
    async function fill() {
      if (filling) return void (again = true);
      filling = true;
      do {
        again = false;
        for (const f of [...files.values()].filter(f => !f.hash)) {
          try {
            await cool();
            const rec = await db.get('files', f.path);
            if (!rec || files.get(f.path) !== f) continue;
            const hash = await sha256(rec.blob, cool);
            if (files.get(f.path) !== f) continue; // replaced or deleted meanwhile
            await db.patch('files', f.path, r => !r.hash && r.size === f.size && r.mtime === f.mtime && { ...r, hash });
            f.hash = hash;
          } catch {}
        }
      } while (again);
      filling = false;
      changed();
    }

    const state = el('span', { class: 'mute' }, 'connecting…');
    const status = el('p', { class: 'status' });
    const say = t => { status.textContent = t; };
    const link = location.origin + '/' + sess.slug;
    const pinEl = el('span', { class: 'pin' });
    let pinShown = false;
    const pinBtn = el('button', { onclick: () => { pinShown = !pinShown; showPin(); } });
    const showPin = () => {
      pinEl.textContent = pinShown ? sess.pin : '•••••••';
      pinBtn.textContent = pinShown ? 'hide' : 'show';
    };
    showPin();
    const qrBox = el('div', { hidden: true });
    const qrBtn = el('button', { onclick: () => {
      if (!qrBox.firstChild) qrBox.append(qrSvg(link), el('p', { class: 'mute' }, 'scan with a phone camera to open the link. they still need the pin.'));
      qrBox.hidden = !qrBox.hidden;
      qrBtn.textContent = qrBox.hidden ? 'qr' : 'hide qr';
    } }, 'qr');
    const modeHint = el('span', { class: 'mute' });
    const modeBtn = el('button', { onclick: () => {
      sess.mode = sess.mode === 'rw' ? 'ro' : 'rw';
      persist();
      showMode();
      changed();
    } });
    const showMode = () => {
      modeBtn.textContent = sess.mode === 'rw' ? 'two-way' : 'one-way';
      modeHint.textContent = sess.mode === 'rw' ? 'others can add, edit, download and delete' : 'others can only download and copy';
    };
    showMode();
    const showPeers = () => {
      const open = [...peers.values()].filter(p => p.open), r = open.filter(p => p.dc.relay).length;
      state.textContent = live ? `live · ${open.length} connected${r ? ` (${r} relayed)` : ''}` : 'reconnecting…';
    };

    const v = panel(src, say, status);
    app.replaceChildren(
      el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + sess.slug), state),
      el('section', { class: 'panel' }, el('h2', {}, 'access'),
        el('div', { class: 'kv' },
          el('span', { class: 'mute' }, 'link'), el('span', { class: 'row' }, el('span', { class: 'url' }, link.replace(/^https?:\/\//, '')), el('button', { onclick: e => copy(link, e.target) }, 'copy'), qrBtn),
          el('span', { class: 'mute' }, 'pin'), el('span', { class: 'row' }, el('span', { class: 'grow' }, pinEl), pinBtn, el('button', { onclick: e => copy(sess.pin, e.target) }, 'copy'), el('button', { onclick: regen }, 'new pin')),
          el('span', { class: 'mute' }, 'mode'), el('span', { class: 'row' }, modeBtn, modeHint),
        ),
        qrBox,
        el('p', { class: 'mute' }, 'send the link and pin to someone. a new pin disconnects everyone. sharing stops when you close this tab and resumes when you reopen it.' +
          (coarse() ? ' on a phone, keep this page open in front: browsers pause pages in the background.' : '')),
      ),
      ...v.els,
      v.foot,
      el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: e => ask(e.target, 'delete it all & free the name?', end) }, 'stop sharing & delete everything')),
    );
    view = v;
    fill();

    let live = false;
    const sig = signal(onSignal, () => sig.send({ t: 'host', slug: sess.slug, token: sess.token, pin: sess.pin }));
    cleanup = () => {
      announce('gone');
      hosting = null;
      sig.close();
      for (const p of peers.values()) p.pc.close();
      peers.clear();
      partial.clear();
      unhold();
    };
    sig.onbin = buf => {
      if (buf.byteLength <= 12) return;
      const p = peers.get(dec.decode(new Uint8Array(buf, 0, 12)));
      if (p && p.dc && p.dc.relay) p.dc.receive(buf.slice(12));
    };

    function onSignal(m) {
      switch (m.t) {
        case 'hosted':
          live = true;
          hosting = sess.slug;
          announce('here');
          if (sess.fresh) { delete sess.fresh; persist(); }
          return showPeers();
        case 'down':
          live = false;
          announce('gone');
          hosting = null;
          for (const p of [...peers.values()]) if (p.dc && p.dc.relay) drop(p.id);
          return showPeers();
        case 'sig': return onPeerSig(m.from, m.data);
        case 'left': {
          const p = peers.get(m.id);
          if (p && (!p.open || p.dc.relay)) drop(p.id);
          return;
        }
        case 'pinned': return say('new pin set — everyone was disconnected');
        case 'err':
          if (m.e === 'replaced') { cleanup(); state.textContent = 'open in another tab'; return; }
          if (m.e === 'taken' || m.e === 'limit' || m.e === 'bad') {
            cleanup();
            if (sess.fresh || m.e === 'taken') {
              if (!sess.fresh) { delHost(sess.slug); db.clear(); }
              return nav('/', m.e === 'taken' ? `"${sess.slug}" is taken, try another name` : m.e === 'limit' ? 'too many new shares from your network, try later' : 'invalid name');
            }
            state.textContent = 'offline';
          }
      }
    }

    function onPeerSig(id, data) {
      if (typeof id !== 'string' || !data) return;
      let p = peers.get(id);
      if (!p) {
        if (!data.d || data.d.type !== 'offer' || peers.size >= 32) return;
        p = addPeer(id);
      }
      p.q = p.q.then(async () => {
        if (data.relay) return toRelay(p);
        if (p.dc && p.dc.relay) return;
        if (data.d) {
          if (kp && typeof data.k === 'string') p.key = shared(kp, data.k).catch(() => null);
          await p.pc.setRemoteDescription(data.d);
          await p.pc.setLocalDescription(await p.pc.createAnswer());
          sig.send({ t: 'sig', to: id, data: { d: p.pc.localDescription, k: kp && kp.pub } });
        } else if (data.c) await p.pc.addIceCandidate(data.c);
      }).catch(() => {});
    }

    function addPeer(id) {
      const pc = new RTCPeerConnection({ iceServers: sig.ice });
      const p = { id, pc, dc: null, open: false, q: Promise.resolve(), ups: new Map(), stop: new Set(), rx: {} };
      pc.onicecandidate = e => e.candidate && sig.send({ t: 'sig', to: id, data: { c: e.candidate } });
      pc.onconnectionstatechange = () => p.pc === pc && (pc.connectionState === 'failed' || pc.connectionState === 'closed') && drop(id);
      pc.ondatachannel = e => {
        if (p.dc) return;
        const dc = p.dc = e.channel;
        dc.binaryType = 'arraybuffer';
        dc.bufferedAmountLowThreshold = LOW;
        dc.onopen = () => { p.open = true; tx(dc, ls()); showPeers(); };
        dc.onclose = () => p.dc === dc && drop(id);
        dc.onmessage = ev => onPeerMsg(p, ev.data).catch(() => {});
        if (dc.readyState === 'open') dc.onopen();
      };
      peers.set(id, p);
      return p;
    }

    // the guest couldn't connect directly: switch this peer to the encrypted relay
    async function toRelay(p) {
      const key = !p.open && p.key && await p.key;
      if (!key || peers.get(p.id) !== p) return;
      const old = p.pc, idb = enc.encode(p.id);
      old.onconnectionstatechange = null;
      p.dc = null;
      old.close();
      let ws = null;
      p.pc = { close: () => { if (ws) ws.close(); } };
      ws = await pipe(p.id);
      if (peers.get(p.id) !== p) { if (ws) ws.close(); return; }
      // own socket for this guest; if that fails, share the main one
      const ch = ws ? new Relay(key, 1, msg => ws.readyState === 1 && ws.send(msg), () => ws.bufferedAmount) : new Relay(key, 1, msg => {
        const f = new Uint8Array(12 + msg.length);
        f.set(idb);
        f.set(msg, 12);
        sig.bin(f);
      }, sig.buffered);
      if (ws) {
        ws.onmessage = e => typeof e.data !== 'string' && ch.receive(e.data);
        ws.onclose = () => ch.close();
      }
      p.pc = { ...RELAY_PC, close: () => { ch.close(); if (ws) ws.close(); } };
      p.dc = ch;
      ch.onmessage = ev => onPeerMsg(p, ev.data).catch(() => {});
      ch.onclose = () => drop(p.id);
      p.open = true;
      tx(ch, ls());
      showPeers();
    }

    // a separate socket per relayed guest, so one slow guest can't hold up
    // signaling or the others. resolves to null if it can't be set up.
    function pipe(id) {
      return new Promise(res => {
        const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
        const end = ok => {
          clearTimeout(t);
          ws.onmessage = ws.onclose = null;
          if (!ok) ws.close();
          res(ok ? ws : null);
        };
        const t = setTimeout(() => end(false), 5000);
        ws.binaryType = 'arraybuffer';
        ws.onmessage = e => {
          let m;
          try { m = JSON.parse(e.data); } catch { return end(false); }
          if (m && m.t === 'hi') ws.send(JSON.stringify({ t: 'pipe', slug: sess.slug, token: sess.token, id }));
          else end(m && m.t === 'piped');
        };
        ws.onclose = () => end(false);
      });
    }

    function drop(id) {
      const p = peers.get(id);
      if (!p) return;
      peers.delete(id);
      for (const u of p.ups.values()) park(u);
      p.ups.clear();
      try { p.pc.close(); } catch {}
      showPeers();
      serve();
    }

    // guest uploads by the guest's upload id. one whose connection drops is kept a
    // while, so the guest can carry on from where it got to instead of starting over
    const partial = new Map(), stored = new Set();
    const serve = () => busy('serve', hot());
    function forget(u) {
      clearTimeout(u.ttl);
      if (u.peer && u.peer.ups.get(u.req) === u) u.peer.ups.delete(u.req);
      if (partial.get(u.id) === u) partial.delete(u.id);
      serve();
    }
    function park(u) {
      u.peer = null;
      if (partial.get(u.id) !== u) return;
      clearTimeout(u.ttl);
      u.ttl = setTimeout(() => !u.peer && forget(u), 10 * 6e4);
    }
    function keep(u) {
      if (partial.size >= 16) {
        let k = partial.keys().next().value; // full: drop the oldest, preferably one nobody is sending
        for (const [id, x] of partial) if (!x.peer) { k = id; break; }
        partial.delete(k);
      }
      partial.set(u.id, u);
    }
    const saved = (p, req, ok) => tx(p.dc, ok ? { t: 'ok', req } : { t: 'err', req, e: 'host is out of storage' });

    // everything a guest sends is untrusted
    async function onPeerMsg(p, data) {
      if (typeof data !== 'string') {
        if (data.byteLength < 4) return;
        const req = new DataView(data).getUint32(0), u = p.ups.get(req);
        if (!u) return;
        if (u.got + data.byteLength - 4 > u.size) return forget(u);
        u.got += data.byteLength - 4;
        collect(u, new Uint8Array(data, 4));
        return;
      }
      const m = rx(p.rx, data);
      if (!m) return;
      const req = m.req >>> 0, rw = sess.mode === 'rw';
      const fail = e => tx(p.dc, { t: 'err', req, e });
      switch (m.t) {
        case 'get': {
          const path = clean(m.path);
          const f = path && files.has(path) && await db.get('files', path);
          if (!f) return fail('not found');
          // resuming from an offset: only while it is still the same file
          const off = Number.isSafeInteger(m.off) && m.off > 0 ? m.off : 0;
          if (off && (off > f.size || m.size !== f.size || m.mtime !== (+f.mtime || 0))) return fail('the file changed — get it again');
          serving++;
          serve();
          try {
            if (await stream(p.pc, p.dc, req, f.blob, null, () => p.stop.has(req), off)) tx(p.dc, { t: 'end', req });
          } catch {
            fail('could not read the file'); // (a no-op if it was the connection that went)
          } finally {
            p.stop.delete(req);
            serving--;
            serve();
          }
          return;
        }
        case 'cancel': {
          const u = p.ups.get(req);
          if (u) return forget(u);
          if (p.stop.size < 64) p.stop.add(req);
          return;
        }
        case 'put': {
          if (!rw) return fail('read-only share');
          const path = clean(m.path), id = typeof m.id === 'string' && /^[a-z0-9]{12}$/.test(m.id) ? m.id : null;
          // the guest lost its connection mid-upload and is back: say how far it got
          if (id && m.resume) {
            const old = partial.get(id);
            if (stored.has(id)) return tx(p.dc, { t: 'ok', req });
            if (old && old.saving) return void old.saving.then(ok => saved(p, req, ok));
            if (old && old.path === path && old.size === m.size && p.ups.size < 8) {
              if (old.peer) old.peer.ups.delete(old.req); // late frames from the old connection are ignored
              clearTimeout(old.ttl);
              old.peer = p;
              old.req = req;
              p.ups.set(req, old);
              serve();
              return tx(p.dc, { t: 'at', req, off: old.got });
            }
          }
          if (!path || !Number.isSafeInteger(m.size) || m.size < 0 || p.ups.size >= 8) return fail('rejected');
          const u = { id: id && !partial.has(id) ? id : null, path, size: m.size, mtime: m.mtime, parts: [], got: 0, peer: p, req };
          p.ups.set(req, u); // before any await: chunks follow at once
          if (u.id) keep(u);
          serve();
          if (m.resume) tx(p.dc, { t: 'at', req, off: 0 }); // nothing kept: start over
          const q = navigator.storage && navigator.storage.estimate && await navigator.storage.estimate().catch(() => null);
          if (q && q.quota - q.usage < m.size) { forget(u); return fail('host is out of storage'); }
          return;
        }
        case 'end': {
          const u = p.ups.get(req);
          if (!u) return;
          if (u.got !== u.size) { forget(u); return fail('upload incomplete'); }
          p.ups.delete(req);
          serve();
          // a guest that reconnects while this is being stored waits for the same result
          u.saving = src.put(new Blob(u.parts), u.path, u.mtime).then(() => true, () => false);
          const ok = await u.saving;
          forget(u);
          if (ok && u.id) {
            stored.add(u.id);
            if (stored.size > 64) stored.delete(stored.values().next().value);
          }
          return saved(p, req, ok);
        }
        case 'rm': {
          if (!rw) return fail('read-only share');
          const path = clean(m.path);
          if (path) await src.rm(path, m.dir === true);
          return;
        }
        case 'note': return rw ? src.note(m.title, m.text, typeof m.id === 'string' ? m.id : null) : fail('read-only share');
        case 'unnote': return !rw ? fail('read-only share') : notes.has(m.id) && src.unnote(m.id);
      }
    }

    function kickAll(why) {
      for (const p of peers.values()) {
        tx(p.dc, { t: 'bye', why });
        setTimeout(() => drop(p.id), 300);
      }
    }
    function regen() {
      sess.pin = newPin();
      partial.clear(); // whoever was uploading needs the new pin first anyway
      persist();
      showPin();
      sig.send({ t: 'pin', pin: sess.pin });
      kickAll('revoked');
    }
    onKill = end;
    async function end() {
      kickAll('ended');
      sig.send({ t: 'end' });
      delHost(sess.slug);
      await db.clear().catch(() => {});
      setTimeout(() => nav('/'), 400);
    }
  }

  // ---- guest --------------------------------------------------------------

  function guest(slug) {
    document.title = slug + ' · p2p';
    const key = 'p2p:g:' + slug;
    const files = new Map(), notes = new Map(), pend = new Map();
    // transfers outlive a dropped connection and carry on from where they got to on the
    // next one; notes and deletes made meanwhile wait in the outbox
    const xfers = new Set(), outbox = [];
    let pin = store.get(key), mode = 'ro', sig = null, pc = null, dc = null, rxs = {}, n = 0, timer = null, v = null;
    let ready = false, retrying = false, hostV = 0, relayed = false;
    const unhold = hold();

    const state = el('span', { class: 'mute' });
    const status = el('p', { class: 'status' });
    const say = t => { status.textContent = t; };
    const head = el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + slug), state);

    // keep: a reconnect follows, so transfers and the outbox wait for it
    function teardown(keep) {
      clearTimeout(timer);
      ready = retrying = false;
      const s = sig, p = pc;
      sig = pc = dc = null;
      if (s) s.close();
      if (p) p.close();
      pend.clear();
      rxs = {};
      if (keep) return;
      for (const x of [...xfers]) finish(x, new Error('disconnected'));
      outbox.length = 0;
    }
    const quit = () => { teardown(); unhold(); wake.delete(onWake); };
    cleanup = quit;
    // back in front or online: retry now instead of when the (slowed down) timer fires
    function onWake() {
      const p = pc;
      if (retrying) connect();
      else if (p && p.lost && /^(disconnected|failed)$/.test(p.connectionState || p.iceConnectionState)) p.lost();
    }
    wake.add(onWake);

    // nobody owns this name: say so instead of asking for a pin
    function missing() {
      app.replaceChildren(head,
        el('section', { class: 'panel' }, el('h2', {}, 'not found'),
          el('p', {}, `nobody is sharing /${slug}.`),
          el('p', { class: 'mute' }, 'check the link, or take the name for yourself.'),
          el('div', { class: 'row' },
            el('button', { onclick: () => { quit(); host({ slug, token: newToken(), pin: newPin(), mode: 'rw', fresh: true }); } }, `create /${slug}`),
            el('a', { href: '/' }, 'home'))));
    }

    async function start() {
      if (pin) return connect();
      app.replaceChildren(head, status);
      const s = await peek(slug);
      if (cleanup !== quit) return; // navigated away
      if (!s.exists) return missing();
      form(s.live ? '' : `the owner of /${slug} is offline right now. you can still enter the pin; you'll connect when they're back.`);
    }

    function form(msg) {
      teardown();
      view = v = null;
      dropTo = pasteTo = null;
      state.textContent = '';
      const input = el('input', { class: 'big', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', placeholder: '•••••••', 'aria-label': 'pin' });
      const submit = () => {
        const val = input.value.replace(/\D/g, '');
        if (val.length !== 7) return say('the pin has 7 digits');
        pin = val;
        connect();
      };
      input.addEventListener('input', () => { input.value = input.value.replace(/\D/g, '').slice(0, 7); if (input.value.length === 7) submit(); });
      app.replaceChildren(head,
        el('section', { class: 'panel' }, el('h2', {}, 'enter pin'),
          el('form', { class: 'row', onsubmit: e => { e.preventDefault(); submit(); } }, input, el('button', { type: 'submit' }, 'open')),
          el('p', { class: 'mute' }, 'ask the person sharing /' + slug + ' for their 7-digit pin.')),
        status);
      say(msg || '');
      input.focus();
    }

    function wait(msg, ms) {
      teardown(true);
      state.textContent = 'waiting';
      if (!v) app.replaceChildren(head, status);
      say(msg + (xfers.size ? ' · transfers paused' : ''));
      retrying = true;
      timer = setTimeout(connect, ms);
    }

    function connect() {
      teardown(true);
      state.textContent = v ? 'reconnecting…' : 'connecting…';
      if (!v) app.replaceChildren(head, status);
      if (!xfers.size) say('');
      const s = sig = signal(m => sig === s && onSignal(m), () => s.send({ t: 'join', slug, pin }));
      timer = setTimeout(() => wait('could not reach the other browser directly — retrying…', 3000), 25000);
    }

    function onSignal(m) {
      switch (m.t) {
        case 'joined': return startRtc();
        case 'sig': {
          const p = pc, d = m.data || {};
          if (!p || !p.q) return;
          if (p.kp && typeof d.k === 'string') p.key = shared(p.kp, d.k).catch(() => null);
          p.q = p.q.then(() => d.d ? p.setRemoteDescription(d.d) : d.c ? p.addIceCandidate(d.c) : 0).catch(() => {});
          return;
        }
        case 'down': if (dc && dc.relay) wait('connection lost — reconnecting…', 1000); return;
        case 'revoked': store.del(key); return form('access was revoked — ask for the new pin');
        case 'ended': store.del(key); return form('this share has ended');
        case 'err':
          switch (m.e) {
            case 'pin': store.del(key); return form('wrong pin');
            case 'limit': return form('too many attempts — try again in 15 minutes');
            case 'bad': store.del(key); return form('enter the 7-digit pin');
            case 'full': return wait('too many people connecting — retrying…', 10000);
            default: return wait(`no one is sharing /${slug} right now — waiting…`, 5000);
          }
      }
    }

    async function startRtc() {
      if (pc) pc.close();
      const s = sig, kp = await keypair().catch(() => null);
      if (sig !== s || !s) return;
      const p = pc = new RTCPeerConnection({ iceServers: s.ice });
      p.q = Promise.resolve();
      p.kp = kp;
      const ch = dc = p.createDataChannel('fs', { ordered: true });
      ch.binaryType = 'arraybuffer';
      ch.bufferedAmountLowThreshold = LOW;
      p.onicecandidate = e => e.candidate && sig && sig.send({ t: 'sig', data: { c: e.candidate } });
      let opened = false;
      const lost = p.lost = () => pc === p && (opened ? wait('connection lost — reconnecting…', 1000) : toRelay(p));
      // after 6s use the relay (2.5s if the last connection needed it too), unless a direct
      // (or turn) path was already found and is just finishing its handshake: then give it up to 15s in total
      const late = () => pc === p && !opened && toRelay(p);
      setTimeout(() => /^(connected|completed)$/.test(p.iceConnectionState) ? setTimeout(late, 9000) : late(), relayed ? 2500 : 6000);
      // a path that stays down for 6s rarely comes back by itself: reconnect, transfers resume
      p.onconnectionstatechange = p.oniceconnectionstatechange = () => {
        const st = p.connectionState || p.iceConnectionState;
        clearTimeout(p.down);
        if (st === 'failed') lost();
        else if (st === 'disconnected' && opened) p.down = setTimeout(() => /^(disconnected|failed)$/.test(p.connectionState || p.iceConnectionState) && lost(), 6000);
      };
      ch.onopen = () => {
        opened = true;
        relayed = false;
        clearTimeout(timer);
        store.set(key, pin);
        if (sig) { sig.close(); sig = null; } // direct from here on
        show();
      };
      ch.onclose = lost;
      ch.onmessage = e => onMsg(e.data);
      await p.setLocalDescription(await p.createOffer());
      if (sig) sig.send({ t: 'sig', data: { d: p.localDescription, k: kp && kp.pub } });
    }

    // no direct path (strict nat, no hairpin, privacy settings): use the encrypted relay
    async function toRelay(p) {
      const k = p.key && await p.key;
      if (pc !== p || !sig) return;
      if (!k) return wait('could not open a direct connection between your browsers — retrying…', 5000);
      // hold frames until the host's first one arrives: by then its relay
      // socket is set up, so nothing can overtake on the way
      let held = [];
      const s = sig, ch = new Relay(k, 0, msg => held ? held.push(msg) : s.bin(msg), s.buffered);
      pc = { ...RELAY_PC, close: () => ch.close() };
      dc = ch;
      relayed = true;
      p.close();
      ch.onmessage = e => onMsg(e.data);
      ch.onclose = () => dc === ch && wait('connection lost — reconnecting…', 1000);
      s.onbin = buf => {
        if (held) { for (const m of held) s.bin(m); held = null; }
        ch.receive(buf);
      };
      s.send({ t: 'sig', data: { relay: 1 } });
      clearTimeout(timer);
      store.set(key, pin);
      show();
    }

    function onMsg(data) {
      if (typeof data !== 'string') {
        if (data.byteLength < 4) return;
        const x = pend.get(new DataView(data).getUint32(0));
        if (!x || x.up) return;
        collect(x, new Uint8Array(data, 4));
        x.got += data.byteLength - 4;
        if (x.prog) x.prog(x.got);
        return;
      }
      const m = rx(rxs, data);
      if (!m) return;
      const x = pend.get(m.req);
      switch (m.t) {
        case 'ls':
          mode = m.mode === 'rw' ? 'rw' : 'ro';
          files.clear();
          for (const f of arr(m.files)) {
            const path = f && clean(f.path);
            if (path && Number.isSafeInteger(f.size) && f.size >= 0) files.set(path, { path, size: f.size, mtime: +f.mtime || 0, hash: HASH.test(f.hash) ? f.hash : null });
          }
          notes.clear();
          for (const x of arr(m.notes)) {
            if (x && typeof x.id === 'string' && typeof x.title === 'string' && typeof x.text === 'string' && x.text.length <= NOTE_MAX) notes.set(x.id, { id: x.id, title: x.title.slice(0, TITLE_MAX), text: x.text, t: +x.t || 0 });
          }
          state.textContent = 'connected · ' + (mode === 'rw' ? 'two-way' : 'one-way') + (dc && dc.relay ? ' · relayed' : '');
          if (!ready) {
            // first listing on this connection: carry on with whatever was going before
            ready = true;
            hostV = +m.v || 0;
            for (const t of xfers) begin(t);
            for (const o of outbox.splice(0)) tx(dc, o);
          }
          return v && v.refresh();
        case 'at': if (x && x.up && Number.isSafeInteger(m.off) && m.off >= 0 && m.off <= x.blob.size) pump(x, m.off); return;
        case 'end': if (x && !x.up) finish(x, null, new Blob(x.parts)); return;
        case 'ok': if (x && x.up) finish(x); return;
        case 'err':
          if (x) finish(x, new Error(String(m.e).slice(0, 100))); else say('error: ' + String(m.e).slice(0, 100));
          return;
        case 'bye':
          store.del(key);
          return form(m.why === 'ended' ? 'this share has ended' : 'access was revoked — ask for the new pin');
      }
    }

    function finish(x, err, val) {
      if (!xfers.delete(x)) return;
      if (pend.get(x.req) === x) pend.delete(x.req);
      err ? x.rej(err) : x.res(val);
    }
    function transfer(x, signal) {
      return new Promise((res, rej) => {
        if (signal && signal.aborted) return rej(signal.reason);
        x.res = res;
        x.rej = rej;
        xfers.add(x);
        if (signal) signal.addEventListener('abort', () => {
          if (xfers.has(x) && pend.get(x.req) === x) tx(dc, { t: 'cancel', req: x.req });
          finish(x, signal.reason);
        }, { once: true });
        begin(x);
      });
    }
    // (re)start a transfer on the current connection, from where it got to
    function begin(x) {
      if (!ready || !dc || dc.readyState !== 'open') return; // the next connection starts it
      const req = x.req = ++n;
      pend.set(req, x);
      if (!x.up) {
        if (hostV < 2) { x.parts = []; x.got = x.mem = 0; } // this host can't resume: start over
        return tx(dc, { t: 'get', req, path: x.path, off: x.got, size: x.size, mtime: x.mtime });
      }
      // first try: the bytes follow the request at once. after a reconnect: wait for
      // the host to say how much it already has ('at')
      const resume = x.sent && hostV >= 2;
      x.sent = true;
      tx(dc, { t: 'put', req, path: x.path, size: x.blob.size, mtime: x.mtime, id: x.id, resume });
      if (!resume) pump(x, 0);
    }
    function pump(x, off) {
      const c = dc, req = x.req;
      stream(pc, c, req, x.blob, x.prog, () => x.req !== req || !xfers.has(x), off).then(all => all && tx(c, { t: 'end', req }), e => {
        if (c.readyState !== 'open' || x.req !== req) return; // connection dropped: begin() picks it up again
        tx(c, { t: 'cancel', req }); // the file itself can't be read (moved, changed)
        finish(x, e);
      });
    }
    // notes and deletes made while reconnecting go out once connected again
    function post(m) {
      if (ready && dc && dc.readyState === 'open') return tx(dc, m);
      if (outbox.length < 100) outbox.push(m);
      say('not connected — will send when reconnected');
    }

    const src = {
      files, notes,
      writable: () => mode === 'rw',
      get: (path, prog, signal) => {
        const f = files.get(path) || {};
        return transfer({ path, size: f.size, mtime: f.mtime, parts: [], got: 0, prog }, signal);
      },
      put: (blob, path, mtime, prog, hash, signal) => transfer({ up: true, id: newId(), blob, path, mtime, prog }, signal),
      rm: async (path, dir) => post({ t: 'rm', path, dir: !!dir }),
      note: async (title, text, id) => post({ t: 'note', title, text, id }),
      unnote: async id => post({ t: 'unnote', id }),
    };

    function show() {
      if (v) return v.refresh();
      v = view = panel(src, say, status);
      app.replaceChildren(head, ...v.els, v.foot,
        el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: () => { store.del(key); form('disconnected'); } }, 'disconnect')));
      say('');
    }

    start();
  }

  // ---- routing ------------------------------------------------------------

  let current = null;
  function route(msg) {
    if (cleanup) cleanup();
    cleanup = view = dropTo = pasteTo = onTabs = onKill = null;
    busy.clear();
    current = location.pathname;
    const slug = location.pathname.slice(1);
    const hs = hosts();
    if (!slug) return landing(msg);
    if (!SLUG.test(slug)) return nav('/');
    if (hs[slug]) return host(hs[slug]);
    guest(slug);
  }
  function nav(path, msg) {
    history.pushState(null, '', path);
    route(msg);
  }
  addEventListener('popstate', () => location.pathname !== current && route());
  route();
})();

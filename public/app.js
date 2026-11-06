'use strict';
// p2p: files, folders and notes go browser to browser over an encrypted webrtc
// data channel. the server only checks the pin and relays the handshake.
(() => {
  const SLUG = /^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$/;
  const ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
  // send buffer: refill below LOW, pause above HIGH (chrome closes a channel past 16 MB).
  // MSG: largest data channel message we send, when the other side accepts it
  const LOW = 2 << 20, HIGH = 8 << 20, PART = 8000, MSG = 256 << 10;
  // downloads ask for WIN bytes at a time, INFLIGHT windows ahead (see the wire format)
  const WIN = 1 << 20, INFLIGHT = 4;
  const TITLE_MAX = 100, NOTE_MAX = 100000, NOTES_MAX = 200, NOTES_PER = 50, ITEMS_MAX = 10000, TOMB_MAX = 2000, MEMBERS_MAX = 1000;
  // an owner's things wait this long after they go offline (tests may shorten it)
  const grace = () => +window.__p2pGrace || 10 * 6e4;
  // links between guests: at most LINKS_MAX each, closed after LINK_IDLE unused; a link
  // not open after DIRECT_WAIT goes through the host instead. SERVES_MAX files served at once
  const LINKS_MAX = 8, LINK_IDLE = 2 * 6e4, DIRECT_WAIT = 6000, SERVES_MAX = 4;
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
  const newToken = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
  const b64u = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // ---- who you are ----------------------------------------------------------
  // every participant has a display name. left empty, a random readable one is
  // used: made once and kept, so it doesn't change between visits
  const ADJ = 'amber bold brave brisk calm clever cosy crisp curly dapper eager fair fancy fond fresh gentle glad golden grand happy hazy jolly keen kind lively lucky merry mild misty neat nimble noble odd plain polite proud quick quiet rapid rosy rustic shy silent silly sleek smart snowy soft spry steady sunny swift tidy tiny upbeat vivid warm wavy wild wise witty young zany zesty'.split(' ');
  const NOUN = 'badger bear beaver bison crane crow deer dingo dove eagle egret falcon ferret finch fox gecko goat goose hare hawk heron ibis koala lark lemur lion llama lynx magpie marten mink mole moose newt otter owl panda parrot pigeon puffin quail rabbit raven robin salmon seal shrew skunk sloth snail sparrow stoat swan tapir tiger toad trout turtle viper walrus weasel whale wolf wren yak zebra'.split(' ');
  const randName = () => ADJ[rnd(ADJ.length)] + '-' + NOUN[rnd(NOUN.length)];
  // one normal form for a name, wherever it comes from: the display form, and its
  // lowercase as the key names are compared by (so "Alice", "alice " and "ali\u200bce" clash)
  function normName(s) {
    if (typeof s !== 'string' || s.length > 256) return null;
    const d = s.normalize('NFKC').replace(/[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, '').replace(/\s+/gu, ' ').trim(), n = [...d].length;
    return n >= 1 && n <= 24 ? d : null;
  }
  const nameKey = d => d.toLowerCase();
  // p2p:me = { name, rand, secret }. the secret never leaves this browser as is:
  // each share only ever sees a hash of it mixed with the share's name (shareSecret)
  function me() {
    const raw = store.get('p2p:me'), m = raw && typeof raw === 'object' ? raw : {};
    const out = { name: normName(m.name) || '', rand: normName(m.rand) || randName(), secret: /^[\w-]{43}$/.test(m.secret) ? m.secret : newToken() };
    if (out.name !== m.name || out.rand !== m.rand || out.secret !== m.secret) store.set('p2p:me', out);
    return out;
  }
  const myName = () => { const m = me(); return m.name || m.rand; };
  // sha-256 of a short string, as base64url (the js one on plain http, where subtle is missing)
  const digest = async str => b64u(Uint8Array.from((await sha256(new Blob([str]))).match(/../g), h => parseInt(h, 16)));
  // what proves who you are to one share's host. per share, so a host can't use it
  // to pass as you in someone else's share
  const shareSecret = slug => digest(me().secret + ':' + slug);
  // a member's public id: the first 12 characters of the hash of its share secret
  const memberOf = async sec => { const h = await digest(sec); return { id: h.slice(0, 12), secretHash: h }; };
  const MEMBER = /^[\w-]{12}$/;
  const RESERVE = 30 * 864e5; // a name stays reserved this long after its member was last seen (as the server keeps share names)

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
    // a lone surrogate (only ever from a hand-made message) can't be url-encoded
    p = p.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd');
    const parts = p.replace(/\\/g, '/').split('/').map(s => s.replace(/[\p{Cc}\p{Cf}]/gu, '').trim()).filter(s => s && s !== '.' && s !== '..');
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
  // only ever over a few MiB (fingerprints, ids). signal: stops between slices
  // (and around the native digest, which can't be interrupted)
  async function sha256(blob, signal) {
    const stop = () => { if (signal && signal.aborted) throw signal.reason; };
    stop();
    if (subtle) {
      const buf = await blob.arrayBuffer();
      stop();
      const d = new Uint8Array(await subtle.digest('SHA-256', buf));
      stop();
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
      const u = new Uint8Array(await blob.slice(o, o + left).arrayBuffer());
      stop();
      blocks(u);
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
    let shut = false;
    const close = ok => {
      if (shut) return;
      shut = true;
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

  // indexeddb, keyed [share, item id] / [share, note id] / [share, member id].
  // upgrades keep what is there: hosts must never lose files to a new version
  const idb = (() => {
    let p;
    const open = () => p || (p = new Promise((res, rej) => {
      const r = indexedDB.open('p2p', 4);
      r.onupgradeneeded = e => {
        const d = r.result, t = r.transaction;
        if (e.oldVersion < 2) for (const n of [...d.objectStoreNames]) d.deleteObjectStore(n); // (v1 layouts are long gone)
        if (!d.objectStoreNames.contains('notes')) d.createObjectStore('notes', { keyPath: ['slug', 'id'] });
        if (!d.objectStoreNames.contains('members')) d.createObjectStore('members', { keyPath: ['slug', 'id'] });
        if (!d.objectStoreNames.contains('items')) d.createObjectStore('items', { keyPath: ['slug', 'id'] });
        // v2/v3 kept files by path: each gets an id (transfers address items by id) and
        // moves over, in this same transaction. old hashes go; fingerprints are made later
        if (d.objectStoreNames.contains('files')) {
          const items = t.objectStore('items'), q = t.objectStore('files').openCursor();
          q.onsuccess = () => {
            const c = q.result;
            if (!c) return d.deleteObjectStore('files');
            const f = c.value;
            if (f && f.blob) items.put({ slug: f.slug, id: newId(), path: f.path, mtime: f.mtime, fp: null, blob: f.blob });
            c.continue();
          };
        }
      };
      // a tab still running an older version holds the database: it has to close first
      r.onblocked = () => { p = null; rej(Object.assign(new Error('a tab with an older version of this site is open — close it, then reload this page'), { blocked: true })); };
      // a newer version in another tab needs this one to let go
      r.onsuccess = () => { r.result.onversionchange = () => { r.result.close(); p = null; }; res(r.result); };
      r.onerror = () => rej(r.error);
    }));
    // signal: aborting it rolls the transaction back, as long as it hasn't committed yet
    const run = async (name, mode, fn, signal) => {
      const d = await open();
      return new Promise((res, rej) => {
        if (signal && signal.aborted) return rej(signal.reason);
        const t = d.transaction(name, mode);
        const q = fn(t.objectStore(name));
        const off = () => { try { t.abort(); } catch {} };
        if (signal) signal.addEventListener('abort', off, { once: true });
        const done = () => signal && signal.removeEventListener('abort', off);
        t.oncomplete = () => { done(); res(q && q.result); };
        t.onerror = t.onabort = () => { done(); rej(signal && signal.aborted ? signal.reason : t.error || new Error('storage error')); };
      });
    };
    // one share's view of the stores
    return slug => {
      const every = IDBKeyRange.bound([slug], [slug, []]);
      return {
        all: s => run(s, 'readonly', o => o.getAll(every)),
        get: (s, k) => run(s, 'readonly', o => o.get([slug, k])),
        put: (s, v) => run(s, 'readwrite', o => o.put({ ...v, slug })),
        putAll: (s, vs, signal) => run(s, 'readwrite', o => { for (const v of vs) o.put({ ...v, slug }); }, signal),
        del: (s, k) => run(s, 'readwrite', o => o.delete([slug, k])),
        // read, check and write in one transaction, so a newer put can't be overwritten
        patch: (s, k, fn) => run(s, 'readwrite', o => { const q = o.get([slug, k]); q.onsuccess = () => { const v = q.result && fn(q.result); if (v) o.put(v); }; }),
        delAll: (s, ks) => run(s, 'readwrite', o => { for (const k of ks) o.delete([slug, k]); }),
        clear: () => Promise.all(['items', 'notes', 'members'].map(s => run(s, 'readwrite', o => o.delete(every)))),
      };
    };
  })();

  // ---- wire format --------------------------------------------------------
  //
  // every connection (guest↔host, and guest↔guest "links") has two ordered
  // channels: ctl carries json strings, bin carries file bytes. control messages
  // (cancel, listing changes, notes, signaling) never queue behind file data.
  // json messages over PART characters are split into { t: '+', d, end } parts.
  //
  // joining (guest → host, first message on ctl):
  //   hello { v: 3, name, secret, have: [ids] }   secret: per-share, see shareSecret
  //   ← welcome { you: { id, name }, v, mode, rev, members, items, notes, tomb }
  //   ← name-taken { suggest }
  // after that the host sends changes, numbered:
  //   ← delta { rev, items: { add, up, rm }, notes: { up, rm }, members: { up }, mode? }
  //   a guest that misses a rev asks: sync {} → ← snap { …same as welcome }
  // items: { id, path, size, mtime, fp, owner, kind: 'stored'|'ref', off }
  //   stored: bytes in the host's indexeddb; ref: bytes in the owner's open tab.
  //   off: when the owner went offline (0 = online)
  // guest → host: add { items: [{ id, path, size, mtime, fp }], dir? }  ← added { no: [refused ids] }
  //               rm { ids } | rm { path, dir: true }, note { title, text, id? }, unnote { id }
  //               peer-sig { to: member, data }  → forwarded as peer-sig { from: member, data }
  // host → owner: unshared { ids, by, why: 'deleted'|'one-way' }
  // host → guest: bye { why }, err { e }
  //
  // files are pulled, the same way on every connection. the requester:
  //   open { xid, id }        ← meta { xid, size, mtime }  or  ← err { xid, e }
  //   want { xid, off, len }  windows of WIN bytes, at most INFLIGHT outstanding
  //   close { xid }           done or cancelled
  // the owner answers each want on bin, in order, with frames
  //   [u32 xid][u32 offset high][u32 offset low][bytes]   (≤ min(256 KiB, max message) - 12)
  // and checks before every chunk that the transfer is still open. the requester
  // only accepts bytes that continue the oldest outstanding window, and never more
  // than size. resuming after a reconnect is open again + want from the last byte.
  // pulling (rather than the owner pushing) bounds what anyone holds in flight to
  // INFLIGHT × WIN per transfer, which is what lets the host forward bytes between
  // two guests without storing them, and lets a slow disk or stream set the pace.

  // m: a message, or one already encoded (the same delta to every guest)
  function tx(dc, m) {
    if (!dc || dc.readyState !== 'open') return;
    const s = typeof m === 'string' ? m : JSON.stringify(m);
    if (s.length <= PART && !dc.txn) return dc.send(s);
    // a peer that stops reading (or keeps asking for snapshots) can't make us queue
    // without limit: past 64 MB of text waiting, it is cut off
    if ((dc.txb || 0) + s.length > 64e6) { try { dc.close(); } catch {} return; }
    dc.txb = (dc.txb || 0) + s.length;
    // a big one (a listing of thousands of files) waits for room between parts, so the
    // channel's buffer never overflows; whatever is sent meanwhile queues behind it
    const parts = [];
    if (s.length <= PART) parts.push(s);
    else for (let i = 0; i < s.length; i += PART) parts.push(JSON.stringify({ t: '+', d: s.slice(i, i + PART), end: i + PART >= s.length }));
    dc.txn = (dc.txn || 0) + 1;
    dc.txq = (dc.txq || Promise.resolve()).then(async () => {
      for (const p of parts) {
        if (dc.readyState !== 'open') return;
        if (dc.bufferedAmount > LOW) await drain(dc);
        dc.send(p);
      }
    }).catch(() => {}).finally(() => { dc.txb -= s.length; if (!--dc.txn) dc.txq = null; });
  }
  function rx(st, raw) {
    if (typeof raw !== 'string' || raw.length > 64e3) return null; // ours are parts of PART chars
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
  const u32 = n => Number.isSafeInteger(n) && n >= 1 && n <= 0xffffffff;
  const ITEM = /^[a-z0-9]{12}$/;
  // the two channels of a webrtc connection, set up the same way on both ends (negotiated)
  function chans(pc) {
    const ctl = pc.createDataChannel('ctl', { negotiated: true, id: 0, ordered: true });
    const bin = pc.createDataChannel('bin', { negotiated: true, id: 1, ordered: true });
    for (const c of [ctl, bin]) { c.binaryType = 'arraybuffer'; c.bufferedAmountLowThreshold = LOW; }
    return { ctl, bin };
  }
  const bothOpen = ({ ctl, bin }) => new Promise(r => {
    const check = () => ctl.readyState === 'open' && bin.readyState === 'open' && r();
    ctl.addEventListener('open', check);
    bin.addEventListener('open', check);
    check();
  });

  // ---- relay ---------------------------------------------------------------
  // fallback for when the browsers can't reach each other directly: frames go
  // through the signaling server, end-to-end encrypted with aes-gcm under a key
  // from an ecdh exchange done during the handshake. the server only sees
  // ciphertext. one socket carries both channels: the first byte of each
  // (encrypted) frame says which, and queued ctl frames go out before bin ones.

  const subtle = window.crypto && crypto.subtle;
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  const RELAY_MAX = 65536; // per message, + headers: well under the server's 128 KB cap
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
    // v2: two channels per frame; a v1 peer can't decrypt these, nor these theirs
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('p2p relay v2') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
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
    // side: 0 guest, 1 host. out(ciphertext) sends on the socket, buffered() is its backlog
    constructor(key, side, out, buffered) {
      Object.assign(this, { key, side, out, buffered, readyState: 'open', q: [[], []], qb: [0, 0], sent: 0, got: 0, busy: false, rx: Promise.resolve(), onclose: null });
      const r = this;
      const ch = c => ({
        relay: true, onmessage: null, onclose: null,
        get readyState() { return r.readyState; },
        // file bytes count what waits on the socket too: that's what drain() waits on
        get bufferedAmount() { return r.qb[c] + (c ? r.buffered() : 0); },
        send: d => r.send(c, d),
        close: () => r.close(),
        addEventListener() {}, removeEventListener() {},
      });
      this.ctl = ch(0);
      this.bin = ch(1);
    }
    send(c, data) {
      if (this.readyState !== 'open') return;
      const body = c ? new Uint8Array(data.buffer || data, data.byteOffset || 0, data.byteLength) : enc.encode(data);
      const frame = new Uint8Array(body.length + 1);
      frame[0] = c;
      frame.set(body, 1);
      this.q[c].push(frame);
      this.qb[c] += frame.length;
      this.pump();
    }
    // one at a time (the nonce counter is the order). file bytes only go to the socket
    // while its backlog is small, so a control frame never waits behind much
    async pump() {
      if (this.busy) return;
      this.busy = true;
      try {
        while (this.readyState === 'open') {
          const c = this.q[0].length ? 0 : this.q[1].length ? 1 : -1;
          if (c < 0) break;
          if (c && this.buffered() > 256 << 10) { await new Promise(r => setTimeout(r, 10)); continue; }
          const f = this.q[c].shift();
          const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce(this.side, this.sent++) }, this.key, f));
          this.qb[c] -= f.length;
          if (this.readyState === 'open') this.out(ct);
        }
      } catch { this.close(); }
      this.busy = false;
    }
    receive(buf) {
      this.rx = this.rx.then(async () => {
        if (this.readyState !== 'open') return;
        const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce(1 - this.side, this.got++) }, this.key, buf));
        const ch = pt[0] ? this.bin : this.ctl;
        if (ch.onmessage) ch.onmessage({ data: pt[0] ? pt.buffer.slice(1) : dec.decode(pt.subarray(1)) });
      }).catch(() => this.close()); // tampered or wrong key
    }
    close() {
      if (this.readyState === 'closed') return;
      this.readyState = 'closed';
      this.q = [[], []];
      for (const ch of [this.ctl, this.bin]) if (ch.onclose) ch.onclose();
      if (this.onclose) this.onclose();
    }
  }

  // ---- moving files: pull on one side, serve on the other --------------------
  // conn(): one end of a connection. hooks:
  //   resolve(c, id) → { blob, size, mtime }  what this end hands out (throws a message if not)
  //   proxy(c, m)    → true if it forwarded the open (the host, for items in other guests' tabs)
  //   gone(id)       a file we hand out can't be read any more

  const HDR = 12;
  // SERVES_MAX files served at once, at most 2 of them to any one connection, so one
  // requester can't hold every slot. a serve nobody asks anything of for a minute
  // (a paused download, or someone squatting) gives its slot back
  let serving = 0;
  const slots = [], live = new Set();
  const serveSync = () => busy('serve', serving > 0); // owners keep the screen on while serving
  const slot = c => {
    if (serving < SERVES_MAX && (c.slotted || 0) < 2) { serving++; c.slotted = (c.slotted || 0) + 1; serveSync(); return Promise.resolve(); }
    return new Promise(r => slots.push({ c, r }));
  };
  const unslot = c => {
    c.slotted--;
    const i = slots.findIndex(w => (w.c.slotted || 0) < 2);
    if (i >= 0) { const [w] = slots.splice(i, 1); w.c.slotted = (w.c.slotted || 0) + 1; w.r(); } else serving--;
    serveSync();
  };
  // and while others wait, one that moved less than a window in the last minute (a
  // trickle that only keeps its slot warm) gives it back too
  setInterval(() => {
    const now = Date.now();
    for (const s of live) {
      if (!s.busy && !s.wants.length && now - s.last > 6e4) { endServe(s, 'idle'); continue; }
      if (now - s.mark < 6e4) continue;
      if (slots.length && s.moved < WIN) endServe(s, 'idle');
      s.mark = now;
      s.moved = 0;
    }
  }, 15e3);

  function conn(ctl, bin, maxMsg, hooks) {
    return { ctl, bin, hooks, pulls: new Map(), serves: new Map(), xid: 0, max: Math.min(MSG, maxMsg || 65536) - HDR, used: Date.now(), send: m => tx(ctl, m) };
  }
  function frame(xid, off, bytes) {
    const f = new Uint8Array(HDR + bytes.length), v = new DataView(f.buffer);
    v.setUint32(0, xid);
    v.setUint32(4, Math.floor(off / 2 ** 32));
    v.setUint32(8, off >>> 0);
    f.set(bytes, HDR);
    return f;
  }

  // a transfer message from c: true if handled
  function xmsg(c, m) {
    switch (m.t) {
      case 'open': serveOpen(c, m); return true;
      case 'want': {
        const s = c.serves.get(m.xid);
        if (!s || !Number.isSafeInteger(m.off) || !Number.isSafeInteger(m.len) || m.len < 1 || m.len > 4 * WIN || m.off < 0) return true;
        if (s.up) { // forwarded, nothing kept
          if (s.fwd + m.len > INFLIGHT * WIN) { endServe(s, 'bad request'); return true; }
          s.fwd += m.len;
          (c.held || (c.held = [])).push({ s, off: m.off, len: m.len });
          release(c);
          return true;
        }
        if (!s.src || m.off + m.len > s.src.size || s.wants.length >= 4 * INFLIGHT) { endServe(s, 'bad request'); return true; }
        s.wants.push({ off: m.off, len: m.len });
        c.used = s.last = Date.now();
        pumpServe(s);
        return true;
      }
      case 'close': {
        const s = c.serves.get(m.xid);
        if (s) endServe(s);
        return true;
      }
      case 'meta': case 'err': {
        if (!u32(m.xid)) return m.t === 'meta';
        const a = c.pulls.get(m.xid);
        if (!a) return true; // late answer to something already closed
        if (a.down) { // forwarding for another guest
          if (m.t === 'err') { endProxy(a, String(m.e).slice(0, 100)); return true; }
          if (Number.isSafeInteger(m.size) && m.size >= 0) tx(a.down.c.ctl, { t: 'meta', xid: a.down.xid, size: m.size, mtime: +m.mtime || 0 });
          return true;
        }
        if (m.t === 'err') attemptFailed(a, String(m.e).slice(0, 100));
        else gotMeta(a, m);
        return true;
      }
    }
    return false;
  }

  // ---- serving
  async function serveOpen(c, m) {
    if (!u32(m.xid) || c.serves.has(m.xid)) return;
    if (c.serves.size >= 64 || !ITEM.test(m.id)) return c.send({ t: 'err', xid: m.xid, e: 'rejected' });
    const s = { c, xid: m.xid, id: m.id, wants: [], open: true, src: null, up: null, slot: false, last: Date.now(), fwd: 0 };
    c.serves.set(m.xid, s);
    if (c.hooks.proxy && c.hooks.proxy(c, s)) return;
    await slot(c);
    s.slot = true;
    live.add(s);
    s.last = s.mark = Date.now();
    s.moved = 0;
    if (!s.open) return endServe(s);
    try { s.src = await c.hooks.resolve(c, m.id); } catch (e) { return endServe(s, (e && e.message) || 'not available'); }
    if (!s.open) return endServe(s);
    c.send({ t: 'meta', xid: s.xid, size: s.src.size, mtime: s.src.mtime });
  }
  function endServe(s, err) {
    const first = s.open;
    s.open = false;
    if (s.c.serves.get(s.xid) === s) s.c.serves.delete(s.xid);
    if (err && first) s.c.send({ t: 'err', xid: s.xid, e: err });
    if (s.up) { const u = s.up; s.up = null; if (u.c.pulls.get(u.xid)) { u.c.pulls.delete(u.xid); tx(u.c.ctl, { t: 'close', xid: u.xid }); } }
    if (s.slot) { s.slot = false; live.delete(s); unslot(s.c); }
    if (s.out) { s.c.fwdOut = Math.max(0, (s.c.fwdOut || 0) - s.out); s.out = 0; } // what won't arrive any more
  }
  const readAt = (s, w) => { const p = s.src.blob.slice(w.off, w.off + w.len).arrayBuffer(); p.catch(() => {}); return p; };
  // answer wants in order: read the next window while this one goes out
  async function pumpServe(s) {
    if (s.busy) return;
    s.busy = true;
    const { c } = s, n = c.max;
    let next = null;
    try {
      while (s.open && s.wants.length) {
        const w = s.wants[0];
        const buf = new Uint8Array(await (next || readAt(s, w)));
        next = s.wants[1] ? readAt(s, s.wants[1]) : null;
        s.wants.shift();
        if (buf.length !== w.len) throw new Error('short read');
        for (let i = 0; i < buf.length; i += n) {
          if (c.bin.bufferedAmount > HIGH) await drain(c.bin);
          if (!s.open) return;
          if (c.bin.readyState !== 'open') return endServe(s);
          c.bin.send(frame(s.xid, w.off + i, buf.subarray(i, i + n)));
        }
        s.last = Date.now();
        s.moved += buf.length;
        c.used = Date.now();
      }
    } catch {
      // moved, changed or deleted on disk since it was shared
      if (s.open) { endServe(s, 'the file can no longer be read'); if (c.hooks.gone) c.hooks.gone(s.id); }
    } finally { s.busy = false; }
  }

  // ---- forwarding (the host, between two guests that can't link directly)
  // to the owner we are the requester, to the guest the owner; only wants the guest
  // sends go upstream, so no more than INFLIGHT windows per transfer are ever in flight here
  const nextXid = c => (c.xid = (c.xid % 0xffffffff) + 1);
  function proxyOpen(s, upc, id) {
    const xid = nextXid(upc);
    s.up = { c: upc, xid };
    upc.pulls.set(xid, { down: s, xid });
    upc.send({ t: 'open', xid, id });
  }
  // pass forwarded wants upstream only while little waits on the guest's connection:
  // whatever the owners send then always fits (chrome closes a channel past 16 MB)
  function release(d) {
    clearTimeout(d.heldT);
    while (d.held.length) {
      const h = d.held[0];
      if (!h.s.open || !h.s.up) { d.held.shift(); continue; }
      if (d.bin.bufferedAmount + (d.fwdOut || 0) + h.len > 8 << 20) { d.heldT = setTimeout(() => release(d), 25); return; }
      d.held.shift();
      d.fwdOut = (d.fwdOut || 0) + h.len;
      h.s.out = (h.s.out || 0) + h.len; // asked upstream, not yet arrived
      tx(h.s.up.c.ctl, { t: 'want', xid: h.s.up.xid, off: h.off, len: h.len });
    }
  }
  function endProxy(a, err) {
    const s = a.down;
    if (s.up && s.up.c.pulls.get(s.up.xid) === a) s.up.c.pulls.delete(s.up.xid);
    s.up = null;
    endServe(s, err);
  }
  // connection gone: close what was forwarded through it, both ways
  function connClosed(c) {
    for (const s of [...c.serves.values()]) endServe(s);
    for (const [xid, a] of [...c.pulls]) {
      c.pulls.delete(xid);
      if (a.down) endProxy(a, 'offline');
      else attemptFailed(a, null);
    }
  }

  // ---- pulling
  // x (one download, across reconnects and routes): { id, got, size, mtime, sink, prog, att }
  // a (one attempt over one connection): { c, x, xid, wins, next }
  function attempt(c, x) {
    const xid = nextXid(c);
    const a = { c, x, xid, wins: [], next: x.got, meta: false };
    c.pulls.set(xid, a);
    x.att = a;
    c.used = Date.now();
    c.send({ t: 'open', xid, id: x.id });
  }
  function gotMeta(a, m) {
    const x = a.x;
    if (!Number.isSafeInteger(m.size) || m.size < 0) return attemptFailed(a, 'bad answer');
    const mtime = Number.isSafeInteger(m.mtime) ? m.mtime : 0;
    if (x.size != null && (m.size !== x.size || (x.mtime && mtime !== x.mtime))) return attemptFailed(a, 'the file changed — get it again');
    x.size = m.size;
    x.mtime = mtime;
    a.meta = true;
    if (x.got >= x.size) return pullDone(a);
    fill(a);
  }
  function fill(a) {
    const x = a.x;
    // a sink that's behind (a slow disk, a download the browser reads slowly) holds new wants back
    while (a.wins.length < INFLIGHT && a.next < x.size && !(x.sink.full && x.sink.full())) {
      const len = Math.min(WIN, x.size - a.next);
      a.wins.push({ at: a.next, end: a.next + len });
      a.c.send({ t: 'want', xid: a.xid, off: a.next, len });
      a.next += len;
    }
  }
  // bytes on bin: for one of our pulls, or (host) to forward
  function onFrame(c, buf) {
    if (!(buf instanceof ArrayBuffer) || buf.byteLength <= HDR) return;
    const v = new DataView(buf), xid = v.getUint32(0), off = v.getUint32(4) * 2 ** 32 + v.getUint32(8);
    const a = c.pulls.get(xid);
    if (!a) return; // closed meanwhile
    if (a.down) { // forward with the guest's own transfer id, in pieces its connection takes
      const s = a.down, d = s.c, body = new Uint8Array(buf, HDR);
      if (!s.open || d.bin.readyState !== 'open') return;
      // never more than was asked for
      if (body.length > s.fwd) return endServe(s, 'bad data from the other side');
      s.fwd -= body.length;
      s.out = Math.max(0, (s.out || 0) - body.length);
      d.fwdOut = Math.max(0, (d.fwdOut || 0) - body.length);
      try {
        if (body.length <= d.max) {
          new DataView(buf).setUint32(0, s.xid);
          d.bin.send(buf);
        } else for (let i = 0; i < body.length; i += d.max) d.bin.send(frame(s.xid, off + i, body.subarray(i, i + d.max)));
      } catch { endServe(s, 'offline'); }
      return;
    }
    const x = a.x, w = a.wins[0], n = buf.byteLength - HDR;
    if (x.att !== a) return;
    if (!a.meta || !w || off !== w.at || off + n > w.end) return attemptFailed(a, 'bad data from the other side', true);
    try { x.sink.write(new Uint8Array(buf, HDR), off); } catch (e) { return attemptFailed(a, (e && e.message) || 'could not save', true); }
    w.at += n;
    x.got = w.at;
    c.used = Date.now();
    if (x.prog) x.prog(x.got);
    if (w.at === w.end) { a.wins.shift(); fill(a); }
    if (x.got === x.size) pullDone(a);
  }
  function pullDone(a) {
    const x = a.x;
    if (a.c.pulls.get(a.xid) === a) { a.c.pulls.delete(a.xid); a.c.send({ t: 'close', xid: a.xid }); }
    x.att = null;
    x.finish(null);
  }
  // err null: the connection went (try again, maybe another way); fatal: don't retry
  function attemptFailed(a, err, fatal) {
    const x = a.x;
    if (a.c.pulls.get(a.xid) === a) { a.c.pulls.delete(a.xid); if (err) a.c.send({ t: 'close', xid: a.xid }); }
    if (x.att !== a) return;
    x.att = null;
    x.failed(err, fatal);
  }
  // stop pulling (cancelled): tell the owner at once, on ctl, so it stops before its next chunk
  function cancelPull(x) {
    const a = x.att;
    x.att = null;
    if (a && a.c.pulls.get(a.xid) === a) { a.c.pulls.delete(a.xid); a.c.send({ t: 'close', xid: a.xid }); }
  }

  // ---- where downloads go -------------------------------------------------
  // a sink takes a download's bytes: { write(u8, off), full(), onroom, close(), abort() }.
  // full() says to stop asking the other side for more; onroom() is called when there's
  // room again, so a slow disk or stream sets the pace all the way back to the owner.
  // in order of preference:
  //   fs   file system access (chromium): written in place, any size, folders as folders
  //   sw   a download streamed through public/sw.js (needs https): any size, folders as zip64
  //   mem  in memory, then saved (plain http, or nothing else works): size-limited by ram

  // in memory: blob parts, folded into a blob every 16 MB so the browser can page them out
  function memSink() {
    const t = { parts: [], mem: 0 };
    return {
      kind: 'mem',
      write: u8 => collect(t, u8),
      whole: b => { t.parts = [b]; },
      blob: () => new Blob(t.parts),
      close: async () => {},
      abort: async () => { t.parts = []; },
    };
  }

  // file system access: positional writes into a swap file the browser only puts in
  // place on close(); abort() throws it away and removes the (empty) file the picker made
  async function fsSink(handle) {
    const w = await handle.createWritable();
    let q = Promise.resolve(), pend = 0, err = null;
    const s = {
      kind: 'fs', onroom: null,
      write(u8, off) {
        if (err) throw err;
        const n = u8.length;
        pend += n;
        q = q.then(() => w.write({ type: 'write', position: off, data: u8 })).then(() => { pend -= n; if (s.onroom) s.onroom(); }, e => { err = err || e; if (s.onroom) s.onroom(); });
      },
      // once broken, never "full": the next write then throws, and the download fails instead of waiting
      full: () => !err && pend >= 4 * WIN,
      close: async () => { await q; if (err) throw err; await w.close(); },
      abort: async () => { err = err || new Error('cancelled'); await q; await w.abort().catch(() => {}); if (handle.remove) await handle.remove().catch(() => {}); },
    };
    return s;
  }
  // names that are fine here may not be on someone's disk
  const diskName = s => s.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/[. ]+$/, '_') || '_';
  // "photo.jpg" → "photo (2).jpg"
  const nth = (name, k) => { const d = name.lastIndexOf('.'); return d > 0 ? `${name.slice(0, d)} (${k})${name.slice(d)}` : `${name} (${k})`; };
  const exists = async (dir, name) => {
    for (const kind of ['getFileHandle', 'getDirectoryHandle']) { try { await dir[kind](name); return true; } catch {} }
    return false;
  };
  // a folder written as real files and folders inside the one picked. nothing that is
  // already there gets overwritten: a clash gets " (2)"
  async function fsDir(root, top) {
    let name = diskName(top);
    for (let k = 2; await exists(root, name); k++) name = nth(diskName(top), k);
    const base = await root.getDirectoryHandle(name, { create: true }), dirs = new Map([['', base]]);
    const dirOf = path => {
      if (!dirs.has(path)) {
        const i = path.lastIndexOf('/');
        dirs.set(path, dirOf(i < 0 ? '' : path.slice(0, i)).then(d => d.getDirectoryHandle(diskName(path.slice(i + 1)), { create: true })));
      }
      return Promise.resolve(dirs.get(path));
    };
    return {
      async file(rel) {
        const i = rel.lastIndexOf('/'), d = await dirOf(i < 0 ? '' : rel.slice(0, i)), want = diskName(rel.slice(i + 1));
        let n = want;
        for (let k = 2; await exists(d, n); k++) n = nth(want, k);
        return fsSink(await d.getFileHandle(n, { create: true }));
      },
    };
  }

  // service worker: the browser fetches /dl/<id>/<name>, the worker answers with a stream
  // that asks this page for each chunk (see sw.js). registered once, on https only
  let swReg = null, swPing = null, swOpen = 0;
  if (window.isSecureContext && navigator.serviceWorker) {
    // trusted types: register() takes a script url. the csp allows only this policy,
    // and it only ever gives the one constant
    let url = '/sw.js';
    try { if (window.trustedTypes) url = trustedTypes.createPolicy('p2p-sw', { createScriptURL: () => '/sw.js' }).createScriptURL(''); } catch {}
    navigator.serviceWorker.register(url).then(() => navigator.serviceWorker.ready).then(r => { swReg = r; }).catch(() => {});
  }
  const swOk = () => !!(swReg && swReg.active);
  function swSink(name, size, zip) {
    const id = newId() + newId(), ch = new MessageChannel(), q = [];
    let qb = 0, asked = false, ended = false, aborted = false, err = null, written = 0, done = null, fail = null, pulled = false;
    const s = { kind: 'sw', onroom: null };
    const broke = e => { err = err || e; if (s.onroom) s.onroom(); if (fail) fail(err); };
    // nothing asked for after 30 s: the browser didn't start the download (blocked, or the worker was replaced)
    const first = setTimeout(() => !pulled && broke(new Error('the browser did not start the download')), 3e4);
    // the worker asks for one chunk at a time: data, the end, or that it's off
    const give = () => {
      asked = false;
      if (aborted) return ch.port1.postMessage({ t: 'abort' });
      if (q.length) {
        const b = q.shift();
        qb -= b.byteLength;
        ch.port1.postMessage({ t: 'data', buf: b }, [b]);
        if (s.onroom) s.onroom();
      } else if (ended) { ch.port1.postMessage({ t: 'end' }); if (done) done(); }
      else asked = true;
    };
    ch.port1.onmessage = e => {
      const m = e.data || {};
      if (m.t === 'pull') { pulled = true; clearTimeout(first); give(); }
      else if (m.t === 'cancel') broke(new Error('the download was cancelled in the browser'));
    };
    swReg.active.postMessage({ t: 'dl', id, name, size, zip: !!zip }, [ch.port2]);
    // started by a hidden frame: chromium doesn't send <a download> through service
    // workers, and navigating this page would trip its "leave this page?" guard
    const frame = el('iframe', { src: `/dl/${id}/${encodeURIComponent(name)}`, hidden: true, title: 'download' });
    document.body.append(frame);
    // workers that seem idle get stopped; while bytes flow, keep it awake
    if (!swOpen++) swPing = setInterval(() => swReg && swReg.active && swReg.active.postMessage({ t: 'ping' }), 1e4);
    let stopped = false;
    const stop = () => {
      if (stopped) return;
      stopped = true;
      if (!--swOpen) clearInterval(swPing);
      setTimeout(() => frame.remove(), 3e4);
    };
    return Object.assign(s, {
      write(u8, off) {
        if (err) throw err;
        if (off !== written) throw new Error('out of order');
        const b = u8.slice().buffer;
        written += u8.length;
        q.push(b);
        qb += b.byteLength;
        if (asked) give();
      },
      full: () => !err && qb >= 4 * WIN,
      // resolves once the last chunk has been taken
      close: () => new Promise((r, j) => { if (err) throw err; ended = true; fail = j; done = () => { stop(); r(); }; if (asked) give(); }),
      // the browser marks the download failed and drops what it had
      abort: async () => { if (aborted) return; aborted = true; clearTimeout(first); q.length = 0; qb = 0; if (asked) give(); else ch.port1.postMessage({ t: 'abort' }); stop(); },
    });
  }

  // a local blob (the host's own file, or one of yours) into a sink, a slice at a time
  async function pour(sink, blob, prog, sig) {
    if (sink.whole) { sink.whole(blob); if (prog) prog(blob.size); return; }
    const step = 1 << 20;
    let next = blob.slice(0, step).arrayBuffer();
    for (let o = 0; o < blob.size; o += step) {
      const u = new Uint8Array(await next);
      next = o + step < blob.size ? blob.slice(o + step, o + 2 * step).arrayBuffer() : null;
      if (next) next.catch(() => {});
      if (sig && sig.aborted) throw sig.reason;
      while (sink.full && sink.full()) await new Promise(r => { sink.onroom = r; setTimeout(r, 200); });
      sink.write(u, o);
      if (prog) prog(o + u.length);
    }
  }

  // ---- zip64, streamed, for folder downloads ---------------------------------
  // store only (no compression), sizes after each file (data descriptors), crc worked
  // out while the bytes go by, zip64 fields once anything passes 4 GB or 65,535 files.
  // writes strictly in order, so it works on a stream

  const CRC = new Int32Array(256).map((_, n) => { for (let k = 0; k < 8; k++) n = n & 1 ? 0xEDB88320 ^ (n >>> 1) : n >>> 1; return n; });
  const BIG = 0xffffffff;
  const u64 = (v, at, n) => { v.setUint32(at, n >>> 0, true); v.setUint32(at + 4, Math.floor(n / 2 ** 32), true); };
  function dosTime(ms) {
    const d = new Date(Math.max(ms || Date.now(), 315532800000));
    return { time: d.getHours() << 11 | d.getMinutes() << 5 | d.getSeconds() >> 1, date: (d.getFullYear() - 1980) << 9 | (d.getMonth() + 1) << 5 | d.getDate() };
  }
  function zipper(out) {
    let off = 0, n = 0;
    const cd = [];
    const emit = u8 => { out.write(u8, off); off += u8.length; };
    return {
      // one file: write its bytes in order into what this returns, then end()
      entry(name, size, mtime) {
        const nm = enc.encode(name), z = size >= BIG, at = off, { time, date } = dosTime(mtime);
        const lh = new DataView(new ArrayBuffer(30 + nm.length + (z ? 20 : 0)));
        lh.setUint32(0, 0x04034b50, true);
        lh.setUint16(4, z ? 45 : 20, true);
        lh.setUint16(6, 0x0808, true); // sizes follow the data; utf-8 names
        lh.setUint16(10, time, true);
        lh.setUint16(12, date, true);
        if (z) { lh.setUint32(18, BIG, true); lh.setUint32(22, BIG, true); }
        lh.setUint16(26, nm.length, true);
        lh.setUint16(28, z ? 20 : 0, true);
        new Uint8Array(lh.buffer).set(nm, 30);
        if (z) { lh.setUint16(30 + nm.length, 1, true); lh.setUint16(32 + nm.length, 16, true); } // zip64, sizes 0 here
        emit(new Uint8Array(lh.buffer));
        let crc = -1, got = 0;
        return {
          write(u8) {
            for (let i = 0; i < u8.length; i++) crc = CRC[(crc ^ u8[i]) & 255] ^ (crc >>> 8);
            got += u8.length;
            emit(u8);
          },
          full: () => !!(out.full && out.full()),
          set onroom(f) { out.onroom = f; },
          end() {
            if (got !== size) throw new Error('size mismatch');
            crc = ~crc >>> 0;
            const dd = new DataView(new ArrayBuffer(z ? 24 : 16));
            dd.setUint32(0, 0x08074b50, true);
            dd.setUint32(4, crc, true);
            if (z) { u64(dd, 8, size); u64(dd, 16, size); } else { dd.setUint32(8, size, true); dd.setUint32(12, size, true); }
            emit(new Uint8Array(dd.buffer));
            cd.push({ nm, crc, size, at, time, date });
            n++;
          },
        };
      },
      // the central directory, zip64 records if needed, the end record
      finish() {
        const start = off;
        for (const e of cd) {
          const zs = e.size >= BIG, zo = e.at >= BIG, xl = (zs ? 16 : 0) + (zo ? 8 : 0);
          const v = new DataView(new ArrayBuffer(46 + e.nm.length + (xl ? 4 + xl : 0)));
          v.setUint32(0, 0x02014b50, true);
          v.setUint16(4, 45, true);
          v.setUint16(6, xl ? 45 : 20, true);
          v.setUint16(8, 0x0808, true);
          v.setUint16(12, e.time, true);
          v.setUint16(14, e.date, true);
          v.setUint32(16, e.crc, true);
          v.setUint32(20, zs ? BIG : e.size, true);
          v.setUint32(24, zs ? BIG : e.size, true);
          v.setUint16(28, e.nm.length, true);
          v.setUint16(30, xl ? 4 + xl : 0, true);
          v.setUint32(42, zo ? BIG : e.at, true);
          new Uint8Array(v.buffer).set(e.nm, 46);
          if (xl) {
            let p = 46 + e.nm.length;
            v.setUint16(p, 1, true);
            v.setUint16(p + 2, xl, true);
            p += 4;
            if (zs) { u64(v, p, e.size); u64(v, p + 8, e.size); p += 16; }
            if (zo) u64(v, p, e.at);
          }
          emit(new Uint8Array(v.buffer));
        }
        const size = off - start, z = n >= 0xffff || start >= BIG || size >= BIG;
        if (z) {
          const r = new DataView(new ArrayBuffer(76)), at = off;
          r.setUint32(0, 0x06064b50, true);
          u64(r, 4, 44);
          r.setUint16(12, 45, true);
          r.setUint16(14, 45, true);
          u64(r, 24, n);
          u64(r, 32, n);
          u64(r, 40, size);
          u64(r, 48, start);
          r.setUint32(56, 0x07064b50, true); // locator
          u64(r, 64, at);
          r.setUint32(72, 1, true);
          emit(new Uint8Array(r.buffer));
        }
        const e = new DataView(new ArrayBuffer(22));
        e.setUint32(0, 0x06054b50, true);
        e.setUint16(8, z ? 0xffff : n, true);
        e.setUint16(10, z ? 0xffff : n, true);
        e.setUint32(12, z ? BIG : size, true);
        e.setUint32(16, z ? BIG : start, true);
        emit(new Uint8Array(e.buffer));
      },
    };
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

  const WS_URL = () => (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
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
      const s = ws = new WebSocket(WS_URL());
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
  // src: { items, notes, members, me(), writable(), verb, hint(),
  //        add(list, sig, say), fetch(item, sink, prog, sig, waiting), rm(ids), rmDir(path),
  //        note(title, text, id), unnote(id) }

  // quick fingerprint for "is this the same file": sha-256 of the size, the first
  // and the last MiB. reads at most 2 MiB however big the file is
  async function fingerprint(f, sig) {
    const head = new Uint8Array(8), v = new DataView(head.buffer), M = 1 << 20;
    v.setUint32(0, Math.floor(f.size / 2 ** 32));
    v.setUint32(4, f.size >>> 0);
    return sha256(new Blob(f.size <= 2 * M ? [head, f] : [head, f.slice(0, M), f.slice(f.size - M)]), sig);
  }

  let dropTo = null, pasteTo = null;
  const collator = new Intl.Collator(undefined, { numeric: true });
  function panel(src, say, statusEl) {
    const status = t => view === out && say(t); // quiet once this panel is gone
    const open = new Set();
    const notesEl = el('ul', { class: 'ls' });
    const filesEl = el('ul', { class: 'ls' });
    const hintEl = el('p', { class: 'mute', hidden: true });
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
    const dirIn = el('input', { type: 'file', webkitdirectory: true, onchange: () => { upload([...dirIn.files].map(f => [f, f.webkitRelativePath || f.name]), true); dirIn.value = ''; } });
    // labels don't open their file picker from the keyboard on their own
    const pick = (label, input) => el('label', { class: 'btn', tabindex: '0', onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } } }, label, input);
    const tools = el('span', { class: 'row' }, pick('+ files', fileIn), pick('+ folder', dirIn));

    const cwd = () => { try { return clean(decodeURIComponent(location.hash.slice(1))) || ''; } catch { return ''; } };
    const cd = p => { location.hash = p ? encodeURIComponent(p).replace(/%2F/g, '/') : ''; };
    const fail = e => status('error: ' + (e && e.message || e));
    const byPath = () => { const m = new Map(); for (const it of src.items.values()) m.set(it.path, it); return m; };

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

    // batches run one after another, each into the folder that was open when it was added
    let queue = Promise.resolve();
    function upload(items, dir) {
      if (!src.writable() || !items.length) return;
      const base = cwd() ? cwd() + '/' : '', ctl = track();
      queue = queue.then(() => send(items, base, ctl, dir)).finally(() => untrack(ctl));
    }
    // yes/no bubble on the status line (the cancel button lives there, even while hidden)
    const sure = q => new Promise(r => ask(cancelBtn, q, () => r(true), () => r(false)));
    const short = s => `"${s.length > 40 ? s.slice(0, 18) + '…' + s.slice(-18) : s}"`;
    async function send(list, base, ctl, dir) {
      const sig = ctl.signal, verb = src.verb;
      let items = list.map(([f, rel]) => ({ f, rel, path: clean(base + rel) })).filter(it => it.path);
      let skipped = 0;
      try {
        if (sig.aborted) throw sig.reason;
        // same name as something already in this folder? ask first; if allowed, those
        // skip the content check below
        const paths = byPath(), named = new Set(items.filter(it => paths.has(it.path)));
        if (named.size) {
          const [{ rel }] = named;
          status('');
          const ok = await sure(named.size > 1 ? `${named.size} files with these names already exist. ${verb} them anyway?`
            : `${short(rel)} already exists. ${verb} anyway?`);
          if (sig.aborted) throw sig.reason;
          if (!ok) { skipped = named.size; items = items.filter(it => !named.has(it)); named.clear(); }
        }
        // same content as something already here, or earlier in this batch? (size + fingerprint)
        const have = new Map(), dups = new Map();
        for (const it of src.items.values()) if (it.fp) have.set(it.size + ':' + it.fp, [it.path, false]);
        let k = 0;
        await pool(items, 8, async it => {
          it.fp = await fingerprint(it.f, sig);
          if (++k % 50 === 0 || it.f.size > 64 << 20) status(`checking ${items.length > 1 ? `${k}/${items.length}` : it.rel}…`);
        }, sig);
        for (const it of items) {
          if (sig.aborted) throw sig.reason;
          if (named.has(it)) continue;
          const key = it.f.size + ':' + it.fp;
          if (have.has(key)) dups.set(it, have.get(key));
          else have.set(key, [it.path, true]);
        }
        if (sig.aborted) throw sig.reason; // never ask after a cancel
        if (dups.size) {
          const [[{ rel, path }, [at, batch]]] = dups, same = at === path;
          status('');
          const ok = await sure(dups.size > 1 ? `${dups.size} of these files are already here. ${verb} them anyway?`
            : batch ? `${short(rel)} is the same file as ${short(at)}. ${verb} both?`
            : `${short(rel)} is already here${same ? '' : ' as ' + short(at)}. ${verb} anyway?`);
          if (sig.aborted) throw sig.reason;
          if (!ok) { skipped += dups.size; items = items.filter(it => !dups.has(it)); }
        }
        if (sig.aborted) throw sig.reason;
        const r = items.length ? await src.add(items, sig, status, dir && clean(base + list[0][1].split('/')[0])) : { done: 0 };
        const n = r.done;
        status(!n && skipped ? 'nothing added — already here' : `${src.verb === 'share' ? '' : '↑ '}${n} file${n === 1 ? '' : 's'} ${src.verb === 'share' ? 'shared' : 'added'}${skipped ? ` · ${skipped} duplicate${skipped === 1 ? '' : 's'} skipped` : ''}${r.note ? ' · ' + r.note : ''}`);
      } catch (e) {
        const stopped = sig.aborted;
        ctl.abort();
        stopped ? status(`${src.verb === 'share' ? '' : '↑ '}cancelled${e && e.done ? ` · ${e.done} file${e.done === 1 ? '' : 's'} added` : ''}`) : fail(e);
      }
    }
    // a waiting download says why
    const waiting = name => status(name ? `waiting for ${name}…` : '');
    // where this download goes. called straight from the click: the save pickers and
    // starting a download need the click's user activation, so nothing waits before them
    function choose(name, isDir, size) {
      const picker = isDir ? window.showDirectoryPicker : window.showSaveFilePicker;
      if (picker) {
        try {
          const h = isDir ? picker({ mode: 'readwrite' }) : picker({ suggestedName: diskName(name) });
          h.catch(() => {});
          return { kind: 'fs', h };
        } catch {}
      }
      if (swOk()) return { kind: 'sw', sink: swSink(isDir ? name + '.zip' : name, isDir ? null : size, isDir) };
      return { kind: 'mem' };
    }
    function get(path, isDir, it) {
      const list = isDir ? [...src.items.values()].filter(f => f.path.startsWith(path + '/')) : it && src.items.get(it.id) === it ? [it] : [];
      if (!list.length) return status('not here any more');
      const name = path.split('/').pop(), total = list.reduce((s, f) => s + f.size, 0);
      fetchTo(choose(name, isDir, total), path, name, isDir, list, total);
    }
    async function fetchTo(how, path, name, isDir, list, total) {
      const ctl = track(), sig = ctl.signal, sinks = new Set();
      let sink = how.sink || null;
      if (sink) sinks.add(sink);
      try {
        // in memory only: say so before something big fills it (phones have less)
        if (how.kind === 'mem' && total > (coarse() ? 256 << 20 : 1 << 30)) {
          // on the status line (rows are redrawn under it); cancel answers it too
          const ok = await new Promise(r => { sig.addEventListener('abort', () => r(false), { once: true }); ask(cancelBtn, `this browser can only save it from memory (${size(total)}). go ahead?`, () => r(true), () => r(false)); });
          if (!ok) { status(''); return; }
        }
        if (!isDir) {
          const it = list[0];
          if (how.kind === 'fs') sinks.add(sink = await fsSink(await how.h));
          if (!sink) sinks.add(sink = memSink());
          await src.fetch(it, sink, meter(it.size, () => `↓ ${name}`), sig, waiting);
          if (sig.aborted) throw sig.reason;
          await sink.close();
          sinks.delete(sink);
          if (sink.kind === 'mem') save(sink.blob(), name);
          return status(`↓ ${name} done`);
        }
        let got = 0, done = 0;
        const show = meter(total, () => `↓ ${name}/ ${done}/${list.length}`);
        const one = async (f, s) => {
          let last = 0;
          const step = b => { got += b - last; last = b; show(got); };
          await src.fetch(f, s, step, sig, waiting);
          step(f.size);
          done++;
        };
        const rel = f => f.path.slice(path.length + 1);
        if (how.kind === 'fs') {
          // real files and folders, a few at a time
          const dir = await fsDir(await how.h, name);
          await pool(list, 4, async f => {
            const s = await dir.file(rel(f));
            sinks.add(s);
            await one(f, s);
            await s.close();
            sinks.delete(s);
          }, sig);
          return status(`↓ ${name}/ done`);
        }
        // one zip, written as it arrives
        if (!sink) sinks.add(sink = memSink());
        const z = zipper(sink);
        for (const f of list) {
          if (sig.aborted) throw sig.reason;
          const e = z.entry(name + '/' + rel(f), f.size, f.mtime);
          await one(f, e);
          e.end();
        }
        z.finish();
        await sink.close();
        sinks.delete(sink);
        if (sink.kind === 'mem') save(sink.blob(), name + '.zip');
        status(`↓ ${name}.zip done`);
      } catch (e) {
        const stopped = sig.aborted;
        ctl.abort(); // a failed file stops the rest of the folder
        // nothing half-written left behind, where the browser lets us
        for (const s of sinks) await s.abort().catch(() => {});
        if (!stopped && e && e.name === 'AbortError') return status(''); // the save picker was closed
        stopped ? status(`↓ ${name} cancelled`) : fail(e);
      } finally {
        untrack(ctl);
      }
    }

    // who added something: "you" for your own
    const who = id => !id ? '?' : id === src.me() ? 'you' : (src.members.get(id) || {}).name || '?';
    // several owners in a folder: the one with most files there, "+n" for the rest
    const whos = owners => {
      const ids = [...owners.keys()].sort((a, b) => owners.get(b) - owners.get(a));
      return who(ids[0]) + (ids.length > 1 ? ` +${ids.length - 1}` : '');
    };
    function row(label, meta, acts, off) {
      return el('li', { class: off ? 'off' : null }, label, el('span', { class: 'mute meta' }, meta), el('span', { class: 'acts' }, acts));
    }
    function refresh() {
      const w = src.writable();
      addNote.hidden = tools.hidden = !w;
      if (!w || (editing && !src.notes.has(editing))) closeNote();
      const hint = src.hint && src.hint();
      hintEl.hidden = !hint;
      hintEl.textContent = hint || '';

      const notes = [...src.notes.values()].sort((a, b) => b.t - a.t);
      notesEl.replaceChildren(...notes.map(n => {
        const li = row(
          el('button', { class: 'link', 'aria-expanded': String(open.has(n.id)), onclick: () => { open.has(n.id) ? open.delete(n.id) : open.add(n.id); refresh(); } }, n.title),
          `${who(n.author)} · ${new Date(n.t).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}${n.editor ? ` · edited by ${who(n.editor)}` : ''}`,
          [el('button', { onclick: e => copy(n.text, e.target) }, 'copy'), w && el('button', { onclick: () => openNote(n) }, 'edit'), w && el('button', { onclick: e => ask(e.target, 'delete this note?', () => src.unnote(n.id)) }, 'del')],
        );
        if (open.has(n.id)) li.append(el('pre', {}, n.text));
        return li;
      }));
      if (!notes.length) notesEl.append(el('li', { class: 'empty' }, 'no notes'));

      const dir = cwd(), pre = dir ? dir + '/' : '';
      const dirs = new Map(), files = [];
      for (const f of src.items.values()) {
        if (!f.path.startsWith(pre)) continue;
        const rest = f.path.slice(pre.length), i = rest.indexOf('/');
        if (i < 0) { files.push(f); continue; }
        const d = dirs.get(rest.slice(0, i)) || { n: 0, size: 0, owners: new Map(), off: 0 };
        d.n++;
        d.size += f.size;
        if (f.off) d.off++;
        d.owners.set(f.owner, (d.owners.get(f.owner) || 0) + 1);
        dirs.set(rest.slice(0, i), d);
      }
      const segs = dir ? dir.split('/') : [];
      crumbs.replaceChildren(el('button', { class: 'link', onclick: () => cd('') }, '/'),
        ...segs.flatMap((s, i) => [' ', el('button', { class: 'link', onclick: () => cd(segs.slice(0, i + 1).join('/')) }, s), ' /']));
      const byName = collator.compare;
      filesEl.replaceChildren(
        ...[...dirs.keys()].sort(byName).map(d => {
          const x = dirs.get(d), gone = x.off === x.n;
          return row(
            el('button', { class: 'link', onclick: () => cd(pre + d) }, d + '/'),
            `${x.n} · ${size(x.size)} · ${whos(x.owners)}${gone ? ' · offline' : ''}`,
            [el('button', { disabled: gone, onclick: () => get(pre + d, true) }, 'get'), w && el('button', { onclick: e => ask(e.target, `delete ${d}/ and all inside?`, () => src.rmDir(pre + d)) }, 'del')],
            gone);
        }),
        ...files.sort((a, b) => byName(a.path, b.path)).map(f => {
          const name = f.path.slice(pre.length), off = f.off;
          return row(el('span', {}, name), `${size(f.size)} · ${who(f.owner)}${off ? ' · offline' : ''}`,
            [el('button', { disabled: !!off, onclick: () => get(f.path, false, f) }, 'get'), w && el('button', { onclick: e => ask(e.target, f.owner === src.me() ? 'stop sharing this file?' : 'delete this file?', () => src.rm([f.id])) }, 'del')], off);
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
      // one dropped folder: a clash renames the folder ("photos (bob)/") rather than each file
      upload(items, entries.length === 1 && entries[0].isDirectory);
    };

    // pasted screenshots are all called "image.png": give them a unique name
    pasteTo = list => {
      if (!src.writable()) return;
      const d = new Date(), z = n => String(n).padStart(2, '0');
      const t = `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())} ${z(d.getHours())}.${z(d.getMinutes())}.${z(d.getSeconds())}`;
      // two pastes in the same second would overwrite each other: number the later ones
      const base = cwd() ? cwd() + '/' : '', used = new Set(), paths = byPath();
      upload(list.map(f => {
        if (f.name && !/^image\.\w+$/i.test(f.name)) return [f, f.name];
        const ext = (f.type.split('/')[1] || 'png').replace(/\W.*/, '');
        let name = `pasted ${t}.${ext}`;
        for (let n = 2; used.has(name) || paths.has(clean(base + name)); n++) name = `pasted ${t} (${n}).${ext}`;
        used.add(name);
        return [f, name];
      }));
    };

    const el_ = [
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', { class: 'grow' }, 'notes'), addNote), noteForm, notesEl),
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', {}, 'files'), crumbs, tools), filesEl, hintEl),
    ];
    const out = { els: el_, refresh, foot, stop: () => running.forEach(c => c.abort()) };
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
    const name = el('input', { class: 'name', placeholder: newSlug(), maxlength: '24', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'share name' });
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
    // your name: saved as you type; empty means the random one
    const m0 = me();
    const nameIn = el('input', { class: 'name', value: m0.name, placeholder: m0.rand, maxlength: '64', autocomplete: 'nickname', spellcheck: 'false', 'aria-label': 'your name' });
    const asEl = el('p', { class: 'mute' });
    const showAs = bad => { asEl.textContent = bad ? 'names are 1–24 characters' : `you'll appear as ${myName()}`; };
    let nameT;
    nameIn.addEventListener('input', () => {
      clearTimeout(nameT);
      nameT = setTimeout(() => {
        const raw = nameIn.value, n = normName(raw);
        if (!n && raw.trim()) return showAs(true);
        store.set('p2p:me', { ...me(), name: n || '' });
        showAs();
      }, 250);
    });
    showAs();
    app.replaceChildren(...[
      el('h1', {}, 'p2p'),
      el('section', { class: 'panel' }, el('h2', {}, 'your name'),
        el('form', { class: 'row', onsubmit: e => e.preventDefault() }, nameIn), asEl),
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

  // ---- downloads, shared by host and guest ----------------------------------
  // one download, across reconnects and routes. route(x) starts an attempt and
  // returns true, or returns { wait: name } (the owner is away: parked until kick())
  // or { fail: message }
  function download(it, sink, prog, sig, waiting, route, xfers) {
    return new Promise((res, rej) => {
      if (sig.aborted) return rej(sig.reason);
      const x = { id: it.id, got: 0, size: it.size, mtime: null, sink, prog, att: null, parked: false, waitFor: '' };
      const onAbort = () => x.finish(sig.reason);
      x.finish = err => {
        if (!xfers.delete(x)) return;
        sig.removeEventListener('abort', onAbort);
        clearTimeout(x.retry);
        cancelPull(x);
        err ? rej(err) : res();
      };
      x.failed = (err, fatal) => {
        if (fatal || (err && err !== 'offline' && err !== 'idle')) return x.finish(new Error(err || 'failed'));
        clearTimeout(x.retry);
        x.retry = setTimeout(x.go, err ? 1000 : 300); // connection went, or the owner just did: look again shortly
      };
      x.go = async () => {
        if (!xfers.has(x) || x.att) return;
        x.parked = false;
        let r;
        try { r = await route(x); } catch (e) { r = { fail: e.message }; }
        if (!xfers.has(x) || r === true) return;
        if (r.fail) return x.finish(new Error(x.waitFor && r.gone ? `${x.waitFor} went offline` : r.fail));
        x.parked = true;
        if (r.wait && r.wait !== x.waitFor) waiting(r.wait);
        x.waitFor = r.wait || x.waitFor;
      };
      sig.addEventListener('abort', onAbort, { once: true });
      sink.onroom = () => { const a = x.att; if (a && a.meta) fill(a); };
      xfers.add(x);
      x.go();
    });
  }
  // something changed (an owner came back, a connection opened): parked downloads look again
  const kick = xfers => { for (const x of xfers) if (x.parked) x.go(); };

  // ---- host ---------------------------------------------------------------

  async function host(sess) {
    document.title = sess.slug + ' · p2p';
    onTabs = null; // (straight from the home page's "create")
    if (location.pathname !== '/' + sess.slug) history.replaceState(null, '', '/' + sess.slug);
    current = location.pathname;
    // items: everything listed. stored ones (the host's own) are in indexeddb by id;
    // ref ones are in a guest's open tab: via says which tab (peer id). paths: path → id
    const items = new Map(), paths = new Map(), via = new Map(), notes = new Map(), peers = new Map(), db = idb(sess.slug);
    // the member registry: { id, secretHash, name, key, lastSeen }. this browser decides
    // who is who in its share; secrets and their hashes never leave it
    const members = new Map();
    const { id: myId, secretHash: mySecret } = await memberOf(await shareSecret(sess.slug));
    // recently deleted ids, so a guest coming back doesn't publish them again
    const TOMB = 'p2p:tomb:' + sess.slug, tomb = new Set(arr(store.get(TOMB)).filter(id => ITEM.test(id)));
    const unfp = [];
    const opened = await db.all('notes').then(() => null, e => e);
    if (opened && opened.blocked) return app.replaceChildren(el('h1', {}, el('a', { href: '/' }, 'p2p'), ' /' + sess.slug), el('p', { class: 'status' }, opened.message));
    try {
      for (const m of await db.all('members')) {
        const name = normName(m.name);
        if (name && MEMBER.test(m.id) && typeof m.secretHash === 'string') members.set(m.id, { id: m.id, secretHash: m.secretHash, name, key: nameKey(name), lastSeen: +m.lastSeen || 0 });
      }
      for (const r of await db.all('items')) {
        const path = clean(r.path);
        if (!path || !ITEM.test(r.id) || !r.blob) continue;
        const it = { id: r.id, path, size: r.blob.size, mtime: +r.mtime || 0, fp: HASH.test(r.fp) ? r.fp : null, owner: myId, kind: 'stored', off: 0 };
        items.set(it.id, it);
        paths.set(path, it.id);
        if (!it.fp) unfp.push([it, r.blob]);
      }
      for (const n of await db.all('notes')) if (typeof n.id === 'string' && typeof n.title === 'string' && typeof n.text === 'string') notes.set(n.id, { id: n.id, title: n.title, text: n.text, t: n.t, author: MEMBER.test(n.author) ? n.author : myId, editor: MEMBER.test(n.editor) ? n.editor : null });
    } catch {}
    const online = id => id === myId || [...peers.values()].some(p => p.member === id);
    const holds = id => [...items.values()].some(it => it.owner === id);
    // a name is held while its member is online, has things here, or was seen in the last 30 days
    const taken = (key, except) => [...members.values()].some(m => m.id !== except && m.key === key && (online(m.id) || holds(m.id) || Date.now() - m.lastSeen < RESERVE));
    // "alice" -> the first free of "alice-2", "alice-3", …
    const suggest = name => {
      for (let n = 2; ; n++) {
        const tail = '-' + n, c = [...name].slice(0, 24 - tail.length).join('') + tail;
        if (!taken(nameKey(c))) return c;
      }
    };
    const keepMember = m => db.put('members', m).catch(() => {});
    // members that are long gone and own nothing here: their names are free again
    for (const m of [...members.values()]) {
      const owns = holds(m.id) || [...notes.values()].some(n => n.author === m.id || n.editor === m.id);
      if (m.id !== myId && !owns && Date.now() - m.lastSeen > RESERVE) { members.delete(m.id); db.del('members', m.id).catch(() => {}); }
    }
    // the host is a member too. renaming yourself to a name a guest holds is refused
    let self = members.get(myId), selfMsg = '';
    {
      const want = myName(), key = nameKey(want);
      if (!self) self = { id: myId, secretHash: mySecret, name: taken(key, myId) ? suggest(want) : want, key: '', lastSeen: 0 };
      else if (taken(key, myId)) { if (self.key !== key) selfMsg = `"${want}" is taken in this share — you appear as ${self.name}`; }
      else self.name = want;
      self.key = nameKey(self.name);
      self.lastSeen = Date.now();
      members.set(myId, self);
      keepMember(self);
    }
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    const kp = await keypair().catch(() => null);
    if (location.pathname !== '/' + sess.slug) return; // navigated away while loading
    const unhold = hold();
    const persist = () => setHost(sess);
    const nameOf = id => (members.get(id) || {}).name || 'someone';

    // ---- what guests see, and changes to it
    // guests learn members' names and whether they're here; only people who are
    // online or have something in the share
    const pubMember = m => ({ id: m.id, name: m.name, online: online(m.id), offlineSince: online(m.id) ? 0 : m.lastSeen });
    const pubMembers = () => {
      const used = new Set([myId]);
      for (const it of items.values()) used.add(it.owner);
      for (const n of notes.values()) { used.add(n.author); used.add(n.editor); }
      return [...members.values()].filter(m => used.has(m.id) || online(m.id)).map(pubMember);
    };
    const pubItem = it => ({ id: it.id, path: it.path, size: it.size, mtime: it.mtime, fp: it.fp, owner: it.owner, kind: it.kind, off: it.off || 0 });
    let rev = 0, flushT = null;
    const D = { add: new Map(), up: new Map(), rm: new Set(), nup: new Map(), nrm: new Set(), mem: new Set(), mode: false };
    const snap = t => ({ t, v: 3, rev, mode: sess.mode, members: pubMembers(), items: [...items.values()].map(pubItem), notes: [...notes.values()], tomb: [...tomb] });
    // changes go out together, numbered, a moment after they happen
    function flush() {
      if (!D.add.size && !D.up.size && !D.rm.size && !D.nup.size && !D.nrm.size && !D.mem.size && !D.mode) return;
      rev++;
      const m = {
        t: 'delta', rev,
        items: { add: [...D.add.values()].map(pubItem), up: [...D.up.values()].map(pubItem), rm: [...D.rm] },
        notes: { up: [...D.nup.values()], rm: [...D.nrm] },
        members: { up: [...D.mem].map(id => members.get(id)).filter(Boolean).map(pubMember) },
      };
      if (D.mode) m.mode = sess.mode;
      D.add.clear(); D.up.clear(); D.rm.clear(); D.nup.clear(); D.nrm.clear(); D.mem.clear(); D.mode = false;
      const s = JSON.stringify(m);
      for (const p of peers.values()) if (p.member) tx(p.ctl, s);
    }
    let shown = false;
    // changes go out, and the page redraws, at most every 80 ms however many there are
    function dirty() {
      if (flushT) return;
      flushT = setTimeout(() => {
        flushT = null;
        flush();
        if (!shown) return;
        v.refresh();
        showPeople();
        kick(xfers);
      }, 80);
    }
    const putItem = it => { items.set(it.id, it); paths.set(it.path, it.id); D.rm.delete(it.id); D.add.set(it.id, it); dirty(); };
    const upItem = it => { if (!D.add.has(it.id)) D.up.set(it.id, it); dirty(); };
    const dropItem = id => {
      const it = items.get(id);
      if (!it) return;
      items.delete(id);
      via.delete(id);
      if (paths.get(it.path) === id) paths.delete(it.path);
      D.add.delete(id); D.up.delete(id); D.rm.add(id);
      dirty();
    };
    const memberChanged = id => { D.mem.add(id); dirty(); };
    const putNote = n => { notes.set(n.id, n); D.nrm.delete(n.id); D.nup.set(n.id, n); dirty(); };
    const dropNote = id => { notes.delete(id); D.nup.delete(id); D.nrm.add(id); dirty(); db.del('notes', id).catch(() => {}); };
    const bury = ids => {
      for (const id of ids) { tomb.delete(id); tomb.add(id); }
      for (const k of tomb) { if (tomb.size <= TOMB_MAX) break; tomb.delete(k); }
      store.set(TOMB, [...tomb]);
    };
    const peersOf = id => [...peers.values()].filter(p => p.member === id);

    // where added files go: their own path, unless someone else has something there:
    // then "report (bob).pdf", or for a folder added whole, "photos (bob)/…"
    function place(list, owner, dir) {
      // names can hold "/" or "\\": every candidate is cleaned before it is compared, so
      // a crafted name can never land on someone else's exact path
      const name = nameOf(owner).replace(/[\\/]/g, '_'), seen = new Map(paths), tried = new Map();
      const clash = p => { const id = seen.get(p), o = id && items.get(id); return id && (!o || o.owner !== owner); };
      const free = p => p && !seen.has(p) && ![...seen.keys()].some(k => k.startsWith(p + '/'));
      let from = null, to = null;
      if (dir && list.some(it => it.path.startsWith(dir + '/') && clash(it.path))) {
        for (let n = 1; n < 1000; n++) { to = clean(`${dir} (${name}${n > 1 ? ' ' + n : ''})`); if (free(to)) break; to = null; }
        if (to) from = dir;
      }
      return list.map(it => {
        let p = clean(from && it.path.startsWith(from + '/') ? to + it.path.slice(from.length) : it.path);
        if (p && clash(p)) {
          const i = p.lastIndexOf('/'), d = p.slice(0, i + 1), b = p.slice(i + 1), dot = b.lastIndexOf('.');
          const stem = dot > 0 ? b.slice(0, dot) : b, ext = dot > 0 ? b.slice(dot) : '', k = d + stem + '\n' + ext;
          // many of the same name in one batch: carry on counting, don't start over each time
          let c = null;
          for (let n = tried.get(k) || 1; n < 1e5; n++) { c = clean(`${d}${stem} (${name}${n > 1 ? ' ' + n : ''})${ext}`); if (c && !seen.has(c)) { tried.set(k, n + 1); break; } c = null; }
          p = c;
        }
        if (p) seen.set(p, '-' + owner); // later ones in the batch see it (not an item: always a clash for others)
        return p;
      });
    }

    // take items out of the share. stored: deleted from this browser. ref: the owner's
    // file stays on their disk; they're told. why: deleted (remembered, so it isn't
    // published again), one-way, replaced, gone (owner away too long / tab closed), pin
    function remove(list, by, why = 'deleted') {
      const owners = new Map(), gone = new Set(), stored = [], told = why === 'deleted' || why === 'one-way';
      for (const it of list) {
        if (!it || !items.has(it.id)) continue;
        dropItem(it.id);
        gone.add(it.id);
        if (it.kind === 'stored') stored.push(it.id);
        else if (told) { const o = owners.get(it.owner) || []; o.push(it.id); owners.set(it.owner, o); }
      }
      if (!gone.size) return;
      if (stored.length) db.delAll('items', stored).catch(() => {});
      if (told) bury(gone);
      stopFor(gone, why === 'one-way' ? 'the host switched to one-way' : 'removed from the share');
      for (const [owner, ids] of owners) for (const p of peersOf(owner)) p.c.send({ t: 'unshared', ids, by, why });
      showStorage();
    }
    // transfers of something that's gone: what the host forwards, and its own downloads
    function stopFor(ids, why) {
      for (const p of peers.values()) if (p.c) for (const s of [...p.c.serves.values()]) if (ids.has(s.id)) endServe(s, why);
      for (const x of [...xfers]) if (ids.has(x.id)) x.finish(new Error(why));
    }

    // ---- the host's own files: copied into this browser's storage
    async function addStored(list, sig, say, dir) {
      const total = list.reduce((s, it) => s + it.f.size, 0);
      const q = navigator.storage && navigator.storage.estimate && await navigator.storage.estimate().catch(() => null);
      if (q && q.quota - q.usage < total * 1.05) throw new Error(`not enough browser storage: ${size(total)} needed, ${size(Math.max(0, q.quota - q.usage))} free`);
      const where = place(list, myId, dir);
      let done = 0;
      try {
        // up to 500 files or 64 MB per transaction: thousands of small files copy quickly
        for (let k = 0; k < list.length;) {
          if (sig.aborted) throw sig.reason;
          const batch = [];
          for (let bytes = 0; k < list.length && batch.length < 500 && (!batch.length || bytes + list[k].f.size <= 64 << 20); k++) {
            const it = list[k], path = where[k];
            if (!path) continue;
            bytes += it.f.size;
            batch.push([it, { id: newId(), path, size: it.f.size, mtime: Number.isSafeInteger(it.f.lastModified) ? it.f.lastModified : Date.now(), fp: it.fp, owner: myId, kind: 'stored', off: 0 }]);
          }
          if (!batch.length) continue;
          say(list.length > 1 ? `↑ copying ${done + 1}/${list.length}…` : `↑ copying ${batch[0][0].rel}…`);
          await db.putAll('items', batch.map(([it, r]) => ({ id: r.id, path: r.path, mtime: r.mtime, fp: r.fp, blob: it.f })), sig);
          if (sig.aborted) { await Promise.all(batch.map(([, r]) => db.del('items', r.id).catch(() => {}))); throw sig.reason; }
          for (const [, rec] of batch) {
            // the same name of yours: the new one replaces it
            const old = items.get(paths.get(rec.path));
            if (old && old.owner === myId) remove([old], myId, 'replaced');
            putItem(rec);
            done++;
          }
        }
      } catch (e) {
        throw Object.assign(e instanceof Error ? e : new Error(String(e)), { done });
      } finally { showStorage(); }
      return { done };
    }
    // fingerprints for files stored before they existed (cheap: 2 MiB each)
    (async () => {
      for (const [it, blob] of unfp.splice(0)) {
        try {
          const fp = await fingerprint(blob);
          if (items.get(it.id) !== it) continue;
          it.fp = fp;
          await db.patch('items', it.id, r => ({ ...r, fp }));
          upItem(it);
        } catch {}
      }
    })();

    // ---- notes: anyone may edit or delete; the author stays, "edited by" shows who changed it
    function doNote(title, text, id, by) {
      const old = notes.get(id), n = mkNote(title, text, old ? id : null);
      if (!n) return;
      if (!old && (notes.size >= NOTES_MAX || (by !== myId && [...notes.values()].filter(x => x.author === by).length >= NOTES_PER))) return 'too many notes';
      n.author = old ? old.author : by;
      n.editor = n.author === by ? null : by;
      db.put('notes', n).catch(() => {});
      putNote(n);
    }

    // ---- downloads the host makes (from guests' tabs; its own are right here)
    const xfers = new Set();
    function route(x) {
      const it = items.get(x.id);
      if (!it) return { fail: 'not available any more', gone: true };
      const p = peers.get(via.get(it.id));
      if (it.off || !p || !p.c || !p.member) return { wait: nameOf(it.owner) };
      attempt(p.c, x);
      return true;
    }

    const src = {
      items, notes, members, verb: 'upload',
      me: () => myId,
      writable: () => true,
      hint: () => null,
      add: addStored,
      fetch: async (it, sink, prog, sig, waiting) => {
        if (it.kind === 'stored') {
          const r = await db.get('items', it.id);
          if (!r || !r.blob) throw new Error('not here any more');
          return pour(sink, r.blob, prog, sig);
        }
        return download(it, sink, prog, sig, waiting, route, xfers);
      },
      rm: ids => remove(ids.map(id => items.get(id)), myId),
      rmDir: path => remove([...items.values()].filter(it => it.path.startsWith(path + '/')), myId),
      note: (title, text, id) => doNote(title, text, id, myId),
      unnote: id => notes.has(id) && dropNote(id),
    };

    // ---- the page
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
    // one-way: only your things. whatever others shared goes (after asking, if there is any)
    function setMode(mode) {
      if (mode === 'ro') {
        remove([...items.values()].filter(it => it.owner !== myId), myId, 'one-way');
        for (const n of [...notes.values()]) if (n.author !== myId) dropNote(n.id);
      }
      sess.mode = mode;
      persist();
      showMode();
      D.mode = true;
      dirty();
    }
    const modeBtn = el('button', { onclick: () => {
      if (sess.mode === 'ro') return setMode('rw');
      const theirs = [...items.values()].filter(it => it.owner !== myId), tn = [...notes.values()].filter(n => n.author !== myId);
      if (!theirs.length && !tn.length) return setMode('ro');
      const who = [...new Set([...theirs.map(it => it.owner), ...tn.map(n => n.author)])].map(nameOf);
      const what = [theirs.length && `${theirs.length} file${theirs.length === 1 ? '' : 's'}`, tn.length && `${tn.length} note${tn.length === 1 ? '' : 's'}`].filter(Boolean).join(' and ');
      ask(modeBtn, `switch to one-way? this removes ${what} shared by ${who.join(', ')} — their downloads stop`, () => setMode('ro'));
    } });
    const showMode = () => {
      modeBtn.textContent = sess.mode === 'rw' ? 'two-way' : 'one-way';
      modeHint.textContent = sess.mode === 'rw' ? 'others can add, edit, download and delete' : 'others can only download and copy';
    };
    showMode();
    // everyone in the share, host first, then who is here, then who isn't
    const peopleEl = el('span', {});
    const showPeople = () => {
      const list = [...members.values()].filter(m => m.id === myId || Date.now() - m.lastSeen < RESERVE || online(m.id) || holds(m.id))
        .sort((a, b) => (b.id === myId) - (a.id === myId) || online(b.id) - online(a.id) || a.name.localeCompare(b.name));
      peopleEl.textContent = list.map(m => m.name + (m.id === myId ? ' (host)' : online(m.id) ? '' : ' (offline)')).join(' · ');
    };
    // how much of this browser's storage the share's files take
    const storageEl = el('span', {}, '…');
    let storageT;
    const showStorage = () => {
      clearTimeout(storageT);
      storageT = setTimeout(async () => {
        const q = navigator.storage && navigator.storage.estimate && await navigator.storage.estimate().catch(() => null);
        storageEl.textContent = q ? `${size(q.usage || 0)} used · ${size(Math.max(0, (q.quota || 0) - (q.usage || 0)))} free` : 'unknown';
      }, 300);
    };
    const showPeers = () => {
      showPeople();
      const open = [...peers.values()].filter(p => p.member), r = open.filter(p => p.ctl.relay).length;
      state.textContent = live ? `live · ${open.length} connected${r ? ` (${r} relayed)` : ''}` : 'reconnecting…';
    };

    const v = panel(src, say, status);
    app.replaceChildren(
      el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + sess.slug), state),
      el('p', { class: 'mute' }, `you: ${self.name}`),
      el('section', { class: 'panel' }, el('h2', {}, 'access'),
        el('div', { class: 'kv' },
          el('span', { class: 'mute' }, 'link'), el('span', { class: 'row' }, el('span', { class: 'url' }, link.replace(/^https?:\/\//, '')), el('button', { onclick: e => copy(link, e.target) }, 'copy'), qrBtn),
          el('span', { class: 'mute' }, 'pin'), el('span', { class: 'row' }, el('span', { class: 'grow' }, pinEl), pinBtn, el('button', { onclick: e => copy(sess.pin, e.target) }, 'copy'), el('button', { onclick: regen }, 'new pin')),
          el('span', { class: 'mute' }, 'mode'), el('span', { class: 'row' }, modeBtn, modeHint),
          el('span', { class: 'mute' }, 'people'), peopleEl,
          el('span', { class: 'mute' }, 'storage'), storageEl,
        ),
        qrBox,
        el('p', { class: 'mute' }, 'send the link and pin to someone. a new pin disconnects everyone. sharing stops when you close this tab and resumes when you reopen it. your files are kept in this browser; files others add stay on their computer and are only sent when someone gets them.' +
          (coarse() ? ' on a phone, keep this page open in front: browsers pause pages in the background.' : '')),
      ),
      ...v.els,
      v.foot,
      el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: e => ask(e.target, 'delete it all & free the name?', end) }, 'stop sharing & delete everything')),
    );
    view = v;
    shown = true;
    showPeople();
    showStorage();
    if (selfMsg) say(selfMsg);

    // owners who went away: their things wait GRACE, then go. checked by the clock
    // (background tabs slow timers down), now and then and whenever the page wakes
    const sweep = () => {
      const now = Date.now(), gone = [...items.values()].filter(it => it.off && now - it.off > grace());
      if (gone.length) remove(gone, null, 'gone');
    };
    const sweepT = setInterval(sweep, 15e3);
    wake.add(sweep);
    // closing the tab doesn't always close the connections with it: say so, so guests
    // know at once instead of when their connection times out
    const leaving = () => { for (const p of peers.values()) tx(p.ctl, { t: 'away' }); };
    addEventListener('pagehide', leaving);

    let live = false;
    const sig = signal(onSignal, () => sig.send({ t: 'host', slug: sess.slug, token: sess.token, pin: sess.pin }));
    cleanup = () => {
      announce('gone');
      hosting = null;
      sig.close();
      clearInterval(sweepT);
      wake.delete(sweep);
      removeEventListener('pagehide', leaving);
      clearTimeout(flushT);
      for (const x of [...xfers]) x.finish(new Error('closed'));
      for (const p of peers.values()) { try { p.pc.close(); } catch {} if (p.c) connClosed(p.c); }
      peers.clear();
      unhold();
    };
    sig.onbin = buf => {
      if (buf.byteLength <= 12) return;
      const p = peers.get(dec.decode(new Uint8Array(buf, 0, 12)));
      if (p && p.relay) p.relay.receive(buf.slice(12));
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
          for (const p of [...peers.values()]) if (p.relay) drop(p.id);
          return showPeers();
        case 'sig': return onPeerSig(m.from, m.data);
        case 'left': {
          const p = peers.get(m.id);
          if (p && (!p.open || p.relay)) drop(p.id);
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
        if (p.relay) return;
        if (data.d) {
          if (kp && typeof data.k === 'string') p.key = shared(kp, data.k).catch(() => null);
          await p.pc.setRemoteDescription(data.d);
          await p.pc.setLocalDescription(await p.pc.createAnswer());
          sig.send({ t: 'sig', to: id, data: { d: p.pc.localDescription, k: kp && kp.pub } });
        } else if (data.c) await p.pc.addIceCandidate(data.c);
      }).catch(() => {});
    }

    // hooks for one guest's connection: what the host hands out to it
    const hooksFor = p => ({
      // the host's own files, from this browser's storage
      resolve: async (c, id) => {
        const it = items.get(id);
        if (!it || it.kind !== 'stored') throw new Error('not found');
        const r = await db.get('items', id);
        if (!r || !r.blob) throw new Error('not found');
        return { blob: r.blob, size: r.blob.size, mtime: it.mtime };
      },
      // in another guest's tab: forwarded (the guests couldn't link directly)
      proxy: (c, s) => {
        const it = items.get(s.id);
        if (!it || it.kind !== 'ref') return false;
        const o = peers.get(via.get(it.id));
        if (sess.mode !== 'rw') endServe(s, 'not found');
        else if (it.owner === p.member) endServe(s, 'not found');
        else if (it.off || !o || !o.member || !o.c) endServe(s, 'offline');
        else proxyOpen(s, o.c, s.id);
        return true;
      },
    });
    function attachPeer(p, ctl, bin, max) {
      p.ctl = ctl;
      p.bin = bin;
      p.c = conn(ctl, bin, max, hooksFor(p));
      ctl.onmessage = ev => onPeerMsg(p, ev.data);
      bin.onmessage = ev => p.member && onFrame(p.c, ev.data);
      p.open = true;
      waitHello(p);
      showPeers();
    }
    function addPeer(id) {
      const pc = new RTCPeerConnection({ iceServers: sig.ice });
      const ch = chans(pc);
      const p = { id, pc, ctl: ch.ctl, bin: ch.bin, c: null, relay: null, open: false, member: null, q: Promise.resolve(), rx: {}, sigs: { n: 100, t: Date.now() } };
      pc.onicecandidate = e => e.candidate && sig.send({ t: 'sig', to: id, data: { c: e.candidate } });
      pc.onconnectionstatechange = () => p.pc === pc && (pc.connectionState === 'failed' || pc.connectionState === 'closed') && drop(id);
      bothOpen(ch).then(() => { if (peers.get(id) === p && p.pc === pc) attachPeer(p, ch.ctl, ch.bin, pc.sctp && pc.sctp.maxMessageSize); });
      ch.ctl.onclose = () => p.pc === pc && drop(id);
      peers.set(id, p);
      return p;
    }

    // the guest couldn't connect directly: switch this peer to the encrypted relay
    async function toRelay(p) {
      const key = !p.open && p.key && await p.key;
      if (!key || peers.get(p.id) !== p) return;
      const old = p.pc, idb = enc.encode(p.id);
      old.onconnectionstatechange = null;
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
      p.pc = { close: () => { ch.close(); if (ws) ws.close(); } };
      p.relay = ch;
      ch.onclose = () => drop(p.id);
      attachPeer(p, ch.ctl, ch.bin, RELAY_MAX);
      // the guest holds its frames until ours arrive (so nothing overtakes its relay
      // socket being set up): say something first, then wait for its hello
      tx(ch.ctl, { t: 'hi' });
    }

    // a separate socket per relayed guest, so one slow guest can't hold up
    // signaling or the others. resolves to null if it can't be set up.
    function pipe(id) {
      return new Promise(res => {
        const ws = new WebSocket(WS_URL());
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

    // tabs from before names can't say hello: tell them to reload
    const OUTDATED = 'this share was updated — reload the page';
    function outdated(p, why = OUTDATED) {
      p.outdated = true;
      tx(p.ctl, { t: 'err', e: why });
      setTimeout(() => drop(p.id), 300);
    }
    function waitHello(p) {
      clearTimeout(p.helloT);
      p.helloT = setTimeout(() => peers.get(p.id) === p && !p.member && outdated(p), 3000);
    }
    // hellos are handled one at a time, so two people can't take one name at once
    let helloQ = Promise.resolve();
    function hello(p, m) {
      if (p.member || p.hello || p.outdated) return;
      if (!(m.v >= 3)) return outdated(p);
      const name = normName(m.name), sec = typeof m.secret === 'string' && /^[\w-]{43}$/.test(m.secret) ? m.secret : null;
      if (!name || !sec) return outdated(p);
      p.hello = true;
      clearTimeout(p.helloT);
      const have = new Set(arr(m.have).slice(0, ITEMS_MAX).filter(id => typeof id === 'string' && ITEM.test(id)));
      helloQ = helloQ.then(async () => {
        const { id, secretHash } = await memberOf(sec), key = nameKey(name);
        if (peers.get(p.id) !== p) return;
        let mb = members.get(id);
        if (mb && mb.secretHash !== secretHash) return outdated(p); // (a 72-bit id clash: never in practice)
        if (id === myId) return outdated(p); // this browser is the host
        if (mb) {
          // known member: a new name is taken on if it's free, else the old one stays
          if (mb.key !== key && !taken(key, id)) { mb.name = name; mb.key = key; }
        } else if (taken(key)) {
          p.hello = false;
          waitHello(p);
          return tx(p.ctl, { t: 'name-taken', suggest: suggest(name) });
        } else if (members.size >= MEMBERS_MAX) return outdated(p, 'this share has too many people — ask the host for a new share');
        else members.set(id, mb = { id, secretHash, name, key, lastSeen: 0 });
        mb.lastSeen = Date.now();
        keepMember(mb);
        p.member = id;
        // back again: what this tab still holds comes back online; what no tab holds any more goes
        for (const it of [...items.values()]) {
          if (it.owner !== id || it.kind !== 'ref') continue;
          if (have.has(it.id)) { via.set(it.id, p.id); if (it.off) { it.off = 0; upItem(it); } continue; } // (even if its old connection isn't gone yet)
          const holder = peers.get(via.get(it.id));
          if (holder && holder !== p && holder.member) continue; // another tab of theirs has it
          remove([it], null, 'gone');
        }
        tx(p.ctl, { ...snap('welcome'), you: { id, name: mb.name } });
        memberChanged(id);
        showPeers();
      }).catch(() => {});
    }

    function drop(id) {
      const p = peers.get(id);
      if (!p) return;
      peers.delete(id);
      clearTimeout(p.helloT);
      try { p.pc.close(); } catch {}
      if (p.c) connClosed(p.c);
      // what that tab held is offline now: kept GRACE, in case it comes back
      const now = Date.now();
      for (const [iid, pid] of via) if (pid === id) { const it = items.get(iid); if (it && !it.off) { it.off = now; upItem(it); } }
      const mb = p.member && members.get(p.member);
      if (mb && !online(mb.id)) { mb.lastSeen = now; keepMember(mb); memberChanged(mb.id); }
      showPeers();
    }

    // token bucket for link signaling: 50 a second, bursts of 100
    const sigOk = p => {
      const now = Date.now(), b = p.sigs;
      b.n = Math.min(100, b.n + (now - b.t) / 20);
      b.t = now;
      return --b.n >= 0;
    };

    // everything a guest sends is untrusted
    function onPeerMsg(p, data) {
      const m = rx(p.rx, data);
      if (!m) return;
      if (m.t === 'hello') return hello(p, m);
      if (!p.member) return; // nothing else before we know who this is
      if (xmsg(p.c, m)) return;
      const rw = sess.mode === 'rw';
      switch (m.t) {
        case 'sync': // one at a time: a guest asking in a loop gets no more than it can read
          if (p.ctl.txn) return;
          return tx(p.ctl, snap('snap'));
        case 'away': return drop(p.id); // its tab is closing
        case 'add': {
          if (!rw) return tx(p.ctl, { t: 'added', no: arr(m.items).map(x => x && x.id).filter(id => ITEM.test(id)).slice(0, ITEMS_MAX) });
          const ok = [], no = [];
          let count = [...items.values()].filter(it => it.owner === p.member).length;
          const all = arr(m.items);
          for (const x of all.slice(ITEMS_MAX)) if (x && ITEM.test(x.id)) no.push(x.id);
          for (const x of all.slice(0, ITEMS_MAX)) {
            if (!x || !ITEM.test(x.id)) continue;
            const path = clean(x.path), cur = items.get(x.id);
            if (!path || !Number.isSafeInteger(x.size) || x.size < 0 || (x.fp != null && !HASH.test(x.fp)) || tomb.has(x.id) || (cur && cur.owner !== p.member) || (!cur && count >= ITEMS_MAX)) { no.push(x.id); continue; }
            if (!cur) count++;
            ok.push({ id: x.id, path, size: x.size, mtime: Number.isSafeInteger(x.mtime) ? x.mtime : 0, fp: x.fp || null });
          }
          const where = place(ok, p.member, typeof m.dir === 'string' ? clean(m.dir) : null);
          ok.forEach((x, k) => {
            const path = where[k];
            if (!path) return no.push(x.id);
            // the same name of theirs: the new one replaces it
            const old = items.get(paths.get(path));
            if (old && old.id !== x.id && old.owner === p.member) remove([old], p.member, 'replaced');
            const cur = items.get(x.id);
            if (cur && cur.path !== path && paths.get(cur.path) === cur.id) paths.delete(cur.path);
            via.set(x.id, p.id);
            putItem({ ...x, path, owner: p.member, kind: 'ref', off: 0 });
          });
          return tx(p.ctl, { t: 'added', no });
        }
        case 'rm': {
          if (!rw) return;
          let list = [];
          if (Array.isArray(m.ids)) list = m.ids.slice(0, ITEMS_MAX).map(id => typeof id === 'string' && items.get(id));
          else {
            const path = clean(m.path);
            if (path && m.dir === true) list = [...items.values()].filter(it => it.path.startsWith(path + '/'));
            else if (path) list = [items.get(paths.get(path))];
          }
          return remove(list, p.member);
        }
        case 'note': {
          if (!rw) return;
          const e = doNote(m.title, m.text, typeof m.id === 'string' ? m.id : null, p.member);
          if (e) tx(p.ctl, { t: 'err', e });
          return;
        }
        case 'unnote': return rw && typeof m.id === 'string' && notes.has(m.id) && dropNote(m.id);
        // link signaling between two guests, only through here: the host vouches for both ends
        case 'peer-sig': {
          if (!rw || !MEMBER.test(m.to) || m.to === p.member || !m.data || typeof m.data !== 'object' || !sigOk(p)) return;
          if (JSON.stringify(m.data).length > 32e3) return;
          const to = peersOf(m.to).pop();
          if (to) tx(to.ctl, { t: 'peer-sig', from: p.member, data: m.data });
          return;
        }
      }
    }

    function kickAll(why) {
      for (const p of peers.values()) {
        tx(p.ctl, { t: 'bye', why });
        setTimeout(() => drop(p.id), 300);
      }
    }
    // a new pin: everyone is out, and what they shared goes at once (their notes stay)
    function regen() {
      sess.pin = newPin();
      persist();
      showPin();
      remove([...items.values()].filter(it => it.kind === 'ref'), null, 'pin');
      sig.send({ t: 'pin', pin: sess.pin });
      kickAll('revoked');
    }
    onKill = end;
    async function end() {
      kickAll('ended');
      sig.send({ t: 'end' });
      delHost(sess.slug);
      store.del(TOMB);
      await db.clear().catch(() => {});
      setTimeout(() => nav('/'), 400);
    }
  }

  // ---- guest --------------------------------------------------------------

  function guest(slug) {
    document.title = slug + ' · p2p';
    const key = 'p2p:g:' + slug;
    const items = new Map(), notes = new Map(), members = new Map();
    // what this tab shares (two-way): id → { f: File, meta }. only ever in this tab
    const mine = new Map();
    // downloads outlive a dropped connection and carry on from where they got to on
    // the next one; notes and deletes made meanwhile wait in the outbox
    const xfers = new Set(), outbox = [];
    // p2p:g:<slug> = { pin, name } (name: only when it differs from your usual one).
    // older versions stored just the pin
    const kept = store.get(key);
    let pin = typeof kept === 'string' ? kept : kept && typeof kept.pin === 'string' ? kept.pin : null;
    let myname = (kept && normName(kept.name)) || myName(), myId = null, secret = null;
    const remember = () => store.set(key, myname === myName() ? { pin } : { pin, name: myname });
    let mode = 'ro', sig = null, pc = null, ctl = null, hostC = null, rxs = {}, timer = null, v = null, ice = [], rev = 0;
    let ready = false, retrying = false, relayed = false;
    const unhold = hold();

    const state = el('span', { class: 'mute' });
    const status = el('p', { class: 'status' });
    const say = t => { status.textContent = t; };
    const head = el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + slug), state);

    // keep: a reconnect follows, so downloads and the outbox wait for it
    function teardown(keep) {
      clearTimeout(timer);
      ready = retrying = false;
      const s = sig, p = pc, c = hostC;
      sig = pc = ctl = hostC = null;
      if (s) s.close();
      if (p) p.close();
      if (c) connClosed(c);
      rxs = {};
      if (keep) return;
      for (const x of [...xfers]) x.finish(new Error('disconnected'));
      outbox.length = 0;
      closeLinks();
    }
    const quit = () => { teardown(); mine.clear(); unhold(); wake.delete(onWake); clearInterval(linkT); removeEventListener('pagehide', leaving); };
    // closing the tab doesn't always close the connection with it: say so, so the host
    // marks our files offline at once instead of when the connection times out
    const leaving = () => tx(ctl, { t: 'away' });
    addEventListener('pagehide', leaving);
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
      secret = await shareSecret(slug).catch(() => null);
      if (cleanup !== quit) return; // navigated away
      if (pin) return connect();
      app.replaceChildren(head, status);
      const s = await peek(slug);
      if (cleanup !== quit) return; // navigated away
      if (!s.exists) return missing();
      form(s.live ? '' : `the owner of /${slug} is offline right now. you can still enter the pin; you'll connect when they're back.`);
    }

    // keepPin: back here only to pick another name, so the pin is still good
    function form(msg, suggest, keepPin) {
      teardown();
      view = v = null;
      dropTo = pasteTo = null;
      state.textContent = '';
      const input = el('input', { class: 'big', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', placeholder: '•••••••', 'aria-label': 'pin', value: keepPin && pin || '' });
      // people who open a link never see the home page: this is where they pick a name
      const nameIn = el('input', { class: 'name', value: suggest || myname, placeholder: me().rand, maxlength: '64', autocomplete: 'nickname', spellcheck: 'false', 'aria-label': 'your name' });
      const submit = () => {
        const val = input.value.replace(/\D/g, '');
        const nm = nameIn.value.trim() ? normName(nameIn.value) : me().rand;
        if (!nm) return say('names are 1–24 characters');
        if (val.length !== 7) return say('the pin has 7 digits');
        pin = val;
        myname = nm;
        connect();
      };
      input.addEventListener('input', () => { input.value = input.value.replace(/\D/g, '').slice(0, 7); if (input.value.length === 7 && !suggest) submit(); });
      app.replaceChildren(head,
        el('section', { class: 'panel' }, el('h2', {}, 'enter pin'),
          el('form', { class: 'row', onsubmit: e => { e.preventDefault(); submit(); } },
            el('div', { class: 'row grow' }, el('span', { class: 'mute' }, 'name'), nameIn), input, el('button', { type: 'submit' }, 'open')),
          el('p', { class: 'mute' }, 'ask the person sharing /' + slug + ' for their 7-digit pin.')),
        status);
      say(msg || '');
      (suggest ? nameIn : input).focus();
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
      const s = sig = signal(m => sig === s && onSignal(m), () => { ice = s.ice; s.send({ t: 'join', slug, pin }); });
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
        case 'down': if (ctl && ctl.relay) wait('connection lost — reconnecting…', 1000); return;
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

    // the connection to the host: two channels, then hello
    function opened(c, b, max) {
      ctl = c;
      hostC = conn(c, b, max, hooks);
      c.onmessage = e => onMsg(e.data);
      b.onmessage = e => hostC && onFrame(hostC, e.data);
      tx(ctl, { t: 'hello', v: 3, name: myname, secret, have: [...mine.keys()].slice(0, ITEMS_MAX) });
    }
    async function startRtc() {
      if (pc) pc.close();
      const s = sig, kp = await keypair().catch(() => null);
      if (sig !== s || !s) return;
      const p = pc = new RTCPeerConnection({ iceServers: s.ice });
      p.q = Promise.resolve();
      p.kp = kp;
      const ch = chans(p);
      p.onicecandidate = e => e.candidate && sig && sig.send({ t: 'sig', data: { c: e.candidate } });
      let isOpen = false;
      const lost = p.lost = () => pc === p && (isOpen ? wait('connection lost — reconnecting…', 1000) : toRelay(p));
      // after 6s use the relay (2.5s if the last connection needed it too), unless a direct
      // (or turn) path was already found and is just finishing its handshake: then give it up to 15s in total
      const late = () => pc === p && !isOpen && toRelay(p);
      setTimeout(() => /^(connected|completed)$/.test(p.iceConnectionState) ? setTimeout(late, 9000) : late(), relayed ? 2500 : 6000);
      // a path that stays down for 6s rarely comes back by itself: reconnect, transfers resume
      p.onconnectionstatechange = p.oniceconnectionstatechange = () => {
        const st = p.connectionState || p.iceConnectionState;
        clearTimeout(p.down);
        if (st === 'failed') lost();
        else if (st === 'disconnected' && isOpen) p.down = setTimeout(() => /^(disconnected|failed)$/.test(p.connectionState || p.iceConnectionState) && lost(), 6000);
      };
      bothOpen(ch).then(() => {
        if (pc !== p) return;
        isOpen = true;
        relayed = false;
        clearTimeout(timer);
        if (sig) { sig.close(); sig = null; } // direct from here on
        opened(ch.ctl, ch.bin, p.sctp && p.sctp.maxMessageSize);
      });
      ch.ctl.onclose = lost;
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
      pc = { close: () => ch.close() };
      relayed = true;
      p.close();
      ch.onclose = () => ctl === ch.ctl && wait('connection lost — reconnecting…', 1000);
      s.onbin = buf => {
        if (held) { for (const m of held) s.bin(m); held = null; }
        ch.receive(buf);
      };
      s.send({ t: 'sig', data: { relay: 1 } });
      clearTimeout(timer);
      opened(ch.ctl, ch.bin, RELAY_MAX);
    }

    // ---- the listing: a snapshot, then numbered changes
    const okItem = x => x && ITEM.test(x.id) && clean(x.path) === x.path && Number.isSafeInteger(x.size) && x.size >= 0 && MEMBER.test(x.owner)
      && { id: x.id, path: x.path, size: x.size, mtime: Number.isSafeInteger(x.mtime) ? x.mtime : 0, fp: HASH.test(x.fp) ? x.fp : null, owner: x.owner, kind: x.kind === 'stored' ? 'stored' : 'ref', off: Number.isSafeInteger(x.off) && x.off > 0 ? x.off : 0 };
    const okNote = x => x && typeof x.id === 'string' && x.id.length <= 32 && typeof x.title === 'string' && typeof x.text === 'string' && x.text.length <= NOTE_MAX
      && { id: x.id, title: x.title.slice(0, TITLE_MAX), text: x.text, t: +x.t || 0, author: MEMBER.test(x.author) ? x.author : null, editor: MEMBER.test(x.editor) ? x.editor : null };
    const okMember = x => { const nm = x && normName(x.name); return nm && MEMBER.test(x.id) && { id: x.id, name: nm, online: !!x.online, offlineSince: +x.offlineSince || 0 }; };
    const nameOf = id => id === myId ? 'you' : (members.get(id) || {}).name || 'someone';
    function setMode(m) {
      const was = mode;
      mode = m === 'rw' ? 'rw' : 'ro';
      if (mode === 'ro' && mine.size) {
        // the host is not on our direct links, so we stop serving ourselves
        mine.clear();
        if (was === 'rw') say('the host switched to one-way — your shared files were removed');
      }
      if (mode === 'ro') closeLinks();
    }
    function snapshot(m) {
      members.clear();
      for (const x of arr(m.members)) { const o = okMember(x); if (o) members.set(o.id, o); }
      items.clear();
      for (const x of arr(m.items)) { const o = okItem(x); if (o) items.set(o.id, o); }
      notes.clear();
      for (const x of arr(m.notes)) { const o = okNote(x); if (o) notes.set(o.id, o); }
      rev = Number.isSafeInteger(m.rev) ? m.rev : 0;
      for (const id of arr(m.tomb)) mine.delete(id);
      setMode(m.mode);
      // ours that the host doesn't list any more (it dropped them while we were away): again
      const again = [...mine].filter(([id]) => !items.has(id)).map(([, x]) => x.meta);
      if (again.length && mode === 'rw') post({ t: 'add', items: again });
    }
    function delta(m) {
      if (m.rev !== rev + 1) { if (m.rev > rev) tx(ctl, { t: 'sync' }); return; } // missed one: start over from a snapshot
      rev = m.rev;
      const it = m.items || {}, nt = m.notes || {}, mb = m.members || {};
      for (const x of [...arr(it.add), ...arr(it.up)]) { const o = okItem(x); if (o) items.set(o.id, o); }
      for (const id of arr(it.rm)) items.delete(id);
      for (const x of arr(nt.up)) { const o = okNote(x); if (o) notes.set(o.id, o); }
      for (const id of arr(nt.rm)) notes.delete(id);
      for (const x of arr(mb.up)) { const o = okMember(x); if (o) members.set(o.id, o); }
      if (m.mode) setMode(m.mode);
    }
    function showState() {
      state.textContent = `connected as ${myname} · ` + (mode === 'rw' ? 'two-way' : 'one-way') + (ctl && ctl.relay ? ' · relayed' : '');
    }

    function onMsg(data) {
      const m = rx(rxs, data);
      if (!m) return;
      if (ready && xmsg(hostC, m)) return;
      switch (m.t) {
        case 'name-taken': {
          const taken = myname, sug = normName(m.suggest);
          return form(`"${taken}" is taken in this share — pick another name`, sug || '', true);
        }
        case 'welcome':
          if (!m.you || !MEMBER.test(m.you.id)) return;
          myId = m.you.id;
          myname = normName(m.you.name) || myname;
          remember();
          // first listing on this connection: carry on with whatever was going before
          ready = true;
          snapshot(m);
          show();
          showState();
          for (const o of outbox.splice(0)) tx(ctl, o);
          kick(xfers);
          return redraw();
        case 'snap':
          if (!ready) return;
          snapshot(m);
          showState();
          kick(xfers);
          return redraw();
        case 'delta':
          if (!ready) return;
          delta(m);
          showState();
          kick(xfers);
          return redraw();
        case 'added':
          for (const id of arr(m.no)) mine.delete(id);
          if (arr(m.no).length) say(`${arr(m.no).length} file${arr(m.no).length === 1 ? '' : 's'} could not be shared`);
          return redraw();
        // taken out of the share by someone (our file on disk is untouched)
        case 'unshared': {
          const ids = arr(m.ids).filter(id => mine.has(id)), gone = new Set(ids);
          for (const id of ids) mine.delete(id);
          for (const c of [hostC, ...[...links.values()].map(l => l.c)]) if (c) for (const s of [...c.serves.values()]) if (m.why === 'one-way' || gone.has(s.id)) endServe(s, 'removed from the share');
          if (m.why === 'one-way') { mine.clear(); closeLinks(); say('the host switched to one-way — your shared files were removed'); }
          else if (ids.length && m.by !== myId) {
            const it = items.get(ids[0]);
            say(`${nameOf(m.by)} removed ${ids.length > 1 ? ids.length + ' of your files' : it ? it.path.split('/').pop() : 'a file of yours'}`);
          }
          return redraw();
        }
        case 'peer-sig': return onPeerSig(m.from, m.data);
        case 'err':
          say('error: ' + String(m.e).slice(0, 100));
          return;
        case 'bye':
          store.del(key);
          return form(m.why === 'ended' ? 'this share has ended' : 'access was revoked — ask for the new pin');
        case 'away': return wait(`the owner of /${slug} closed the share — waiting for them…`, 5000);
      }
    }

    // a burst of changes redraws the page once
    let redrawT = null;
    const redraw = () => { if (!redrawT) redrawT = setTimeout(() => { redrawT = null; if (v) v.refresh(); }, 30); };
    // notes and deletes made while reconnecting go out once connected again
    function post(m) {
      if (ready && ctl && ctl.readyState === 'open') return tx(ctl, m);
      if (outbox.length < 100) outbox.push(m);
      say('not connected — will send when reconnected');
    }

    // ---- serving our own files: to the host, and over links to other guests
    const hooks = {
      resolve: async (c, id) => {
        const it = items.get(id), x = mine.get(id);
        if (mode !== 'rw' || !x || !it || it.owner !== myId) throw new Error('not found');
        return { blob: x.f, size: x.f.size, mtime: it.mtime };
      },
      // moved or changed on disk: it can't be served any more
      gone: id => {
        const it = items.get(id);
        if (!mine.delete(id)) return;
        post({ t: 'rm', ids: [id] });
        say(`${it ? it.path.split('/').pop() : 'a file'} changed or moved on your computer — removed from the share`);
      },
    };

    // ---- direct links to other guests, set up through the host
    // (perfect negotiation: the lower member id is the polite side and gives way when
    // both dial at once). opened on demand, closed when idle
    const links = new Map(), noDirect = new Map();
    function killLink(l) {
      if (l.dead) return;
      l.dead = true;
      if (links.get(l.id) === l) links.delete(l.id);
      try { l.pc.close(); } catch {}
      if (l.c) connClosed(l.c);
    }
    function closeLinks() { for (const l of [...links.values()]) killLink(l); }
    const idleLink = l => !l.c || (!l.c.pulls.size && !l.c.serves.size);
    const linkT = setInterval(() => { for (const l of [...links.values()]) if (idleLink(l) && Date.now() - (l.c ? l.c.used : l.born) > LINK_IDLE) killLink(l); }, 3e4);
    const sendSig = (to, data) => ready && tx(ctl, { t: 'peer-sig', to, data });
    function getLink(id, passive) {
      let l = links.get(id);
      if (l && !l.dead) return l;
      if (links.size >= LINKS_MAX) {
        const old = [...links.values()].filter(idleLink).sort((a, b) => (a.c ? a.c.used : a.born) - (b.c ? b.c.used : b.born))[0];
        if (!old) return null;
        killLink(old);
      }
      const pc = new RTCPeerConnection({ iceServers: ice }), ch = chans(pc);
      l = { id, pc, polite: myId < id, making: false, ignore: false, open: false, dead: false, c: null, q: Promise.resolve(), born: Date.now(), rx: {}, passive };
      l.ready = bothOpen(ch).then(() => {
        if (l.dead) return false;
        l.open = true;
        l.c = conn(ch.ctl, ch.bin, pc.sctp && pc.sctp.maxMessageSize, hooks);
        return true;
      });
      // only transfers on a link; nothing else is listened to
      ch.ctl.onmessage = e => { const m = l.c && rx(l.rx, e.data); if (m) xmsg(l.c, m); };
      ch.bin.onmessage = e => l.c && onFrame(l.c, e.data);
      ch.ctl.onclose = () => killLink(l);
      pc.onicecandidate = e => e.candidate && sendSig(id, { c: e.candidate });
      pc.onnegotiationneeded = async () => {
        if (l.passive || pc.signalingState !== 'stable') return; // the other side's offer covers it
        try { l.making = true; await pc.setLocalDescription(); sendSig(id, { d: pc.localDescription }); } catch {} finally { l.making = false; }
      };
      pc.onconnectionstatechange = () => /^(failed|closed)$/.test(pc.connectionState) && killLink(l);
      links.set(id, l);
      return l;
    }
    function onPeerSig(from, data) {
      if (!MEMBER.test(from) || from === myId || !data || typeof data !== 'object' || mode !== 'rw') return;
      let l = links.get(from);
      if (!l || l.dead) {
        if (!data.d || data.d.type !== 'offer') return;
        if (!mine.size) return; // nothing of ours to fetch: no reason to show our addresses
        l = getLink(from, true);
        if (!l) return; // too many links: they'll go through the host
      }
      l.q = l.q.then(async () => {
        if (data.d) {
          const d = data.d;
          if (!/^(offer|answer)$/.test(d.type) || typeof d.sdp !== 'string' || d.sdp.length > 3e4) return;
          const collision = d.type === 'offer' && (l.making || l.pc.signalingState !== 'stable');
          l.ignore = !l.polite && collision;
          if (l.ignore) return;
          await l.pc.setRemoteDescription({ type: d.type, sdp: d.sdp });
          if (d.type === 'offer') { await l.pc.setLocalDescription(); sendSig(from, { d: l.pc.localDescription }); }
        } else if (data.c && typeof data.c === 'object') {
          try { await l.pc.addIceCandidate(data.c); } catch (e) { if (!l.ignore) throw e; }
        }
      }).catch(() => {});
    }
    // a link to an owner, if one opens within DIRECT_WAIT; else null (go through the host).
    // after a failure, the host route is used for a while before trying direct again
    async function viaLink(owner) {
      if (mode !== 'rw' || (noDirect.get(owner) || 0) > Date.now()) return null;
      const l = getLink(owner);
      if (!l) return null;
      if (l.open) return l;
      const ok = await Promise.race([l.ready, new Promise(r => setTimeout(() => r(false), DIRECT_WAIT))]);
      if (ok && l.open && !l.dead) return l;
      noDirect.set(owner, Date.now() + 2 * 6e4);
      killLink(l);
      return null;
    }

    // ---- downloads: the host's files from the host; another guest's directly, or through the host
    async function route(x) {
      const it = items.get(x.id);
      if (!ready || !hostC) return { wait: '' };
      if (!it) return { fail: 'not available any more', gone: true };
      if (it.off) return { wait: nameOf(it.owner) };
      if (it.kind === 'ref' && it.owner !== myId) {
        const l = await viaLink(it.owner);
        if (!xfers.has(x)) return true;
        if (l && l.c) { attempt(l.c, x); return true; }
        if (!ready || !hostC) return { wait: '' };
      }
      attempt(hostC, x);
      return true;
    }

    const src = {
      items, notes, members, verb: 'share',
      me: () => myId,
      writable: () => mode === 'rw',
      hint: () => mine.size ? 'your files are shared from this tab — keep it open' : null,
      // two-way: only names and sizes go to the host; the bytes stay here until someone gets them
      add: async (list, sig, say, dir) => {
        const out = list.map(it => ({ id: newId(), path: it.path, size: it.f.size, mtime: Number.isSafeInteger(it.f.lastModified) ? it.f.lastModified : Date.now(), fp: it.fp }));
        const own = new Map();
        for (const it of items.values()) if (it.owner === myId) own.set(it.path, it.id);
        for (const o of out) if (own.has(o.path)) mine.delete(own.get(o.path)); // replaced
        out.forEach((o, k) => mine.set(o.id, { f: list[k].f, meta: o }));
        post({ t: 'add', items: out, dir: dir || undefined });
        v.refresh();
        return { done: out.length };
      },
      fetch: (it, sink, prog, sig, waiting) => {
        const x = mine.get(it.id);
        if (x && it.owner === myId) return pour(sink, x.f, prog, sig);
        return download(it, sink, prog, sig, waiting, route, xfers);
      },
      rm: ids => { for (const id of ids) mine.delete(id); post({ t: 'rm', ids }); },
      rmDir: path => post({ t: 'rm', path, dir: true }),
      note: async (title, text, id) => post({ t: 'note', title, text, id }),
      unnote: async id => post({ t: 'unnote', id }),
    };

    function show() {
      if (v) return v.refresh();
      v = view = panel(src, say, status);
      app.replaceChildren(head, ...v.els, v.foot,
        el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: () => { store.del(key); mine.clear(); form('disconnected'); } }, 'disconnect')));
      say('');
    }

    start();
  }

  // ---- routing ------------------------------------------------------------

  let current = null;
  function route(msg) {
    if (view && view.stop) view.stop();
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

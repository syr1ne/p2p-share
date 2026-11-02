'use strict';
// p2p: files, folders and notes go browser to browser over an encrypted webrtc
// data channel. the server only checks the pin and relays the handshake.
(() => {
  const SLUG = /^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$/;
  const ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
  const LOW = 1 << 20, HIGH = 4 << 20, PART = 8000;
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
  const isDark = () => document.documentElement.dataset.theme ? document.documentElement.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  function setTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    themeBtn.textContent = isDark() ? 'light' : 'dark';
  }
  setTheme(store.get('p2p:theme'));
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
  // big transfers: fold received chunks into a blob every 64 MB so the
  // browser can page them to disk instead of holding everything in ram
  function collect(t, buf) {
    t.parts.push(buf);
    t.mem = (t.mem || 0) + buf.byteLength;
    if (t.mem < 64 << 20) return;
    t.parts = [new Blob(t.parts)];
    t.mem = 0;
  }
  // small confirm bubble beside a button, instead of a browser dialog
  function ask(btn, question, yes) {
    document.querySelectorAll('.pop').forEach(p => p.remove());
    const close = () => {
      pop.remove();
      removeEventListener('pointerdown', outside, true);
      removeEventListener('keydown', esc);
    };
    const outside = e => !pop.contains(e.target) && close();
    const esc = e => e.key === 'Escape' && close();
    const no = el('button', { class: 'link', onclick: close }, 'no');
    const pop = el('span', { class: 'pop', role: 'alertdialog' }, question,
      el('button', { onclick: () => { close(); yes(); } }, 'yes'), no);
    btn.parentElement.append(pop);
    addEventListener('pointerdown', outside, true);
    addEventListener('keydown', esc);
    no.focus();
  }
  function save(blob, name) {
    const u = URL.createObjectURL(blob);
    const a = el('a', { href: u, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 6e4);
  }

  // ---- storage (survives reloads) -------------------------------------------

  // shares this browser owns: { slug: { slug, token, pin, mode } }
  function hosts() {
    const h = store.get('p2p:hosts') || {};
    const old = store.get('p2p:host'); // v1 kept a single share
    if (old && old.slug) { h[old.slug] = old; store.set('p2p:hosts', h); store.del('p2p:host'); }
    return h;
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
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k.startsWith('p2p:g:')) out.push(k.slice(6)); } } catch {}
    return out.sort();
  };

  // indexeddb, keyed [share, path] / [share, note id]
  const idb = (() => {
    let p;
    const open = () => p || (p = new Promise((res, rej) => {
      const r = indexedDB.open('p2p', 2);
      r.onupgradeneeded = e => {
        const d = r.result, t = r.transaction;
        const make = () => {
          d.createObjectStore('files', { keyPath: ['slug', 'path'] });
          d.createObjectStore('notes', { keyPath: ['slug', 'id'] });
        };
        if (e.oldVersion < 1) return make();
        // v1 held one share's data: move it under that share's name
        const slug = Object.keys(hosts())[0];
        const fq = t.objectStore('files').getAll(), nq = t.objectStore('notes').getAll();
        nq.onsuccess = () => {
          const files = fq.result, notes = nq.result;
          d.deleteObjectStore('files');
          d.deleteObjectStore('notes');
          make();
          if (!slug) return;
          for (const f of files) t.objectStore('files').put({ ...f, slug });
          for (const n of notes) t.objectStore('notes').put({ ...n, slug });
        };
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
  const drain = dc => new Promise(r => {
    if (dc.relay) {
      const t = setInterval(() => { if (dc.readyState !== 'open' || dc.bufferedAmount < LOW) { clearInterval(t); r(); } }, 25);
      return;
    }
    const f = () => { dc.removeEventListener('bufferedamountlow', f); dc.removeEventListener('close', f); r(); };
    dc.addEventListener('bufferedamountlow', f);
    dc.addEventListener('close', f);
  });
  async function stream(pc, dc, req, blob, prog, stop) {
    const n = Math.min(65536, (pc.sctp && pc.sctp.maxMessageSize) || 16384) - 4;
    for (let o = 0; o < blob.size; o += n) {
      if (dc.readyState !== 'open') throw new Error('disconnected');
      if (stop && stop()) return;
      if (dc.bufferedAmount > HIGH) await drain(dc);
      const chunk = new Uint8Array(await blob.slice(o, o + n).arrayBuffer());
      const buf = new Uint8Array(chunk.length + 4);
      new DataView(buf.buffer).setUint32(0, req);
      buf.set(chunk, 4);
      dc.send(buf);
      if (prog) prog(Math.min(o + n, blob.size));
    }
  }

  // ---- relay ---------------------------------------------------------------
  // fallback for when the browsers can't reach each other directly: frames go
  // through the signaling server, end-to-end encrypted with aes-gcm under a key
  // from an ecdh exchange done during the handshake. the server only sees
  // ciphertext. quacks like an RTCDataChannel so the rest of the code doesn't care.

  const subtle = window.crypto && crypto.subtle;
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  const RELAY_PC = { sctp: { maxMessageSize: 32768 } };
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
    let ws, stop = false, delay = 1000;
    const api = {
      ice: [],
      onbin: null,
      send: m => ws && ws.readyState === 1 && ws.send(JSON.stringify(m)),
      bin: b => ws && ws.readyState === 1 && ws.send(b),
      buffered: () => ws ? ws.bufferedAmount : 0,
      close: () => { stop = true; if (ws) ws.close(); },
    };
    (function connect() {
      ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
      ws.binaryType = 'arraybuffer';
      ws.onmessage = e => {
        if (typeof e.data !== 'string') return api.onbin && api.onbin(e.data);
        let m;
        try { m = JSON.parse(e.data); } catch { return; }
        if (!m || typeof m.t !== 'string') return;
        if (m.t !== 'hi') return onmsg(m);
        delay = 1000;
        api.ice = arr(m.ice);
        onopen();
      };
      ws.onclose = () => {
        if (stop) return;
        onmsg({ t: 'down' });
        setTimeout(connect, delay);
        delay = Math.min(delay * 1.6, 15000);
      };
    })();
    return api;
  }

  // ---- the panel: notes + files, shared by host and guest -----------------
  // src: { files, notes, writable(), get(path, prog), put(blob, path, mtime, prog), rm(path, dir), note(title, text, id), unnote(id) }

  let dropTo = null;
  function panel(src, status) {
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
    const tools = el('span', { class: 'row' }, el('label', { class: 'btn', tabindex: '0' }, '+ files', fileIn), el('label', { class: 'btn', tabindex: '0' }, '+ folder', dirIn));

    const cwd = () => { try { return clean(decodeURIComponent(location.hash.slice(1))) || ''; } catch { return ''; } };
    const cd = p => { location.hash = p ? encodeURIComponent(p).replace(/%2F/g, '/') : ''; };
    const fail = e => status('error: ' + (e && e.message || e));

    // one upload batch at a time, into the folder that was open when it was added
    let queue = Promise.resolve();
    function upload(items) {
      if (!src.writable() || !items.length) return;
      const base = cwd() ? cwd() + '/' : '';
      queue = queue.then(() => send(items, base));
    }
    async function send(items, base) {
      let i = 0;
      try {
        for (const [f, rel] of items) {
          const p = clean(base + rel);
          if (!p) continue;
          i++;
          await src.put(f, p, f.lastModified, b => status(`↑ ${i}/${items.length} ${rel} ${pct(b, f.size)}`));
        }
        status(`↑ ${i} file${i === 1 ? '' : 's'} added`);
      } catch (e) { fail(e); }
    }
    async function get(path, isDir) {
      const name = path.split('/').pop();
      try {
        if (!isDir) {
          const f = src.files.get(path);
          const blob = await src.get(path, b => status(`↓ ${name} ${pct(b, f.size)}`));
          save(blob, name);
          return status(`↓ ${name} done`);
        }
        const list = [...src.files.values()].filter(f => f.path.startsWith(path + '/'));
        const entries = [];
        for (const [i, f] of list.entries()) {
          const blob = await src.get(f.path, b => status(`↓ ${i + 1}/${list.length} ${f.path} ${pct(b, f.size)}`));
          entries.push({ name: f.path.slice(path.length - name.length), blob, mtime: f.mtime });
        }
        status(`zipping ${name}…`);
        save(await zip(entries), name + '.zip');
        status(`↓ ${name}.zip done`);
      } catch (e) { fail(e); }
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
      if (!dirs.size && !files.length) filesEl.append(el('li', { class: 'empty' }, w ? 'empty — drop files or folders anywhere on the page' : 'empty'));
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

    const el_ = [
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', { class: 'grow' }, 'notes'), addNote), noteForm, notesEl),
      el('section', { class: 'panel' }, el('div', { class: 'row' }, el('h2', {}, 'files'), crumbs, tools), filesEl),
    ];
    refresh();
    return { els: el_, refresh };
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
    name.focus();
  }

  // ---- host ---------------------------------------------------------------

  async function host(sess) {
    document.title = sess.slug + ' · p2p';
    if (location.pathname !== '/' + sess.slug) history.replaceState(null, '', '/' + sess.slug);
    current = location.pathname;
    const files = new Map(), notes = new Map(), peers = new Map(), db = idb(sess.slug);
    try {
      for (const f of await db.all('files')) files.set(f.path, { path: f.path, size: f.size, mtime: f.mtime });
      for (const n of await db.all('notes')) notes.set(n.id, { id: n.id, title: n.title, text: n.text, t: n.t });
    } catch {}
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    const kp = await keypair().catch(() => null);
    if (location.pathname !== '/' + sess.slug) return; // navigated away while loading

    const persist = () => setHost(sess);
    const ls = () => ({ t: 'ls', mode: sess.mode, files: [...files.values()], notes: [...notes.values()] });
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
      put: async (blob, path, mtime) => {
        const f = { path, size: blob.size, mtime: Number.isSafeInteger(mtime) ? mtime : Date.now() };
        await db.put('files', { ...f, blob });
        files.set(path, f);
        changed();
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

    const state = el('span', { class: 'mute' }, 'connecting…');
    const status = el('p', { class: 'status' });
    const say = t => { status.textContent = t; };
    const link = location.origin + '/' + sess.slug;
    const pinEl = el('span', { class: 'pin' }, sess.pin);
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

    const v = panel(src, say);
    app.replaceChildren(
      el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + sess.slug), state),
      el('section', { class: 'panel' }, el('h2', {}, 'access'),
        el('div', { class: 'kv' },
          el('span', { class: 'mute' }, 'link'), el('span', { class: 'row' }, el('span', { class: 'grow' }, link.replace(/^https?:\/\//, '')), el('button', { onclick: e => copy(link, e.target) }, 'copy')),
          el('span', { class: 'mute' }, 'pin'), el('span', { class: 'row' }, el('span', { class: 'grow' }, pinEl), el('button', { onclick: e => copy(sess.pin, e.target) }, 'copy'), el('button', { onclick: regen }, 'new pin')),
          el('span', { class: 'mute' }, 'mode'), el('span', { class: 'row' }, modeBtn, modeHint),
        ),
        el('p', { class: 'mute' }, 'send the link and pin to someone. a new pin disconnects everyone. sharing stops when you close this tab and resumes when you reopen it.'),
      ),
      ...v.els,
      status,
      el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: e => ask(e.target, 'delete it all & free the name?', end) }, 'stop sharing & delete everything')),
    );
    view = v;

    let live = false;
    const sig = signal(onSignal, () => sig.send({ t: 'host', slug: sess.slug, token: sess.token, pin: sess.pin }));
    cleanup = () => {
      announce('gone');
      hosting = null;
      sig.close();
      for (const p of peers.values()) p.pc.close();
      peers.clear();
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
          const p = peers.get(m.from || m.id);
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
      const p = { id, pc, dc: null, open: false, q: Promise.resolve(), ups: new Map(), rx: {} };
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
      const ch = new Relay(key, 1, msg => {
        const f = new Uint8Array(12 + msg.length);
        f.set(idb);
        f.set(msg, 12);
        sig.bin(f);
      }, sig.buffered);
      p.pc = { ...RELAY_PC, close: () => ch.close() };
      p.dc = ch;
      old.close();
      ch.onmessage = ev => onPeerMsg(p, ev.data).catch(() => {});
      ch.onclose = () => drop(p.id);
      p.open = true;
      tx(ch, ls());
      showPeers();
    }

    function drop(id) {
      const p = peers.get(id);
      if (!p) return;
      peers.delete(id);
      try { p.pc.close(); } catch {}
      showPeers();
    }

    // everything a guest sends is untrusted
    async function onPeerMsg(p, data) {
      if (typeof data !== 'string') {
        if (data.byteLength < 4) return;
        const req = new DataView(data).getUint32(0), u = p.ups.get(req);
        if (!u) return;
        u.got += data.byteLength - 4;
        if (u.got > u.size) return void p.ups.delete(req);
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
          await stream(p.pc, p.dc, req, f.blob);
          return tx(p.dc, { t: 'end', req });
        }
        case 'put': {
          if (!rw) return fail('read-only share');
          const path = clean(m.path);
          if (!path || !Number.isSafeInteger(m.size) || m.size < 0 || p.ups.size >= 8) return fail('rejected');
          p.ups.set(req, { path, size: m.size, mtime: m.mtime, parts: [], got: 0 }); // before any await: chunks follow at once
          const q = navigator.storage && navigator.storage.estimate && await navigator.storage.estimate().catch(() => null);
          if (q && q.quota - q.usage < m.size) { p.ups.delete(req); return fail('host is out of storage'); }
          return;
        }
        case 'end': {
          const u = p.ups.get(req);
          p.ups.delete(req);
          if (!u || u.got !== u.size) return;
          try { await src.put(new Blob(u.parts), u.path, u.mtime); } catch { return fail('host is out of storage'); }
          return tx(p.dc, { t: 'ok', req });
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
      persist();
      pinEl.textContent = sess.pin;
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
    let pin = store.get(key), mode = 'ro', sig = null, pc = null, dc = null, rxs = {}, n = 0, timer = null, v = null;

    const state = el('span', { class: 'mute' });
    const status = el('p', { class: 'status' });
    const say = t => { status.textContent = t; };
    const head = el('div', { class: 'row' }, el('h1', { class: 'grow' }, el('a', { href: '/' }, 'p2p'), ' /' + slug), state);

    function teardown() {
      clearTimeout(timer);
      const s = sig, p = pc;
      sig = pc = dc = null;
      if (s) s.close();
      if (p) p.close();
      for (const p of pend.values()) p.rej(new Error('disconnected'));
      pend.clear();
      rxs = {};
    }
    cleanup = teardown;

    // nobody owns this name: say so instead of asking for a pin
    function missing() {
      app.replaceChildren(head,
        el('section', { class: 'panel' }, el('h2', {}, 'not found'),
          el('p', {}, `nobody is sharing /${slug}.`),
          el('p', { class: 'mute' }, 'check the link, or take the name for yourself.'),
          el('div', { class: 'row' },
            el('button', { onclick: () => host({ slug, token: newToken(), pin: newPin(), mode: 'rw', fresh: true }) }, `create /${slug}`),
            el('a', { href: '/' }, 'home'))));
    }

    async function start() {
      if (pin) return connect();
      app.replaceChildren(head, status);
      const s = await peek(slug);
      if (cleanup !== teardown) return; // navigated away
      if (!s.exists) return missing();
      form(s.live ? '' : `the owner of /${slug} is offline right now. you can still enter the pin; you'll connect when they're back.`);
    }

    function form(msg) {
      teardown();
      view = v = null;
      dropTo = null;
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
      teardown();
      state.textContent = 'waiting';
      if (!v) app.replaceChildren(head, status);
      say(msg);
      timer = setTimeout(connect, ms);
    }

    function connect() {
      teardown();
      state.textContent = 'connecting…';
      if (!v) app.replaceChildren(head, status);
      say('');
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
        case 'down': if (dc && dc.relay) wait('connection lost — reconnecting…', 2000); return;
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
      const lost = () => pc === p && (opened ? wait('connection lost — reconnecting…', 2000) : toRelay(p));
      setTimeout(() => pc === p && !opened && toRelay(p), 6000);
      p.onconnectionstatechange = () => p.connectionState === 'failed' && lost();
      ch.onopen = () => {
        opened = true;
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
      const s = sig, ch = new Relay(k, 0, msg => s.bin(msg), s.buffered);
      pc = { ...RELAY_PC, close: () => ch.close() };
      dc = ch;
      p.close();
      ch.onmessage = e => onMsg(e.data);
      ch.onclose = () => dc === ch && wait('connection lost — reconnecting…', 2000);
      s.onbin = buf => ch.receive(buf);
      s.send({ t: 'sig', data: { relay: 1 } });
      clearTimeout(timer);
      store.set(key, pin);
      show();
    }

    function onMsg(data) {
      if (typeof data !== 'string') {
        if (data.byteLength < 4) return;
        const p = pend.get(new DataView(data).getUint32(0));
        if (!p || !p.parts) return;
        collect(p, new Uint8Array(data, 4));
        p.got += data.byteLength - 4;
        if (p.prog) p.prog(p.got);
        return;
      }
      const m = rx(rxs, data);
      if (!m) return;
      const p = pend.get(m.req);
      switch (m.t) {
        case 'ls':
          mode = m.mode === 'rw' ? 'rw' : 'ro';
          files.clear();
          for (const f of arr(m.files)) {
            const path = f && clean(f.path);
            if (path && Number.isSafeInteger(f.size) && f.size >= 0) files.set(path, { path, size: f.size, mtime: +f.mtime || 0 });
          }
          notes.clear();
          for (const x of arr(m.notes)) {
            if (x && typeof x.id === 'string' && typeof x.title === 'string' && typeof x.text === 'string' && x.text.length <= NOTE_MAX) notes.set(x.id, { id: x.id, title: x.title.slice(0, TITLE_MAX), text: x.text, t: +x.t || 0 });
          }
          state.textContent = 'connected · ' + (mode === 'rw' ? 'two-way' : 'one-way') + (dc && dc.relay ? ' · relayed' : '');
          return v && v.refresh();
        case 'end': if (p) { pend.delete(m.req); p.res(new Blob(p.parts)); } return;
        case 'ok': if (p) { pend.delete(m.req); p.res(); } return;
        case 'err':
          if (p) { pend.delete(m.req); p.rej(new Error(String(m.e).slice(0, 100))); } else say('error: ' + String(m.e).slice(0, 100));
          return;
        case 'bye':
          store.del(key);
          return form(m.why === 'ended' ? 'this share has ended' : 'access was revoked — ask for the new pin');
      }
    }

    const src = {
      files, notes,
      writable: () => mode === 'rw',
      get: (path, prog) => new Promise((res, rej) => {
        const req = ++n;
        pend.set(req, { parts: [], got: 0, res, rej, prog });
        tx(dc, { t: 'get', req, path });
      }),
      put: async (blob, path, mtime, prog) => {
        const req = ++n, c = dc, p = pc;
        const done = new Promise((res, rej) => pend.set(req, { res, rej }));
        tx(c, { t: 'put', req, path, size: blob.size, mtime });
        await stream(p, c, req, blob, prog, () => !pend.has(req));
        tx(c, { t: 'end', req });
        return done;
      },
      rm: async (path, dir) => tx(dc, { t: 'rm', path, dir: !!dir }),
      note: async (title, text, id) => tx(dc, { t: 'note', title, text, id }),
      unnote: async id => tx(dc, { t: 'unnote', id }),
    };

    function show() {
      if (v) return v.refresh();
      v = view = panel(src, say);
      app.replaceChildren(head, ...v.els, status,
        el('div', { class: 'row' }, el('span', { class: 'grow' }), el('button', { class: 'link', onclick: () => { store.del(key); form('disconnected'); } }, 'disconnect')));
      say('');
    }

    start();
  }

  // ---- routing ------------------------------------------------------------

  let current = null;
  function route(msg) {
    if (cleanup) cleanup();
    cleanup = view = dropTo = onTabs = onKill = null;
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

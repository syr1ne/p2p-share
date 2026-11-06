# p2p

share files, folders and notes straight from one browser to another.
free, open source, no accounts.

1. open the site, pick a name for your share → `yoursite.com/photos`
2. send the link and the 7-digit pin to someone
3. they open the link, type the pin, and you're connected

- **names**: everyone has a display name, set at the top of the home page (or on
  the pin form). left empty, you get a random one like `quiet-otter` that stays
  the same. names are unique within a share; the host keeps them, not the server.
  every file, folder and note shows who added it.
- **files & folders**: drag and drop files or folders anywhere on the page, or use the buttons.
- **downloads straight to disk**: in chrome and edge you pick where it goes and
  folders are saved as real folders; in firefox and safari (on https) files stream
  into a normal download, folders as one zip. any size, memory stays flat.
  downloads can be cancelled and nothing half-written is left behind.
- **paste images**: paste a screenshot or copied image (ctrl/cmd+v, outside the note box) to add it as a file.
- **notes**: a shared clipboard. titled text notes; anyone can add, edit (shown
  as "edited by") and copy.
- **two-way**: guests can add files too. what a guest adds stays on their
  computer, in their open tab, and is only sent when someone downloads it, directly
  between their browsers. if they leave, their things show as "offline" for 10
  minutes, then go; back in time, they're there again. anyone can delete anything
  (for someone else's file that only takes it out of the share).
- **one-way**: only you share; others can download and copy. switching to one-way
  removes what others added (it asks first).
- **pin**: hidden until you click show. a new pin disconnects everyone instantly.
- **qr code**: show the link as a qr code for phones (the pin is still needed).
- **several shares**: the home page lists your shares (live or offline) and the ones you joined. kill one to delete it and free the name.
- **live while open**: a share works while its tab is open. your own files and the
  notes are kept in your browser (indexeddb), so closing and reopening the tab picks
  up where you left off. guests reconnect on their own.
- **survives drops**: a dropped connection (sleep, a network switch, a phone app
  switch) reconnects by itself, and downloads carry on from where they stopped
  instead of starting over. notes saved meanwhile are sent once back.
- **phones**: touch-sized controls, progress pinned to the bottom of the screen, and
  the screen kept awake while files move (a locked phone pauses the page).
- light / dark theme switch at the top.

## how it works

```
          ┌──wss── server ──wss──┐        pin check + webrtc handshake only
          │                      │
        host ═══ webrtc ═══ guest alice   listing, notes, the host's files,
          ║                      ║        and signaling for guest links
          ║  webrtc              ║ webrtc (set up through the host)
          ║                      ║
       guest bob ════════════════╝        alice's files go straight to bob
```

the host is the hub: every guest connects to it, and it keeps the listing, the
notes and the member names. files a guest adds stay in that guest's tab; when bob
wants one of alice's, the two open a direct link (the host passes the handshake
between them), and the bytes go alice → bob. if that link can't open within ~6s,
the host forwards the bytes instead, without storing them.

every connection has two channels, one for control messages and one for file
bytes, so a cancel or an edit never waits behind a transfer. files are pulled: the
downloader asks for 1 MiB windows, a few ahead, and the owner answers each. that
keeps what anyone holds in flight small, and lets the slowest part (a disk, a
phone, the relay) set the pace.

opening a link to a name nobody owns says so (with a button to take the name)
instead of asking for a pin.

when two browsers can't reach each other directly (strict nat, routers without
hairpinning, safari/brave privacy settings, some mobile and office networks), the
guest falls back to the **relay** after ~6s (up to 15s if a direct path was found
and is still finishing its handshake): frames go through the server's
websocket, end-to-end encrypted with aes-256-gcm under a key derived (hkdf-sha256)
from an ecdh p-256 exchange done during the handshake. nonces are per-direction
counters, so the server can't replay, reorder or drop frames without the
connection noticing and closing. both sides show "relayed" when it's in use.
the owner's browser opens a separate socket for each relayed guest, so one slow
guest can't hold up the others or new people joining.

the server never stores files, notes or people's names. it keeps share names and
hashed pins in memory, nothing on disk.

## run

```sh
npm install
npm start            # http://localhost:8080
```

or `docker build -t p2p . && docker run -p 8080:8080 p2p`.

## deploy

any host that supports websockets and https. run a single instance, since rooms live in memory.

e.g. a vps with docker + caddy (`reverse_proxy localhost:8080`) for automatic https,
then set `TRUST_PROXY=1`.

| env | default | |
|---|---|---|
| `PORT` | `8080` | |
| `TRUST_PROXY` | off | behind a proxy: `1` = rightmost `x-forwarded-for`, or the header your proxy sets (e.g. `cf-connecting-ip`). only that header is trusted |
| `ORIGIN_HOST` | request host | lock websocket origin, e.g. `p2p.example.com` |
| `ICE_SERVERS` | google + cloudflare stun | json array of extra stun/turn servers (e.g. your own coturn) |
| `RELAY` | on | set `0` to disable the relay fallback |
| `RELAY_MBPS` | `10` | relay speed cap per connection, in megabytes/s |

nothing else to set up: no accounts, api keys or outside services. it works with
the defaults above.

## security

- pins: 7 digits, made with `crypto.getRandomValues`, stored on the server only as
  sha-256 and compared in constant time. 5 wrong tries per ip per 15 min, 50 per
  name per hour.
- share names: claimed with a random 256-bit owner token kept in the owner's
  browser. a share name stays reserved for 30 days after its owner was last online.
- people's names never reach the server: a guest says who it is only over the
  encrypted channel to the host. each browser has a random secret; a share only
  ever sees a hash of it mixed with the share's name (so a host can't reuse it to
  pass as you elsewhere), and the host keeps only a hash of that. the host decides
  who is who: a known secret gets its name back, a new one can't take a name in
  use (or reserved: online, owning something, or seen in the last 30 days).
- guest-to-guest links are vouched for by the host: their handshake only travels
  over the host's encrypted connections, between members the host knows, and the
  host tells each side who the other is. the link itself is dtls, like any webrtc
  connection. an owner only serves files it shared, still listed, and not in
  one-way mode.
- when the host forwards between two guests (no direct link), the bytes pass
  through the host's browser in the clear (each hop is encrypted, the host is an
  endpoint of both). the host never stores them and holds at most a few MiB.
- a guest's ip is only revealed to the owner after the right pin, and the reverse.
- a new pin also lifts any wrong-pin lockout on that name.
- transport: dtls-encrypted webrtc, or the aes-gcm relay. the signaling socket is
  same-origin only, rate limited, capped at 128 KB per message, and relay traffic
  is throttled per connection (back-pressure, not dropped).
- strict csp (no inline code, no third-party scripts on the app origin, trusted
  types enforced), `no-referrer`, frame denial, hsts, nosniff, share pages `noindex`.
  for streamed downloads the csp allows `worker-src 'self'` (public/sw.js),
  `frame-src 'self'` (a hidden same-origin frame starts each download: chromium
  doesn't send `<a download>` through service workers) and exactly one trusted
  types policy, `p2p-sw`, which only ever returns `/sw.js`. the worker answers
  only `/dl/<id>/<name>` for downloads this page set up; it caches nothing.
- the server survives malformed or oversized frames, cuts sockets that send
  junk, and evicts the longest-offline name if its table is ever full.
- limits: note titles 100 chars, notes 100k chars, 200 notes per share and 50 per
  guest; 10,000 files per guest. the host's own files are refused up front if its
  browser storage can't hold them. folder zips are zip64 (no size or count limit).
- downloads: chrome/edge write straight to disk. firefox and safari stream to disk
  on https; on plain http (a lan ip) there is no service worker, so downloads are
  kept in memory until done — it asks first above 1 GB (256 MB on phones).
- a guest's files are only available while their tab is open; a file changed or
  moved on their disk after sharing is taken out of the share.
- everything a peer sends is validated: types and lengths, ids, sizes, paths
  (normalised, no `..`), download windows, per-guest caps, link signaling (only
  between members, rate limited, size capped). one-way mode is enforced by the host
  and by owners.

the signaling server is trusted to relay the handshake honestly. if you don't
trust a host, run your own: it's one file.

## license

MIT. `public/qr.js` is [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase, also MIT.

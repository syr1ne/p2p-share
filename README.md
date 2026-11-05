# p2p

share files, folders and notes straight from one browser to another.
free, open source, no accounts.

1. open the site, pick a name → `yoursite.com/alice`
2. send the link and the 7-digit pin to someone
3. they open the link, type the pin, and you're connected

- **files & folders**: drop anything on the page. folders download as zip; downloads can be cancelled.
- **notes**: a shared clipboard. titled text notes either side can add, edit and copy.
- **two-way / one-way**: let the other side add, edit and delete, or only download.
- **pin**: hidden until you click show. a new pin disconnects everyone instantly.
- **qr code**: show the link as a qr code for phones (the pin is still needed).
- **several shares**: the home page lists your shares (live or offline) and the ones you joined. kill one to delete it and free the name.
- **live while open**: a share works while its tab is open. files and notes are kept
  in the owner's browser (indexeddb), so closing and reopening the tab picks up
  where you left off. guests reconnect on their own.
- light / dark theme switch at the top.

## how it works

```
browser A ──wss── server ──wss── browser B     only the pin check + webrtc handshake
browser A ════ encrypted webrtc data channel ════ browser B     every file and note
```

opening a link to a name nobody owns says so (with a button to take the name)
instead of asking for a pin.

when two browsers can't reach each other directly (strict nat, routers without
hairpinning, safari/brave privacy settings, some mobile and office networks), the
guest falls back to the **relay** after ~6s: frames go through the server's
websocket, end-to-end encrypted with aes-256-gcm under a key derived (hkdf-sha256)
from an ecdh p-256 exchange done during the handshake. nonces are per-direction
counters, so the server can't replay, reorder or drop frames without the
connection noticing and closing. both sides show "relayed" when it's in use.

the server never stores files or notes. it keeps names and hashed pins in memory,
nothing on disk.

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
| `TURN_KEY_ID` | – | cloudflare turn key id (see below) |
| `TURN_KEY_API_TOKEN` | – | cloudflare turn api token |

### turn relay (optional)

the built-in relay works out of the box but uses your server's bandwidth. to
offload that, add a turn server: browsers then get a direct-ish path through
turn before falling back to the built-in relay. turn only forwards the
already-encrypted stream and can't read it.

cloudflare's turn is free up to 1,000 GB/month:

1. dash.cloudflare.com → realtime → turn server → create
2. copy the **turn token id** and **api token**
3. set `TURN_KEY_ID` and `TURN_KEY_API_TOKEN` on the server and restart

the server mints short-lived credentials itself; nothing else to configure.

## security

- pins: 7 digits, made with `crypto.getRandomValues`, stored on the server only as
  sha-256 and compared in constant time. 5 wrong tries per ip per 15 min, 50 per
  name per hour.
- names: claimed with a random 256-bit owner token kept in the owner's browser.
  a name stays reserved for 30 days after its owner was last online.
- a guest's ip is only revealed to the owner after the right pin, and the reverse.
- a new pin also lifts any wrong-pin lockout on that name.
- transport: dtls-encrypted webrtc, or the aes-gcm relay. the signaling socket is
  same-origin only, rate limited, capped at 128 KB per message, and relay traffic
  is throttled per connection (back-pressure, not dropped).
- strict csp (no inline code, no third-party scripts on the app origin, trusted
  types enforced), `no-referrer`, frame denial, hsts, nosniff, share pages `noindex`.
- the server survives malformed or oversized frames, cuts sockets that send
  junk, and evicts the longest-offline name if its table is ever full.
- limits: note titles 100 chars, notes 100k chars, 200 notes per share; uploads
  are refused up front if the owner's browser storage can't hold them.
  folder downloads are plain zip (4 GB / 65,535 files max).
- everything a peer sends is validated: paths are normalised (no `..`), sizes
  checked, one-way mode enforced on the owner's side.

the signaling server is trusted to relay the handshake honestly. if you don't
trust a host, run your own: it's one file.

## license

MIT. `public/qr.js` is [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase, also MIT.

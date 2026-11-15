# Xray overlay

Files copied on top of the pinned Xray-core source when the node image is built (`docker/Dockerfile`).
It mostly adds files. The one upstream edit it can't avoid is in `patches/`, applied with `git apply`, so a
`XRAY_CORE_VERSION` bump that moves that code fails the build instead of silently dropping it.

It adds a `mtproto` inbound, a Telegram MTProxy with fake TLS. Users, stats, online IPs and routing go through
Xray's normal paths, so the panel treats it like any other managed inbound:

```json
{
  "tag": "telegram",
  "protocol": "mtproto",
  "port": 443,
  "settings": { "domain": "www.microsoft.com" }
}
```

- `domain`: the site clients claim to visit. Pick one that serves TLS 1.3.
- `target` (optional): `host:port` that anything other than a valid client is forwarded to, so the port looks like
  that site. Defaults to `domain:443`. Set it if `domain` points at this server, or connections will loop back here.
- `adTag` (optional): the sponsored channel for this inbound, a 32-hex-character tag from @MTProxybot. See below.
- `publicIp` (optional): this node's public IPv4. Only needed with `adTag` when the network interface has a private
  address, as on AWS or Oracle Cloud.
- `clients` is filled in by the panel. Each one needs `email` and a 32-hex-character `secret`.

## Sponsored channel

A tag can be set on the inbound or on one client (`clients[].adTag`), and the client's wins. In the panel, brokers set it
per user. With a tag, connections go through Telegram's middle proxies, because those are what read it. Their handshake
keys include the source IP and port they see, so:

| Outbound the route picks                          | Result                                                          |
| ------------------------------------------------- | --------------------------------------------------------------- |
| `freedom` (direct)                                | Middle proxy, channel shows                                     |
| `blackhole`                                       | Connection refused                                              |
| Anything that exits elsewhere (VLESS, WARP, HTTP) | Stays on routing via the direct path, works without the channel |

If middle proxies are unreachable, or refuse the handshake (usually a wrong `publicIp`, or NAT changing the source port),
the inbound logs a warning and uses the direct path for a minute before trying again. Users stay connected.

Most middle proxies listen on port 8888, so outbound 8888 must be open on the node. On this path the inbound counts
usage itself instead of going through Xray's dispatcher, so user limits keep working.

Only cores built from this overlay know `mtproto`. A stock core refuses to start on a profile that uses it, which
includes `docker/dev.Dockerfile` and any `core` URL set in a profile's Geodata section. Update nodes before adding the
inbound to their profile.

## IP limits (beta)

`app/iplimit` caps how many IPs can use one user at the same time, across all nodes. `patches/iplimit-dispatcher.patch`
makes the dispatcher ask it before every connection, and the `mtproto` inbound asks it directly because its
middle-proxy path skips the dispatcher. It's a beta: it counts addresses, not devices, so it errs both ways. The
wiki's "IP limit risks" concept lists how, and the panel links to it from both limit fields.

- Each node counts the live IPs of limited users itself. An IP holds a slot while it has any open connection, so
  devices behind one router count once, and a new device is refused while all slots are taken. IPv6 counts by `/64`,
  because a phone's temporary addresses rotate inside it.
- Every 30 seconds, and right after a node's core starts, the panel reads each node's online IPs, picks which ones
  keep the slots (last sweep's first, if still online), and sends every node the whole table (`SyncOperation`,
  through `HandlerService.AlterInbound` on the API inbound). A node then refuses IPs that don't fit and closes the
  connections of any that already got in.
- That list expires after 2 minutes without a sync, and the node goes back to counting only its own IPs. A failed
  panel or an unreachable node loosens the limit, never tightens it. A core that just started enforces nothing
  until its first sync.
- Limited users are reported in the stats online list even when the node runs without CAP_NET_ADMIN, because that
  list is how the panel sees them.
- Limited users' raw TCP sockets get keepalive and a 60-second `TCP_USER_TIMEOUT`. Without them a device that drops
  off a network holds its slot for minutes to hours: Vision splice sets the idle timer to 24 hours, and the core
  leaves keepalive off. WebSocket, gRPC and XHTTP still wait out the policy's `connIdle` (300 seconds by default).

Behind a CDN or relay the inbound must set `sockopt.trustedXForwardedFor`. Without it a user's connections arrive
from many edge IPs, so one device looks like several and is refused at random. A stock core rejects `SyncOperation`
and the node logs once that it can't enforce limits.

## Develop

```sh
scripts/xray-overlay.sh /tmp/xray        # clone the pinned Xray and copy the overlay on top
cd /tmp/xray && go test ./proxy/mtproto/ ./app/iplimit/
```

After editing a `config.proto`, run `scripts/xray-overlay.sh /tmp/xray proto` to regenerate `config.pb.go`.

Check a running proxy against Telegram itself, no account needed. The secret is the one in the user's `tg://` link:

```sh
cd /tmp/xray && MTPROTO_ADDRESS=1.2.3.4:443 MTPROTO_LINK_SECRET=ee... go test -run TestLiveTelegram -v ./proxy/mtproto/
```

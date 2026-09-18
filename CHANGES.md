# Bug Hunter VPN – analysis and fix

## 1. Were the claims correct? (checked against your source)

| # | Claim | Verdict | What the code actually shows |
|---|-------|---------|------------------------------|
| A | Raw IP packets are sent as if they were VLESS payload | **Confirmed – the fatal bug** | `ws.send(ByteString.of(packet,0,length))` (l.196/199) sends whole IP packets (IP+TCP headers, SYN/ACK, checksums…). A VLESS server expects the *application byte stream*. Even the first packet is a VLESS header followed by a raw IP packet. A VPN needs something that terminates TCP locally (a "tun2socks") – that is what was missing. |
| B | No return path into the TUN | **Confirmed** | `WebSocketListener` has no `onMessage` (l.158-168) and nothing ever writes to the TUN. Even a perfect server reply could not reach any app. |
| C | Own WebSocket loops back into the VPN | **Confirmed, and worse** | `addAllowedApplication(getPackageName())` (l.144) means *only your own app* is routed into the VPN: OkHttp's socket to the server goes into the TUN (loop) **and no other app ever uses the tunnel**. No `protect()` anywhere. |
| D | VLESS header length wrong | **Confirmed (measured)** | I ran your `createVlessHeader` verbatim: it returns 31/31/36/38 bytes for 1.1.1.1/8.8.8.8/104.26.3.143/142.250.185.46; the real IPv4 header is exactly 26. 5-13 stray zero bytes corrupt the stream. Also the header is sent once per *VPN session* (`headerSent`), but VLESS needs one per *connection*. |
| E | VPN-permission result not handled | **Confirmed** | `startActivityForResult(intent, 0)` with no `onActivityResult`: first tap only shows the dialog; you must tap START again. |
| F | Missing foreground service | **Partly** | No `startForeground()` – true, but a VpnService works without it; it only makes Android more likely to kill you. Severity was overstated. Fixed anyway. |
| G | UI says connected too early | **Confirmed** | `isConnected = true` right after `startService` (l.106); `onFailure` never resets it. |
| H | Fixed packet offsets / IPv4 only | **Partly** | Offsets 16-19 / 22-23 are right only for IPv4 with a 20-byte header. IPv6 is not captured at all (only an IPv4 route) so it *leaks around the tunnel*. |
| – | Trust-all TLS | **Confirmed** | l.223-232. Now off by default (checkbox). |
| – | "Manual Upgrade/Connection headers are wrong" | **Harmless** | OkHttp replaces them with its own (`header()` not `addHeader`). |
| – | `START_STICKY` null-intent NPE | **Confirmed** | l.131 dereferences `intent` after only checking it for the STOP case. |
| – | `BIND_VPN_SERVICE` in `<uses-permission>` | **Harmless** | Moved to where it belongs. |

**Not mentioned by the earlier analysis, found while reading:**
* **DNS can never work**: DNS goes through the TUN as UDP to 8.8.8.8; nothing handles UDP. Every hostname lookup would hang.
* The VLESS **response header** (2 bytes) is never stripped (there is no receive code at all).
* OkHttp's `Dispatcher` allows only 5 concurrent requests per host by default and a WebSocket holds a slot for its whole life, so it would silently cap you at ~5 simultaneous connections (I set it to 1024; I could not verify this on a device).
* Android's VPN fd is non-blocking by default, so the original `in.read()` loop likely busy-spins a CPU core.
* `app/src/main/java/AndroidManifest.xml` was a stray duplicate manifest (ignored by Gradle); removed.

## 2. What was built

Architecture (the same idea as DarkTunnel's tun2socks, but pure Java – no native binaries, no NDK):

```
apps -> TUN -> PacketEngine (user-space TCP, DNS) -> 1 VLESS/WebSocket per TCP connection -> your server
                                     ^------------ replies are written back into the TUN ------------|
```

* `engine/` – pure-Java packet engine (no Android classes): IPv4/TCP termination (handshake, seq/ack, window
  flow-control both ways, retransmit, fast-retransmit, out-of-order reassembly, FIN/RST handling, zero-window probes),
  DNS: UDP/53 -> DNS-over-TCP over one persistent tunnelled stream. AAAA queries get an empty answer (IPv6 is blocked).
* `vless/VlessCodec` – correct 26-byte VLESS request header + response-header stripping.
* `VlessWsConnector` – OkHttp WebSocket per flow. SNI = "Bug Host", `Host:` header = "Actual Server", TCP connect to "Connect IP" (as in your Python logic).
* `TunnelVpnService` – VPN lifecycle, **pre-flight check** (a real DNS lookup through the server before touching routes, so a wrong UUID/path/SNI is reported with a clear message instead of a dead VPN), own app excluded from the VPN + `protect()`, foreground notification, clean shutdown.
* `MainActivity` – same form + "Skip TLS verification" and DNS fields, input validation, permission flow, live status/log.

## 3. What was tested – and what was NOT

Tested here (Linux, JDK 21, real kernel via a TUN device – `sh tools/e2e/run_tests.sh`):
* 13/13 end-to-end checks on a clean link **and** under 0.5 % random packet loss in both directions: 8 MiB download / upload byte-exact,
  2 MiB echo with client half-close, 60 parallel connections, refused-connect -> ECONNREFUSED, server-speaks-first, slow reader (tiny window),
  DNS A answer, AAAA suppression, 40 concurrent DNS queries with identical IDs, no leaked flows. Throughput ~25-45 MB/s through the engine.
* 17/17 VLESS framing checks.
* All Android code compiles against API stubs (typos/signatures) – **but I could not run Gradle** (no Android SDK / network here).

NOT tested – please verify on your phone, in this order:
1. `./gradlew assembleDebug` builds. 2. Tapping START shows "Tunnel check OK" in the log (this validates UUID/path/SNI/Host/Connect-IP against your real server).
3. A browser loads a page. If step 2 fails the log tells you why (HTTP status, TLS error, or "server closed without answering").

## 4. Known limitations
* TCP and DNS only. Other UDP (QUIC/HTTP3, VoIP, games) is dropped; Chrome falls back to TCP automatically.
* IPv6 is blocked on purpose (so it can't leak). Local-network addresses (192.168.x) are routed into the tunnel too.
* One WebSocket+TLS handshake per TCP connection (no mux) -> page loads have extra latency vs. native clients.
* Destination is sent as an IP (no domain), so server-side domain routing/sniffing rules will not see hostnames.
* Android "Private DNS: strict" bypasses our DNS; use Off/Automatic.
* Half-close: WebSockets cannot half-close, so a client FIN is not forwarded; idle flows are reaped after 30 s.
* Gradle wrapper / `local.properties` are unchanged from your project (Windows SDK path) – adjust if needed.

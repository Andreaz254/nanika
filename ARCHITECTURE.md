# Protocol split: file map, v2rayNG comparison, VMess plan

## 1. Where each protocol lives now (app/src/main/java/com/example/tunnel)

| Path | Belongs to | Role |
|---|---|---|
| `vless/VlessCodec.java` | **VLESS only** | 26-byte request header, response-header stripping (unchanged) |
| `vless/VlessWsConnector.java` | **VLESS only** | One OkHttp WebSocket per TCP flow (moved here, code unchanged) |
| `vless/VlessProtocol.java` | **VLESS only** | Plugs VLESS into the registry (validate + build connector) |
| `vmess/VmessCodec.java` | **VMess only** | AEAD header (KDF, auth ID, AES-GCM), AES-128-GCM chunk framing, streaming response decoder. Pure JCA |
| `vmess/VmessWsConnector.java` | **VMess only** | One OkHttp WebSocket per TCP flow (same shape as the VLESS connector) |
| `vmess/VmessProtocol.java` | **VMess only** | Plugs VMess into the registry (validate + build connector) |
| `protocol/TunnelProtocol.java` | shared | Interface every protocol implements |
| `protocol/ProtocolRegistry.java` | shared | The one list of protocols (add new ones here) |
| `protocol/ProtocolConfig.java` | shared | Neutral form data handed to a protocol |
| `protocol/WsUrl.java` | shared | WebSocket URL builder (logic moved verbatim out of the service) |
| `protocol/Uuids.java` | shared | 16-byte UUID parsing (VMess uses it; VLESS keeps its own copy) |
| `TunnelVpnService.java` | shared | VPN lifecycle, TUN, protect(); now asks the registry for a connector |
| `engine/*` | shared | User-space TCP/DNS engine; protocol-agnostic via `UpstreamConnector` |
| `MainActivity.java` | shared | UI; UUID validation now goes through the selected protocol |

Adding a protocol (e.g. Trojan): new package `com.example.tunnel.trojan` with codec + connector + `TrojanProtocol`,
then one line in `ProtocolRegistry`. The engine and service need no change.

### VLESS behaviour is unchanged
Same header bytes, same URL logic, same preflight, same engine. Verified here: your 17 framing checks in
`tools/e2e/VlessTest.java` still pass, and a new check confirms the URL builder gives identical output to the old
inline code for TLS and non-TLS. The only visible change is one extra log line, `Protocol: VLESS`.

## 2. Your setup vs v2rayNG

| | v2rayNG | Your app |
|---|---|---|
| Protocol implementation | None in Kotlin. A Go core (Xray or V2Fly) shipped as an AAR does VLESS, VMess, Trojan, etc. | You implement the wire protocol yourself in Java (VLESS only) |
| Language | Kotlin + Go core | Pure Java, no native code |
| Traffic from TUN | Core's TUN inbound, or a native tun2socks (HEV) feeding a local SOCKS inbound | Your own Java packet engine terminates TCP and opens one WebSocket per connection |
| Config | App generates a core JSON config (inbound + outbound + streamSettings) | No core config; settings go directly into a connector |
| Transports | Everything the core supports (WS, gRPC, HTTP/2, Reality, mux...) | WebSocket only, one TLS handshake per flow, no mux |
| Destination | Domain names preserved (sniffing, routing) | Destination is an IP (no domain), so server-side domain rules can't apply |
| UDP | Supported by the core | DNS only; other UDP dropped |
| IPv6 | Supported | Blocked on purpose |
| Adding a protocol | Add a link parser + outbound builder; the core does the rest | Write the full wire protocol yourself |

## 3. VMess: how it is done here, and how that relates to v2rayNG

v2rayNG has no VMess code of its own: `CoreOutboundBuilder.toOutboundVmess` emits a config
(`protocol: vmess`, user id, `security` default **"auto"**, alterId 0, ws + tls streamSettings) and the Xray core does the wire
protocol. The `AndroidLibXrayLite` folder in the uploaded zip is empty (a git submodule), so Xray's source was not available to copy.
`vmess/VmessCodec` therefore implements the Xray-core VMess **AEAD** client spec directly in Java, with v2rayNG's settings:

| Item | v2rayNG / Xray | This app |
|---|---|---|
| alterId | 0 (AEAD header) | 0 |
| security "auto" | AES-128-GCM on arm64/amd64, else ChaCha20-Poly1305 | AES-128-GCM always |
| Header | authID + AEAD(len) + nonce + AEAD(header), nested-HMAC KDF | same |
| Body | chunks; Xray also enables chunk masking, global padding, authenticated length | chunk stream only (option S); plain 2-byte length. Valid for any server |
| Transport | ws (+tls) | ws (+tls), reuses `WsUrl` and the VLESS client settings |
| Address | domain or IP | IPv4 (the engine only has IPs), same as the VLESS path |

Limits: TCP + DNS only (as VLESS), no mux, no ChaCha20 (JCA ChaCha20-Poly1305 needs API 28, minSdk is 21).
The server rejects clients whose clock is more than ~2 minutes off, so a wrong phone clock looks like a dead server.

## 4. Verified / not verified
VMess: `sh tools/vmess/run_vmess_tests.sh`. The Java codec is cross-checked against an independent Python implementation (header, KDF, chunks, response), and the real connector is run against a fake VMess server. **Not tested against a real Xray/V2Ray server or on a device.**

### Still not verified
Gradle/Android build, and any on-device run. I type-checked the pure-Java packages with stubs and ran the tests
above; the Android classes (service, activity) were edited but not compiled here. Please run `./gradlew assembleDebug`
and confirm VLESS still shows "Tunnel check OK" before relying on it.

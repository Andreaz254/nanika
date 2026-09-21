# Protocol split: file map, v2rayNG comparison, VMess plan

## 1. Where each protocol lives now (app/src/main/java/com/example/tunnel)

| Path | Belongs to | Role |
|---|---|---|
| `vless/VlessCodec.java` | **VLESS only** | 26-byte request header, response-header stripping (unchanged) |
| `vless/VlessWsConnector.java` | **VLESS only** | One OkHttp WebSocket per TCP flow (moved here, code unchanged) |
| `vless/VlessProtocol.java` | **VLESS only** | Plugs VLESS into the registry (validate + build connector) |
| `vmess/VmessProtocol.java` | **VMess only** | Registry slot. Validates the UUID; reports "not implemented" on connect |
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

## 3. Which core, and how VMess should be done

**Use Xray-core** (via AndroidLibXrayLite, the same AAR route v2rayNG uses). It handles both VLESS and VMess.
To my knowledge V2Fly's core does not support VLESS, so it cannot be your single core. Verify this before relying on it.

I did **not** implement VMess, deliberately:
* "Exactly like v2rayNG" means embedding the Go core. That needs the AAR (build with gomobile or take it from a
  v2rayNG release) and a Gradle sync; this sandbox has no network and no Android SDK, so I cannot build or test it.
* A pure-Java VMess (AEAD header + AES-GCM/ChaCha20 body) is possible but I have no VMess server here to test
  against, and I won't hand you untested crypto framing and call it guaranteed.

Recommended path, which cannot break VLESS:
1. Keep VLESS on the current engine (untouched).
2. Add the Xray AAR. In `VmessProtocol`, instead of a connector, generate a core config and start the core on the
   TUN fd, the way v2rayNG's `CoreConfigManager` / `CoreServiceManager` do. Outbound shape:
   `{"protocol":"vmess","settings":{"vnext":[{"address":CONNECT_IP,"port":PORT,"users":[{"id":UUID,"alterId":0,"security":"auto"}]}]},
   "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":SNI},"wsSettings":{"path":PATH,"headers":{"Host":HOST}}}}`
3. Because this path hands the TUN to the core, `TunnelProtocol` would need a second kind of backend (core-based
   instead of connector-based). I left that out until the AAR exists so nothing half-built ships in your APK.

## 4. Not verified
Gradle/Android build, and any on-device run. I type-checked the pure-Java packages with stubs and ran the tests
above; the Android classes (service, activity) were edited but not compiled here. Please run `./gradlew assembleDebug`
and confirm VLESS still shows "Tunnel check OK" before relying on it.

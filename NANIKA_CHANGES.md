# Nanika (was Bug Hunter) - what changed in this build

The zip you uploaded was the build *before* v3, so this build contains the v3 items from the chat **and** the
latest request. Nothing could be compiled with Gradle here: every Java file was compiled against the real
Android API 33 jar (with stubs for AppCompat / OkHttp / JSch), and the logic below was run in tests.
Please run `./gradlew assembleDebug` and check it on your phone.

## Icon: ACTION NEEDED
`images.jpg` was not in the zip (only in the old chat), so the icons that ship are a **stand-in orange fox**.
To use your picture:

    pip install pillow
    python tools/make_icons.py path/to/images.jpg

It centre-crops the picture to a square and writes the launcher icon (normal, round, Android 8+ adaptive),
and the small round logo shown in the side panel. Use `--bg 1B1B1F` to choose the adaptive background colour.
The app name "Nanika" is in `res/values/strings.xml`.

## From v3 (re-done on this code base)
* SSH: **Server Address** under Password (default `naruto.freessh.indevs.in`, used for the connection).
  The WebSocket Path field and the `[path]` hint are gone from SSH (VLESS/VMess keep their path).
* Home: logs box removed. Orange **LOGS** button at the top right opens the Logs page; swipe left on Home opens
  it, swipe right (or the arrow) goes back. Logs page: Copy, Clear, selectable text.
* Three-dots menu replaces SAVE on SSH / VLESS / VMess. SSH: Import file, Export file, Inject payload
  (Cloudflare / Enhanced / Direct say "Not available yet"). VLESS / VMess: Import and Export.
* VLESS / VMess `vless://` and `vmess://` links: import from clipboard, export to clipboard (WebSocket only).
* SSH banner: plain text as it is, HTML rendered with colours, spacing and line breaks kept.

## New in this build
* **.anika files** - AES-256-GCM encrypted configs. SSH exports `.anika`; VLESS / VMess export `.anika`
  *and* plain JSON, and import both. Import only accepts a file of the right protocol.
  The key lives inside the app: this stops anyone reading or editing the file, it is not protection
  against someone taking the app apart.
* **Logs fit the screen** - lines wrap, no sideways scrolling. The banner / art is shrunk to fit instead.
  New lines keep the view at the bottom (if you scroll up to read, it leaves you alone until you return).
* **Log filtering** - only the status line (`HTTP/1.1 101 ...` green, 3xx orange, 4xx/5xx red) plus
  Upgrade, Connection, Date and Server are shown. cf-cache-status, server-timing, report-to, nel, cf-ray,
  alt-svc, cookies and other headers are dropped, and so is the SSH server host-key fingerprint.
  The SSH server's own version string is shown instead.
* **Redirects** - a 301/302/303/307/308 is logged ("Redirect: reconnecting to ...") and followed.
  SSH payload mode reconnects to the new host (TLS if https/wss) up to 4 times; a redirect to only a new path
  or a loop gives a clear error. VLESS/VMess (OkHttp) follow it too, with the Host header and DNS adjusted.
* **Export dialog** (SSH "Export file", VLESS/VMess "Save as .anika / JSON"), top to bottom:
  file name, expiry date, three protection boxes, and the home-page message at the very bottom (with preview).
  Expiry and message no longer sit on the configuration pages.
  - **Hide server**: SSH Server Address / VLESS-VMess Host header are shown as dots to the importer.
  - **Hide host only**: proxy host, connect host, SNI (and the payload for SSH) are shown as dots.
  - **Lock all**: the importer's SSH / VLESS / VMess page only says "Config locked by creator".
  The hidden values are still used to connect. A protected config cannot be exported again, its logs always
  mask the server addresses, and protection is only offered for .anika (JSON/links are readable, so they are not).
  Importing an unprotected file removes the protection again (it replaces the whole config).
* **Message on Home** shows expiry (green / orange at 3 days or less / red when expired - display only, it does
  not block connecting) and the HTML message. Links are tappable: `<a href>` and plain URLs such as wa.me or
  t.me, plus tg:// and whatsapp:// . Tapping asks "Open this link?" first. Allowed: http, https, tg, whatsapp,
  mailto, tel, sms, signal, viber.
* **Hide server addresses** (Settings, on by default): proxy host, SNI, server address, connect IP, Host
  header and any redirect host appear as `[hidden]` in logs, error messages, the home status line and the banner.

## This update: forced updates, HWID device-lock, real payload injection, reset

### Forced update
* On launch the app does `GET https://updates.freessh.indevs.in/` (plain `curl`-style GET, always HTTPS).
  Expected JSON: `{"version":"1.17","file":"nanika-v1.17.apk","sha256":"...","size":...}`.
  Any failure (offline, timeout, bad reply, a non-HTTPS download URL) is **ignored silently** - the app just
  opens as normal.
* If the server's version is numerically newer (`1.17` > `1.9`, not string comparison), a dialog with no
  cancel button appears: "Update required". Connecting is blocked (`startConnect()` re-shows the dialog)
  until the update is installed. There is no way to dismiss it other than updating.
* Tapping UPDATE NOW downloads the APK (showing percent progress), checks its SHA-256 against the one the
  server gave (refuses and lets you retry if it doesn't match), then opens the system package installer and
  closes Nanika so you can relaunch the new version. Android still requires you to grant "install unknown apps"
  for Nanika once (API 26+) and to tap Install in the system's own dialog - no app can silently self-install
  without being a device owner or rooted, Nanika included.
* `versionName` in `app/build.gradle` is what gets compared. **Bump it for every release** (e.g. to `1.17`)
  to match the `nanika-v1.17.apk` you upload, and increase `versionCode` too - Android refuses to install an
  update whose versionCode is not higher than what's already installed. Currently set to versionCode 4 /
  versionName "1.0"; you decide the numbering from here.

### Update server (`server/server.py`, run from `~/nanika-updates`)
Pure Python 3 standard library, no dependencies. Tested here end-to-end (version selection, hash, download,
path-traversal rejection, silent 404 when empty):

    cd ~/nanika-updates
    python3 server.py                     # listens on 127.0.0.1:8787

Drop files into `./releases` named exactly `nanika-v<version>.apk` (e.g. `nanika-v1.17.apk`); the script picks
the highest version by comparing the dot-separated numbers (not alphabetically), hashes it (cached by file
mtime so large files aren't re-hashed every request), and serves:
* `GET /` - the JSON above
* `GET /downloads/nanika-v1.17.apk` - the file itself
Point your cloudflared tunnel's hostname `updates.freessh.indevs.in` at `http://127.0.0.1:8787` - Cloudflare
terminates TLS, so the script only needs to speak plain HTTP locally. Keep it running with systemd, tmux,
screen, or `nohup python3 server.py &`.

### HWID (device lock)
* **Settings** now opens with a DEVICE section: your HWID, selectable, with a copy icon - and tapping the row
  itself also copies it. It's built from `ANDROID_ID` (stable per device/app, changes on factory reset),
  salted and SHA-256 hashed, so the raw ANDROID_ID can't be recovered from it. Apps can't read a true hardware
  serial without system privileges, so this is the practical equivalent available to a normal app.
* **Export dialog**: a new "DEVICE LOCK" section (after Protection, before the Message at the very bottom) -
  tick "Restrict to one device", then either tap USE THIS DEVICE or paste someone else's HWID. Unlike the
  Protection boxes, this works for both `.anika` and JSON exports.
* **Import**: if the file has a HWID set and it doesn't match the importing phone, nothing is written and the
  error is "this configuration is locked to another device (HWID mismatch)".

### Real payload injection
SSH's three-dot "Inject payload" now actually fills the payload field (Cloudflare / Enhanced / Direct) instead
of saying "Not available yet". New `[method]` (default `GET`) and `[protocol]` (default `HTTP/1.1`) placeholders
were added for the Direct template. All three templates were tested with real token expansion:
* **Cloudflare**: `GET ws://example.com HTTP/1.1[crlf]Host: [host][crlf]Service: SSH[crlf]ModeX: Bypass[crlf]Upgrade: websocket[crlf][crlf]`
* **Enhanced**: `PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: example.com[crlf]Service: SSH[crlf]ModeX: Bypass[crlf]Upgrade: websocket[crlf][crlf]`
* **Direct**: `[method] [host_port] [protocol][crlf]Host: [host][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]`
"Inject payload" is removed from the menu for a creator-locked/protected SSH import (it would silently
overwrite a payload the creator may have deliberately hidden).

### Reset
Every protocol's three-dot menu (SSH explicitly requested; added to VLESS/VMess too since their locked pages
also have no visible buttons) now has a "Reset" item that clears all of that protocol's stored settings,
including any protection flags and HWID lock - this is the only way to get out of a fully locked ("Lock all")
imported page, since that page shows nothing but the lock message.

## Fix: update dialog looping on every launch

The check now compares against a dedicated version file instead of the app's package `versionName`, which is
easy to forget to bump before building a release - that's almost certainly why it looped (the installed APK
kept reporting the same old version to the server no matter how many times you updated).

* **`app/src/main/res/values/app_version.xml`** - the only thing the update check reads now:
  ```xml
  <string name="app_version">1.0</string>
  ```
  **Bump this to match the number in the filename every time you build a release**, e.g. before building
  `nanika-v1.17.apk`, set it to `1.17`. If it doesn't match what you upload to `~/nanika-updates/releases/`,
  the app will keep seeing "a newer version" is available and keep prompting - same as before.
* If the file's version is equal to (or higher than) the server's, the check is skipped entirely - no
  download, no dialog, nothing.
* **Home page**: a small "v1.0" label now sits right next to the "Nanika" title, read from this same file, so
  you can see at a glance which version is actually installed on the phone.

## Sharenet + icon fix

* **Icon:** `python tools/make_icons.py images.jpg` was run, so the launcher icons (square, round, adaptive) and the
  drawer logo are now the Nanika picture instead of the placeholder fox.
* **Sharenet (drawer > Sharenet):** other devices on the same Wi-Fi / hotspot use this phone's tunnel through a proxy.
  * `share/ShareProxy` - one port, HTTP proxy + SOCKS5 + `/proxy.pac`. Every connection is opened THROUGH the tunnel
    (`UpstreamConnector`), names are resolved through the tunnel too. The app itself is excluded from the VPN, so a
    normal socket would have bypassed the tunnel; this is why the proxy talks to the connector directly.
  * Login (SOCKS5 user/password, HTTP Basic) is ON by default with a random password.
  * `share/ShareManager` starts the proxy when sharing is on AND the tunnel is connected, stops it on disconnect.
  * `share/ShareHotspot` - local-only hotspot (Android 8+). Android chooses its name/password; the page shows them.
    A hotspot called "Nanika WiFi" can only be made with the phone's own hotspot settings (button on the page).
  * `share/SpeedMonitor` + `ui/SpeedGraph` - live download/upload graph (last 90 s), peaks, totals, shared-device counts.
    Counters: TUN device (this phone) and the proxy (shared devices).
  * Only TCP is shared (no UDP, no IPv6), like the tunnel itself.
* Manifest: `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`, `ACCESS_FINE_LOCATION` (Android 12 and older),
  `NEARBY_WIFI_DEVICES` (Android 13+), used only for the hotspot.

## Server picker + Import button

* **Servers:** `servers/ServerList` does an HTTPS GET of `https://servers.freessh.indevs.in/` at launch (silent on any
  failure) and caches the last good answer. Format: see `server/servers.example.json`. A protocol is supported when it
  appears under `"protocols"` (`ssh`, `vless`, `vmess`; also accepted: a plain list of names with sibling settings).
  Only host-type settings are applied (SSH: sshHost, proxyHost, proxyPort, sni, transport, payload, user, pass,
  expiry, message; VLESS/VMess: server, connectIp, port, transport, sni, path, uuid, insecure, expiry, message);
  anything a server leaves out keeps the user's own value. Applying works on imported / locked configs too.
* **Choose server** button under the three protocol cards on Home, and "Choose server" in the side panel. The list has
  a pinned "No server" row and scrolls when there are more than 4 servers. Changing protocol keeps the choice only if
  the server supports it, otherwise it resets to "no server chosen". Never fetched + no internet: the button says to
  connect to the internet. Importing a config or resetting one also clears the choice (the config brings its own server).
* **Home top bar:** the LOGS button is now **IMPORT** (clipboard: vless:// / vmess:// link or Nanika JSON; file:
  .anika / .json; the protocol is detected from the content). **LOGS** is a small chip at about 4 o'clock on the
  connect circle (inside a fixed-height frame, so the circle and the cards did not move).

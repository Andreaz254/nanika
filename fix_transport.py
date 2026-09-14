from pathlib import Path

p = Path("app/src/main/java/com/example/tunnel/TunnelVpnService.java")
s = p.read_text()

old = '''            String urlHost = cfg.tls ? cfg.sni : cfg.hostHeader;
            String url = scheme + urlHost + ":" + cfg.port + path;'''

new = '''            String urlHost = cfg.tls ? cfg.sni : cfg.hostHeader;
            String scheme = cfg.tls ? "https://" : "http://";
            String url = scheme + urlHost + ":" + cfg.port + path;'''

if old in s:
    s = s.replace(old, new, 1)
elif 'String scheme = cfg.tls ? "https://" : "http://";' in s:
    print("Scheme declaration already exists; no change needed.")
else:
    raise SystemExit("ERROR: Expected URL lines not found. File left unchanged.")

# Only disable certificate verification when TLS is enabled.
s = s.replace(
    'if (cfg.insecureTls) {',
    'if (cfg.tls && cfg.insecureTls) {'
)

p.write_text(s)
print("Patched:", p)

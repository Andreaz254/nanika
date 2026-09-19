package com.example.tunnel.protocol;

/** WebSocket URL construction shared by every WebSocket-based protocol (moved verbatim from TunnelVpnService). */
public final class WsUrl {
    private WsUrl() {}

    public static String build(ProtocolConfig cfg) {
        String path = cfg.path.startsWith("/") ? cfg.path : "/" + cfg.path;
        String urlHost = cfg.tls ? cfg.sni : cfg.hostHeader;
        String scheme = cfg.tls ? "https://" : "http://";
        return scheme + urlHost + ":" + cfg.port + path;
    }
}

package com.example.tunnel.ssh;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.TunnelProtocol;
import java.io.IOException;
import okhttp3.OkHttpClient;

/** SSH over a raw byte stream established by an HTTP/WebSocket-style payload handshake. */
public final class SshProtocol implements TunnelProtocol {
    @Override public String id() { return "SSH"; }
    @Override public String unavailableReason() { return null; }
    @Override public String validate(ProtocolConfig c) {
        if (blank(c.sshUsername)) return "Configure SSH: username is required";
        if (blank(c.sshPassword)) return "Configure SSH: password is required";
        if (blank(c.hostHeader)) return "Proxy host is required";
        if (c.port < 1 || c.port > 65535) return "Proxy port must be 1-65535";
        if (c.tls && blank(c.sni)) return "SNI host is required for TLS";
        return null;
    }
    private static boolean blank(String s) { return s == null || s.trim().isEmpty(); }
    @Override public UpstreamConnector createConnector(OkHttpClient ignored, ProtocolConfig c) throws IOException {
        // "Server" = the SSH/WebSocket target (goes into Host: via [host]).
        // "Connect IP" = where the TCP socket really goes (the proxy / bug host, e.g. betika.com). Falls back to Server.
        String target = c.hostHeader;
        String proxy = blank(c.connectIp) ? target : c.connectIp.trim();
        return new SshWsConnector(blank(c.sshHost) ? target : c.sshHost,
                c.sshUsername, c.sshPassword, proxy, target, c.port, c.sni, c.tls, c.insecureTls, c.payload, c.path);
    }
}

package com.example.tunnel.ssh;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.TunnelProtocol;

import java.io.IOException;

import okhttp3.OkHttpClient;

/**
 * SSH over WebSocket / HTTP-upgrade payload, with SNI (TLS, proxy port 443) or without (plain, proxy port 80).
 * One SSH session; every tunnelled TCP connection is an SSH direct-tcpip channel. VLESS / VMess are untouched.
 */
public final class SshProtocol implements TunnelProtocol {
    @Override public String id() { return "SSH"; }

    @Override public String unavailableReason() { return null; }

    @Override public String validate(ProtocolConfig cfg) {
        if (isBlank(cfg.sshUser)) return "SSH username is empty (menu > Configure SSH)";
        if (isBlank(cfg.sshPassword)) return "SSH password is empty (menu > Configure SSH)";
        if (cfg.sshPort < 1 || cfg.sshPort > 65535) return "SSH port must be 1-65535 (menu > Configure SSH)";
        if (isBlank(cfg.proxyHost)) return "Proxy host is empty (menu > Payload)";
        if (cfg.proxyPort < 1 || cfg.proxyPort > 65535) return "Proxy port must be 1-65535 (menu > Payload)";
        if (cfg.tls && isBlank(cfg.sni)) return "SNI host is empty";
        return null;
    }

    @Override public UpstreamConnector createConnector(OkHttpClient client, ProtocolConfig cfg) throws IOException {
        String err = validate(cfg);
        if (err != null) throw new IOException(err);
        return new SshConnector(cfg);
    }

    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }
}

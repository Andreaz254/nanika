package com.example.tunnel.vmess;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.TunnelProtocol;
import com.example.tunnel.protocol.Uuids;
import com.example.tunnel.protocol.WsUrl;

import java.io.IOException;

import okhttp3.OkHttpClient;

/**
 * VMess over WebSocket (AEAD header, alterId 0, AES-128-GCM body, "auto" security as in v2rayNG).
 * Wire logic: VmessCodec + VmessWsConnector. VLESS is untouched.
 */
public final class VmessProtocol implements TunnelProtocol {
    @Override public String id() { return "VMess"; }

    @Override public String unavailableReason() { return null; }

    @Override public String validate(ProtocolConfig cfg) {
        try {
            Uuids.parse(cfg.uuid == null ? "" : cfg.uuid);
        } catch (IllegalArgumentException e) {
            return "UUID: " + e.getMessage();
        }
        return null;
    }

    @Override public UpstreamConnector createConnector(OkHttpClient client, ProtocolConfig cfg) throws IOException {
        byte[] uuid = Uuids.parse(cfg.uuid);
        return new VmessWsConnector(client, WsUrl.build(cfg), cfg.hostHeader, uuid);
    }
}

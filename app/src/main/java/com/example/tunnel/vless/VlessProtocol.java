package com.example.tunnel.vless;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.TunnelProtocol;
import com.example.tunnel.protocol.WsUrl;

import java.io.IOException;

import okhttp3.OkHttpClient;

/** VLESS over WebSocket. Wire logic is unchanged: VlessCodec + VlessWsConnector. */
public final class VlessProtocol implements TunnelProtocol {
    @Override public String id() { return "VLESS"; }

    @Override public String unavailableReason() { return null; }

    @Override public String validate(ProtocolConfig cfg) {
        try {
            VlessCodec.parseUuid(cfg.uuid == null ? "" : cfg.uuid);
        } catch (IllegalArgumentException e) {
            return "UUID: " + e.getMessage();
        }
        return null;
    }

    @Override public UpstreamConnector createConnector(OkHttpClient client, ProtocolConfig cfg) throws IOException {
        byte[] uuid = VlessCodec.parseUuid(cfg.uuid);
        return new VlessWsConnector(client, WsUrl.build(cfg), cfg.hostHeader, uuid);
    }
}

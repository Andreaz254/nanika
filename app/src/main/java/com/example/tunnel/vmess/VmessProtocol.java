package com.example.tunnel.vmess;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.TunnelProtocol;
import com.example.tunnel.protocol.Uuids;

import java.io.IOException;

import okhttp3.OkHttpClient;

/**
 * VMess slot. Form validation works; the wire protocol is NOT implemented yet, so selecting it
 * reports a clear error instead of sending garbage to the server (VLESS is untouched either way).
 * See ARCHITECTURE.md for the two ways to fill it in.
 */
public final class VmessProtocol implements TunnelProtocol {
    @Override public String id() { return "VMess"; }

    @Override public String unavailableReason() {
        return "VMess is not implemented in this build. Choose VLESS, or add a VMess connector "
                + "(see ARCHITECTURE.md) before connecting.";
    }

    @Override public String validate(ProtocolConfig cfg) {
        try {
            Uuids.parse(cfg.uuid == null ? "" : cfg.uuid);
        } catch (IllegalArgumentException e) {
            return "UUID: " + e.getMessage();
        }
        return null;
    }

    @Override public UpstreamConnector createConnector(OkHttpClient client, ProtocolConfig cfg) throws IOException {
        throw new IOException(unavailableReason());
    }
}

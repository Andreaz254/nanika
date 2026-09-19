package com.example.tunnel.protocol;

import com.example.tunnel.engine.UpstreamConnector;

import java.io.IOException;

import okhttp3.OkHttpClient;

/**
 * One implementation per proxy protocol. To add a protocol (Trojan, Shadowsocks, ...):
 *   1. create a package com.example.tunnel.<name> with its codec + connector,
 *   2. implement this interface,
 *   3. register it in {@link ProtocolRegistry}.
 * Nothing in the packet engine or the VPN service needs to change.
 */
public interface TunnelProtocol {
    /** Name shown in the UI and passed in the start intent, e.g. "VLESS". */
    String id();

    /** Null if usable; otherwise a user-facing reason (e.g. "not implemented yet"). */
    String unavailableReason();

    /** Protocol-specific field validation. Returns an error message, or null if the input is fine. */
    String validate(ProtocolConfig cfg);

    /** Builds the per-flow connector the packet engine will use. */
    UpstreamConnector createConnector(OkHttpClient client, ProtocolConfig cfg) throws IOException;
}

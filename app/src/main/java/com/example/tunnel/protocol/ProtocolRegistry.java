package com.example.tunnel.protocol;

import com.example.tunnel.vless.VlessProtocol;
import com.example.tunnel.vmess.VmessProtocol;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Single place that knows which protocols exist. */
public final class ProtocolRegistry {
    private static final Map<String, TunnelProtocol> ALL = new LinkedHashMap<String, TunnelProtocol>();

    static {
        register(new VlessProtocol());
        register(new VmessProtocol());
        // Keep protocol-specific dependencies isolated so codec-only test harnesses remain independent.
        try { register((TunnelProtocol) Class.forName("com.example.tunnel.ssh.SshProtocol").newInstance()); }
        catch (Exception e) { /* SSH is unavailable only if its implementation cannot be loaded. */ }
        // register(new TrojanProtocol());   <- add new protocols here
    }

    private ProtocolRegistry() {}

    private static void register(TunnelProtocol p) { ALL.put(p.id().toLowerCase(), p); }

    /** Falls back to VLESS for a null/blank name (same default the service always had). */
    public static TunnelProtocol require(String name) throws IOException {
        if (name == null || name.trim().isEmpty()) name = "VLESS";
        TunnelProtocol p = ALL.get(name.trim().toLowerCase());
        if (p == null) throw new IOException("Unsupported protocol: " + name);
        return p;
    }
}

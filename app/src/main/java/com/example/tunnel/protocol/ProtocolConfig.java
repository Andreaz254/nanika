package com.example.tunnel.protocol;

/** Protocol-neutral connection settings, filled from the UI form. Each protocol reads what it needs. */
public final class ProtocolConfig {
    public String uuid;
    public String hostHeader;   // WebSocket "Host:" header ("Server" field)
    public String sni;          // TLS SNI / URL host when TLS is on ("Bug Host" field)
    public String path;
    public String connectIp;    // the real TCP destination
    public String dns;
    public int port = 443;
    public boolean tls = true;
    public boolean insecureTls;
}

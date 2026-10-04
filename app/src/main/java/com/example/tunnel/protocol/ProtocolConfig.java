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

    // ---- SSH-over-WebSocket only (ignored by VLESS / VMess)
    public String sshUser;
    public String sshPassword;
    public String sshHost;      // SSH server name as the payload sees it ([host]); falls back to proxyHost
    public int sshPort = 22;
    public String payload;      // payload template sent to the proxy before SSH starts
    public String proxyHost;    // real TCP destination (your host server)
    public int proxyPort;       // 443 with SNI (TLS), 80 without SNI
    public boolean wsFraming;   // true = RFC 6455 frames after the upgrade, false = raw SSH after the 101 reply

    /** Optional factory whose sockets bypass the VPN (set by the service). */
    public javax.net.SocketFactory socketFactory;
}

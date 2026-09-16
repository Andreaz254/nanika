package com.example.tunnel.engine;

public interface UpstreamConnector {
    /**
     * Start connecting to destIp:port (TCP semantics). Must return immediately; progress is
     * reported through the listener (onOpen / onClosed).
     */
    UpstreamStream open(String destIp, int port, UpstreamListener listener);
}

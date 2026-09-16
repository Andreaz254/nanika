package com.example.tunnel.engine;

final class FlowKey {
    final int clientIp, clientPort, serverIp, serverPort;

    FlowKey(int clientIp, int clientPort, int serverIp, int serverPort) {
        this.clientIp = clientIp;
        this.clientPort = clientPort;
        this.serverIp = serverIp;
        this.serverPort = serverPort;
    }

    @Override public boolean equals(Object o) {
        if (!(o instanceof FlowKey)) return false;
        FlowKey k = (FlowKey) o;
        return clientIp == k.clientIp && clientPort == k.clientPort && serverIp == k.serverIp && serverPort == k.serverPort;
    }

    @Override public int hashCode() {
        int h = clientIp;
        h = h * 31 + serverIp;
        h = h * 31 + clientPort;
        h = h * 31 + serverPort;
        return h;
    }

    @Override public String toString() {
        return Ip.str(clientIp) + ":" + clientPort + " -> " + Ip.str(serverIp) + ":" + serverPort;
    }
}

package com.example.tunnel.vless;

import com.example.tunnel.TunnelState;
import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

/**
 * Opens one VLESS-over-WebSocket connection per TCP flow:
 *   WebSocket message 1 (client->server): VLESS request header (26 bytes, IPv4 + port)
 *   later client->server messages:        raw application bytes
 *   server->client: first bytes are the 2-byte VLESS response header (stripped here), then raw bytes.
 */
final class VlessWsConnector implements UpstreamConnector {
    private final OkHttpClient client;
    private final String url;
    private final String hostHeader;
    private final byte[] uuid;
    private final AtomicInteger failureLogs = new AtomicInteger();

    VlessWsConnector(OkHttpClient client, String url, String hostHeader, byte[] uuid) {
        this.client = client;
        this.url = url;
        this.hostHeader = hostHeader;
        this.uuid = uuid;
    }

    @Override
    public UpstreamStream open(String destIp, int port, UpstreamListener listener) {
        Stream s = new Stream(destIp, port, listener);
        Request req = new Request.Builder().url(url).header("Host", hostHeader).build();
        WebSocket ws = client.newWebSocket(req, s);
        s.attach(ws);
        return s;
    }

    private final class Stream extends WebSocketListener implements UpstreamStream {
        private final String destIp;
        private final int port;
        private final UpstreamListener listener;
        private final VlessCodec.ResponseParser parser = new VlessCodec.ResponseParser();
        private final AtomicBoolean finished = new AtomicBoolean();
        private volatile WebSocket ws;
        private volatile boolean closed;

        Stream(String destIp, int port, UpstreamListener listener) {
            this.destIp = destIp;
            this.port = port;
            this.listener = listener;
        }

        void attach(WebSocket w) {
            ws = w;
            if (closed) w.cancel();          // close() raced with newWebSocket()
        }

        private void finish(boolean error) {
            if (finished.compareAndSet(false, true)) listener.onClosed(error);
        }

        // ---- WebSocketListener (called on OkHttp threads)

        @Override
        public void onOpen(WebSocket webSocket, Response response) {
            ws = webSocket;
            if (closed) { webSocket.cancel(); return; }
            try {
                webSocket.send(ByteString.of(VlessCodec.tcpRequestHeader(uuid, destIp, port)));
                listener.onOpen();
            } catch (RuntimeException e) {
                TunnelState.log("open handler failed: " + e);
                close();
                finish(true);
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, ByteString bytes) {
            if (closed) return;
            byte[] b = bytes.toByteArray();
            int off = 0;
            try {
                if (!parser.done()) off = parser.consume(b, 0, b.length);
            } catch (IOException e) {
                TunnelState.log("VLESS error for " + destIp + ":" + port + ": " + e.getMessage());
                close();
                finish(true);
                return;
            }
            if (off < b.length) {
                try {
                    listener.onData(b, off, b.length - off);
                } catch (RuntimeException e) {
                    TunnelState.log("data handler failed: " + e);
                    close();
                    finish(true);
                }
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) { /* VLESS never uses text frames */ }

        @Override
        public void onClosing(WebSocket webSocket, int code, String reason) {
            webSocket.close(1000, null);
            finish(false);
        }

        @Override
        public void onClosed(WebSocket webSocket, int code, String reason) {
            finish(false);
        }

        @Override
        public void onFailure(WebSocket webSocket, Throwable t, Response response) {
            if (!closed && failureLogs.incrementAndGet() <= 25) {
                String http = response != null ? " (HTTP " + response.code() + ")" : "";
                TunnelState.log("WS failed for " + destIp + ":" + port + http + ": " + t);
            }
            finish(!closed);
        }

        // ---- UpstreamStream (called by the packet engine)

        @Override
        public void write(byte[] data, int off, int len) {
            WebSocket w = ws;
            if (w == null || closed) return;
            if (!w.send(ByteString.of(data, off, len))) {   // queue overflow or socket already closed
                close();
                finish(true);
            }
        }

        @Override
        public int pendingBytes() {
            WebSocket w = ws;
            if (w == null) return 0;
            long q = w.queueSize();
            return q > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) q;
        }

        @Override
        public void closeWrite() {
            // WebSockets have no half-close. We keep the socket open so the server can finish
            // sending; the engine's idle timer reaps the flow if the server never does.
        }

        @Override
        public void close() {
            closed = true;
            WebSocket w = ws;
            if (w != null && !w.close(1000, null)) w.cancel();
        }
    }
}

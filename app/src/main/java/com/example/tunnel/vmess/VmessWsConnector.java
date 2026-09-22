package com.example.tunnel.vmess;

import com.example.tunnel.TunnelState;
import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

/**
 * One VMess (AEAD, alterId 0, AES-128-GCM) connection over WebSocket per TCP flow, same shape as the VLESS connector:
 *   client->server: sealed VMess request header, then encrypted chunks
 *   server->client: sealed response header, then encrypted chunks (decoded here, raw bytes go to the engine)
 */
final class VmessWsConnector implements UpstreamConnector {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OkHttpClient client;
    private final String url;
    private final String hostHeader;
    private final byte[] uuid;
    private final AtomicInteger failureLogs = new AtomicInteger();

    VmessWsConnector(OkHttpClient client, String url, String hostHeader, byte[] uuid) {
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
        private final VmessCodec.Session session = new VmessCodec.Session(uuid, RANDOM);
        private final VmessCodec.ResponseDecoder decoder = session.responseDecoder();
        private final Object sendLock = new Object();   // chunk nonce order must equal WebSocket send order
        private final AtomicBoolean finished = new AtomicBoolean();
        private volatile WebSocket ws;
        private volatile boolean closed;
        private volatile boolean opened;

        private final VmessCodec.Sink sink = new VmessCodec.Sink() {
            @Override public void data(byte[] b, int off, int len) { listener.onData(b, off, len); }
        };

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

        private void fail(String why) {
            TunnelState.log("VMess error for " + destIp + ":" + port + ": " + why);
            close();
            finish(true);
        }

        // ---- WebSocketListener (called on OkHttp threads)

        @Override
        public void onOpen(WebSocket webSocket, Response response) {
            ws = webSocket;
            if (closed) { webSocket.cancel(); return; }
            try {
                byte[] header = session.requestHeader(destIp, port, System.currentTimeMillis() / 1000L);
                synchronized (sendLock) { webSocket.send(ByteString.of(header)); }
                opened = true;
                listener.onOpen();
            } catch (IOException e) {
                fail(e.getMessage());
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
            try {
                decoder.feed(b, 0, b.length, sink);
            } catch (IOException e) {
                fail(e.getMessage());
            } catch (RuntimeException e) {
                TunnelState.log("data handler failed: " + e);
                close();
                finish(true);
            }
        }

        @Override
        public void onMessage(WebSocket webSocket, String text) { /* VMess never uses text frames */ }

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
            try {
                synchronized (sendLock) {
                    int pos = off, end = off + len;
                    while (pos < end) {
                        int n = Math.min(VmessCodec.MAX_PLAIN, end - pos);
                        if (!w.send(ByteString.of(session.encodeChunk(data, pos, n)))) {
                            close();
                            finish(true);
                            return;
                        }
                        pos += n;
                    }
                }
            } catch (IOException e) {
                fail(e.getMessage());
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
            // WebSockets have no half-close (same as the VLESS connector); the engine's idle timer reaps the flow.
        }

        @Override
        public void close() {
            closed = true;
            WebSocket w = ws;
            if (w != null && !w.close(1000, null)) w.cancel();
        }
    }
}

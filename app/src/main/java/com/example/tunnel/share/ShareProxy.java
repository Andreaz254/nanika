package com.example.tunnel.share;

import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A small proxy for other devices on the same network. One port speaks
 *   - SOCKS5 (CONNECT)            - HTTP proxy (CONNECT and plain http:// requests)
 *   - GET /proxy.pac              - the auto-config file for those devices
 * Every connection is opened THROUGH the tunnel ({@link UpstreamConnector}), not through the phone's normal
 * network, so the other devices use the same server as this phone. Names are resolved through the tunnel as well.
 * Optional login (SOCKS5 user/password, HTTP Basic). IPv4 only, like the tunnel itself.
 */
public final class ShareProxy {
    public interface Log { void log(String msg); }

    public static final class Config {
        public int port = 8080;
        public boolean auth;
        public String user = "", pass = "";
        public String dnsIp = "8.8.8.8";
    }

    private static final Charset ISO = Charset.forName("ISO-8859-1");
    private static final int MAX_CONNECTIONS = 300;
    private static final long UPSTREAM_BUFFER_LIMIT = 512 * 1024;

    private final UpstreamConnector connector;
    private final Config cfg;
    private final Log log;
    private ServerSocket server;
    private ExecutorService pool;
    private volatile boolean running;
    private final AtomicInteger active = new AtomicInteger();
    private final Map<String, Long> clients = new ConcurrentHashMap<String, Long>();
    private final Map<String, long[]> dnsCache = new ConcurrentHashMap<String, long[]>();   // name -> {ip as int, expiry ms}

    public ShareProxy(UpstreamConnector connector, Config cfg, Log log) {
        this.connector = connector;
        this.cfg = cfg;
        this.log = log == null ? new Log() { @Override public void log(String m) { } } : log;
    }

    public int port() { return server == null ? cfg.port : server.getLocalPort(); }
    public int activeConnections() { return active.get(); }

    /** Devices that opened a connection in the last minute. */
    public int recentClients() {
        long cut = System.currentTimeMillis() - 60000;
        int n = 0;
        for (Long t : clients.values()) if (t >= cut) n++;
        return n;
    }

    public void start() throws IOException {
        ServerSocket s = new ServerSocket();
        s.setReuseAddress(true);
        s.bind(new InetSocketAddress(cfg.port));
        server = s;
        running = true;
        pool = Executors.newCachedThreadPool(new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "share-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
        pool.execute(new Runnable() {
            @Override public void run() { acceptLoop(); }
        });
        log.log("Sharenet: proxy listening on port " + s.getLocalPort() + (cfg.auth ? " (login required)" : " (no login)"));
    }

    public void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignored) { }
        if (pool != null) pool.shutdownNow();
        clients.clear();
        log.log("Sharenet: proxy stopped");
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket c = server.accept();
                if (active.get() >= MAX_CONNECTIONS) { closeQuiet(c); continue; }
                clients.put(c.getInetAddress().getHostAddress(), System.currentTimeMillis());
                pool.execute(new Runnable() {
                    @Override public void run() {
                        active.incrementAndGet();
                        try { handle(c); }
                        catch (Throwable ignored) { }
                        finally { active.decrementAndGet(); closeQuiet(c); }
                    }
                });
            } catch (IOException e) {
                if (running) log.log("Sharenet: accept failed: " + e.getMessage());
                return;
            } catch (RuntimeException e) {
                return;
            }
        }
    }

    // ------------------------------------------------------------------ protocol detection

    private void handle(Socket s) throws IOException {
        s.setTcpNoDelay(true);
        s.setSoTimeout(20000);
        BufferedInputStream in = new BufferedInputStream(s.getInputStream(), 16384);
        OutputStream out = s.getOutputStream();
        in.mark(1);
        int first = in.read();
        if (first < 0) return;
        in.reset();
        if (first == 5) socks5(s, in, out); else http(s, in, out);
    }

    // ------------------------------------------------------------------ SOCKS5

    private void socks5(Socket s, InputStream in, OutputStream out) throws IOException {
        in.read();                                           // version
        int nm = readByte(in);
        boolean hasNone = false, hasUserPass = false;
        for (int i = 0; i < nm; i++) {
            int m = readByte(in);
            if (m == 0) hasNone = true;
            if (m == 2) hasUserPass = true;
        }
        if (cfg.auth) {
            if (!hasUserPass) { out.write(new byte[]{5, (byte) 0xFF}); return; }
            out.write(new byte[]{5, 2});
            readByte(in);                                    // sub-negotiation version
            String u = readString(in, readByte(in));
            String p = readString(in, readByte(in));
            boolean ok = u.equals(cfg.user) && p.equals(cfg.pass);
            out.write(new byte[]{1, (byte) (ok ? 0 : 1)});
            out.flush();
            if (!ok) return;
        } else {
            if (!hasNone) { out.write(new byte[]{5, (byte) 0xFF}); return; }
            out.write(new byte[]{5, 0});
        }
        out.flush();

        int ver = readByte(in);
        int cmd = readByte(in);
        readByte(in);
        int atyp = readByte(in);
        if (ver != 5) return;
        String host;
        if (atyp == 1) {
            host = readByte(in) + "." + readByte(in) + "." + readByte(in) + "." + readByte(in);
        } else if (atyp == 3) {
            host = readString(in, readByte(in));
        } else {
            socksReply(out, 8);                              // IPv6 / unknown address type
            return;
        }
        int port = (readByte(in) << 8) | readByte(in);
        if (cmd != 1) { socksReply(out, 7); return; }       // only CONNECT

        Upstream up;
        try {
            up = connectUpstream(host, port, s);
        } catch (IOException e) {
            socksReply(out, e.getMessage() != null && e.getMessage().startsWith("refused") ? 5 : 4);
            return;
        }
        socksReply(out, 0);
        s.setSoTimeout(0);
        up.go(in);
    }

    private static void socksReply(OutputStream out, int rep) throws IOException {
        out.write(new byte[]{5, (byte) rep, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
    }

    // ------------------------------------------------------------------ HTTP proxy + PAC

    private void http(Socket s, InputStream in, OutputStream out) throws IOException {
        String head = readHead(in);
        if (head == null) return;
        String[] lines = head.split("\r\n");
        String[] rl = lines[0].split(" ");
        if (rl.length < 3) { respond(out, "400 Bad Request", "text/plain", "Bad request\n"); return; }
        String method = rl[0].toUpperCase(Locale.US), target = rl[1];

        String authHeader = null, hostHeader = null;
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c <= 0) continue;
            String n = lines[i].substring(0, c).trim().toLowerCase(Locale.US);
            String v = lines[i].substring(c + 1).trim();
            if (n.equals("proxy-authorization")) authHeader = v;
            else if (n.equals("host")) hostHeader = v;
        }

        boolean proxyRequest = method.equals("CONNECT") || target.toLowerCase(Locale.US).startsWith("http://");
        if (!proxyRequest) {                                 // a direct request to us: the PAC file / a status page
            String path = target.split("\\?")[0];
            String hp = hostHeader != null ? hostHeader : (s.getLocalAddress().getHostAddress() + ":" + port());
            if (path.equals("/proxy.pac") || path.equals("/wpad.dat") || path.equals("/nanika.pac")) {
                respond(out, "200 OK", "application/x-ns-proxy-autoconfig", pac(hp));
            } else if (path.equals("/")) {
                respond(out, "200 OK", "text/plain; charset=utf-8", "Nanika Sharenet\nProxy: " + hp
                        + " (HTTP and SOCKS5)\nPAC: http://" + hp + "/proxy.pac\n");
            } else {
                respond(out, "404 Not Found", "text/plain", "Not found\n");
            }
            return;
        }

        if (cfg.auth && !basicOk(authHeader)) {
            out.write(("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Nanika\"\r\n"
                    + "Content-Length: 0\r\nConnection: close\r\n\r\n").getBytes(ISO));
            out.flush();
            return;
        }

        if (method.equals("CONNECT")) {
            String host = target;
            int port = 443;
            int colon = target.lastIndexOf(':');
            if (colon > 0) {
                host = target.substring(0, colon);
                port = parsePort(target.substring(colon + 1), 443);
            }
            Upstream up;
            try {
                up = connectUpstream(host, port, s);
            } catch (IOException e) {
                respond(out, "502 Bad Gateway", "text/plain", "Could not connect: " + e.getMessage() + "\n");
                return;
            }
            out.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(ISO));
            out.flush();
            s.setSoTimeout(0);
            up.go(in);
            return;
        }

        // plain http://host[:port]/path
        String rest = target.substring(7);
        int slash = rest.indexOf('/');
        String hostPort = slash < 0 ? rest : rest.substring(0, slash);
        String path = slash < 0 ? "/" : rest.substring(slash);
        String host = hostPort;
        int port = 80;
        int colon = hostPort.lastIndexOf(':');
        if (colon > 0) {
            host = hostPort.substring(0, colon);
            port = parsePort(hostPort.substring(colon + 1), 80);
        }
        Upstream up;
        try {
            up = connectUpstream(host, port, s);
        } catch (IOException e) {
            respond(out, "502 Bad Gateway", "text/plain", "Could not connect: " + e.getMessage() + "\n");
            return;
        }
        StringBuilder req = new StringBuilder();
        req.append(rl[0]).append(' ').append(path).append(' ').append(rl[2]).append("\r\n");
        for (int i = 1; i < lines.length; i++) {
            String ln = lines[i];
            int c = ln.indexOf(':');
            String n = c > 0 ? ln.substring(0, c).trim().toLowerCase(Locale.US) : "";
            if (n.equals("proxy-authorization") || n.equals("proxy-connection") || n.equals("connection")
                    || n.equals("keep-alive")) continue;
            if (!ln.isEmpty()) req.append(ln).append("\r\n");
        }
        req.append("Connection: close\r\n\r\n");                  // one request per connection keeps the relay simple
        up.sendFirst(req.toString().getBytes(ISO));
        s.setSoTimeout(0);
        up.go(in);
    }

    private boolean basicOk(String header) {
        if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) return false;
        try {
            String dec = new String(b64decode(header.substring(6).trim()), "UTF-8");
            return dec.equals(cfg.user + ":" + cfg.pass);
        } catch (Exception e) {
            return false;
        }
    }

    /** Plain base64 decoder (java.util.Base64 needs Android 8). */
    static byte[] b64decode(String in) {
        String al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int buf = 0, bits = 0;
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            if (c == '=') break;
            int v = al.indexOf(c);
            if (v < 0) continue;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                o.write((buf >> bits) & 255);
            }
        }
        return o.toByteArray();
    }

    private static void respond(OutputStream out, String status, String type, String body) throws IOException {
        byte[] b = body.getBytes(Charset.forName("UTF-8"));
        out.write(("HTTP/1.1 " + status + "\r\nContent-Type: " + type + "\r\nContent-Length: " + b.length
                + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").getBytes(ISO));
        out.write(b);
        out.flush();
    }

    /** The auto-config file: private addresses go direct, everything else through this proxy. */
    public static String pac(String hostPort) {
        return "function FindProxyForURL(url, host) {\n"
                + "  if (isPlainHostName(host) || host === \"localhost\" || shExpMatch(host, \"*.local\")) return \"DIRECT\";\n"
                + "  if (/^(10\\.|127\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/.test(host)) return \"DIRECT\";\n"
                + "  return \"PROXY " + hostPort + "; SOCKS5 " + hostPort + "; SOCKS " + hostPort + "\";\n"
                + "}\n";
    }

    // ------------------------------------------------------------------ upstream (through the tunnel)

    private final class Upstream implements UpstreamListener {
        final Socket client;
        final OutputStream cout;
        volatile UpstreamStream stream;
        final CountDownLatch opened = new CountDownLatch(1), ready = new CountDownLatch(1), closed = new CountDownLatch(1);
        volatile boolean openOk, failedConnect;
        private final Object outLock = new Object();

        Upstream(Socket client) throws IOException {
            this.client = client;
            this.cout = client.getOutputStream();
        }

        @Override public void onOpen() { openOk = true; opened.countDown(); }

        @Override public void onData(byte[] d, int off, int len) {
            try {
                ready.await(30, TimeUnit.SECONDS);
                synchronized (outLock) {
                    cout.write(d, off, len);
                    cout.flush();
                }
                SpeedMonitor.shareDown.addAndGet(len);
            } catch (IOException e) {
                closeQuiet(client);
                if (stream != null) stream.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override public void onClosed(boolean error) {
            if (!openOk) failedConnect = true;
            opened.countDown();
            closed.countDown();
            if (openOk) closeQuiet(client);
        }

        void sendFirst(byte[] b) {
            stream.write(b, 0, b.length);
            SpeedMonitor.shareUp.addAndGet(b.length);
        }

        /** Relays client -> tunnel until either side ends. Called after the client was told "connected". */
        void go(InputStream cin) throws IOException {
            ready.countDown();
            byte[] buf = new byte[16384];
            try {
                int n;
                while ((n = cin.read(buf)) >= 0) {
                    long waited = 0;
                    while (stream.pendingBytes() > UPSTREAM_BUFFER_LIMIT && closed.getCount() > 0 && waited < 30000) {
                        sleep(5);
                        waited += 5;
                    }
                    if (closed.getCount() == 0) break;
                    stream.write(buf, 0, n);
                    SpeedMonitor.shareUp.addAndGet(n);
                }
                stream.closeWrite();
                try { closed.await(60, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
            } catch (IOException ignored) {
            } finally {
                stream.close();
            }
        }
    }

    private Upstream connectUpstream(String host, int port, Socket client) throws IOException {
        String ip = resolve(host);
        Upstream u = new Upstream(client);
        u.stream = connector.open(ip, port, u);
        try {
            if (!u.opened.await(15, TimeUnit.SECONDS)) {
                u.stream.close();
                throw new IOException("timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            u.stream.close();
            throw new IOException("interrupted");
        }
        if (!u.openOk) {
            u.stream.close();
            throw new IOException("refused or unreachable");
        }
        return u;
    }

    // ------------------------------------------------------------------ name resolution through the tunnel

    private String resolve(String host) throws IOException {
        if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return host;
        if (host.indexOf(':') >= 0) throw new IOException("IPv6 is not supported");
        String key = host.toLowerCase(Locale.US);
        long[] c = dnsCache.get(key);
        long now = System.currentTimeMillis();
        if (c != null && c[1] > now) return ipToString((int) c[0]);
        int ip = dnsLookup(host);
        dnsCache.put(key, new long[]{ip, now + 5 * 60 * 1000});
        return ipToString(ip);
    }

    private static String ipToString(int ip) {
        return ((ip >>> 24) & 255) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 8) & 255) + "." + (ip & 255);
    }

    private int dnsLookup(String host) throws IOException {
        final byte[] q = buildQuery(host, 0x4e41);
        final ByteArrayOutputStream rx = new ByteArrayOutputStream();
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<byte[]> answer = new AtomicReference<byte[]>();
        final AtomicBoolean sent = new AtomicBoolean();
        final UpstreamStream[] holder = new UpstreamStream[1];
        final CountDownLatch assigned = new CountDownLatch(1);
        UpstreamListener l = new UpstreamListener() {
            @Override public void onOpen() {
                try { assigned.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { return; }
                byte[] f = new byte[q.length + 2];
                f[0] = (byte) (q.length >>> 8);
                f[1] = (byte) q.length;
                System.arraycopy(q, 0, f, 2, q.length);
                if (sent.compareAndSet(false, true)) holder[0].write(f, 0, f.length);
            }
            @Override public void onData(byte[] d, int off, int len) {
                synchronized (rx) {
                    rx.write(d, off, len);
                    byte[] all = rx.toByteArray();
                    if (all.length >= 2) {
                        int need = ((all[0] & 255) << 8) | (all[1] & 255);
                        if (all.length >= 2 + need) {
                            byte[] a = new byte[need];
                            System.arraycopy(all, 2, a, 0, need);
                            answer.compareAndSet(null, a);
                            done.countDown();
                        }
                    }
                }
            }
            @Override public void onClosed(boolean error) { done.countDown(); }
        };
        UpstreamStream s = connector.open(cfg.dnsIp, 53, l);
        holder[0] = s;
        assigned.countDown();
        try {
            if (!done.await(8, TimeUnit.SECONDS)) throw new IOException("name lookup timed out");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        } finally {
            s.close();
        }
        byte[] a = answer.get();
        if (a == null) throw new IOException("name lookup failed");
        int ip = parseFirstA(a);
        if (ip == 0) throw new IOException("no address for " + host);
        return ip;
    }

    static byte[] buildQuery(String host, int id) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(id >> 8); b.write(id);
        b.write(0x01); b.write(0x00);                       // recursion desired
        b.write(0); b.write(1);                             // 1 question
        b.write(0); b.write(0); b.write(0); b.write(0); b.write(0); b.write(0);
        for (String label : host.split("\\.")) {
            byte[] lb = label.getBytes(ISO);
            b.write(Math.min(63, lb.length));
            b.write(lb, 0, Math.min(63, lb.length));
        }
        b.write(0);
        b.write(0); b.write(1);                             // type A
        b.write(0); b.write(1);                             // class IN
        return b.toByteArray();
    }

    /** First IPv4 address (as an int) in a DNS answer, 0 if none. */
    static int parseFirstA(byte[] m) {
        if (m.length < 12) return 0;
        int an = ((m[6] & 255) << 8) | (m[7] & 255);
        int qd = ((m[4] & 255) << 8) | (m[5] & 255);
        int pos = 12;
        for (int i = 0; i < qd; i++) {
            pos = skipName(m, pos);
            pos += 4;
        }
        for (int i = 0; i < an && pos + 10 <= m.length; i++) {
            pos = skipName(m, pos);
            if (pos + 10 > m.length) return 0;
            int type = ((m[pos] & 255) << 8) | (m[pos + 1] & 255);
            int rdlen = ((m[pos + 8] & 255) << 8) | (m[pos + 9] & 255);
            pos += 10;
            if (type == 1 && rdlen == 4 && pos + 4 <= m.length) {
                return ((m[pos] & 255) << 24) | ((m[pos + 1] & 255) << 16) | ((m[pos + 2] & 255) << 8) | (m[pos + 3] & 255);
            }
            pos += rdlen;
        }
        return 0;
    }

    private static int skipName(byte[] m, int pos) {
        while (pos < m.length) {
            int l = m[pos] & 255;
            if (l == 0) return pos + 1;
            if ((l & 0xC0) == 0xC0) return pos + 2;
            pos += l + 1;
        }
        return pos;
    }

    // ------------------------------------------------------------------ small helpers

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) throw new IOException("closed");
        return b;
    }

    private static String readString(InputStream in, int len) throws IOException {
        byte[] b = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(b, off, len - off);
            if (n < 0) throw new IOException("closed");
            off += n;
        }
        return new String(b, ISO);
    }

    private static String readHead(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) >= 0) {
            sb.append((char) b);
            int n = sb.length();
            if (n >= 4 && sb.charAt(n - 1) == '\n' && sb.charAt(n - 2) == '\r' && sb.charAt(n - 3) == '\n' && sb.charAt(n - 4) == '\r') {
                return sb.substring(0, n - 4);
            }
            if (n > 16384) return null;
        }
        return null;
    }

    private static int parsePort(String v, int def) {
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return def; }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static void closeQuiet(Socket s) {
        try { s.close(); } catch (IOException ignored) { }
    }
}

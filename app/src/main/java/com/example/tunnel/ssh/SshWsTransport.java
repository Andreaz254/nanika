package com.example.tunnel.ssh;

import com.example.tunnel.LogFilter;
import com.example.tunnel.TunnelState;
import com.jcraft.jsch.Proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The byte pipe JSch runs SSH over:
 *   TCP to the proxy host  ->  (TLS with SNI, or plain)  ->  payload  ->  "101 / 200" reply  ->  SSH bytes.
 *
 * With SNI (TLS):    TCP to proxyHost:proxyPort (443), TLS handshake with SNI = the SNI field.
 * Without SNI:       plain TCP to proxyHost:proxyPort (80).
 * After the reply the stream is raw SSH (what HTTP-injector style servers do) or, if wsFraming is on,
 * RFC 6455 binary frames.
 */
public final class SshWsTransport implements Proxy {

    public static final class Settings {
        public String proxyHost;
        public int proxyPort;
        public boolean tls;
        public String sni;
        public boolean insecure;
        public String payload;
        public String sshHost;
        public int sshPort = 22;
        public boolean wsFraming;
        public SocketFactory socketFactory;
    }

    private static final Charset LATIN1 = Charset.forName("ISO-8859-1");
    private static final int SPLIT_DELAY_MS = 250;
    private static final int PEEK_MS = 700;
    private static final int MAX_HEAD = 8192;
    private static final int MAX_REDIRECTS = 4;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Settings s;
    private volatile Socket socket;
    private InputStream in;
    private OutputStream out;

    public SshWsTransport(Settings settings) { this.s = settings; }

    // ------------------------------------------------------------------ com.jcraft.jsch.Proxy

    @Override
    public void connect(com.jcraft.jsch.SocketFactory jschFactory, String host, int port, int timeout) throws Exception {
        int to = timeout > 0 ? timeout : 20000;
        SocketFactory factory = s.socketFactory != null ? s.socketFactory : SocketFactory.getDefault();
        String curHost = s.proxyHost;
        int curPort = s.proxyPort;
        boolean curTls = s.tls;
        String curSni = s.sni;
        for (int hop = 0; ; hop++) {
            Socket raw = factory.createSocket();
            socket = raw;
            try {
                TunnelState.log("SSH: connecting to " + curHost + ":" + curPort
                        + (curTls ? " (TLS, SNI " + curSni + ")" : " (plain, no SNI)"));
                raw.connect(new InetSocketAddress(curHost, curPort), to);
                raw.setTcpNoDelay(true);
                raw.setKeepAlive(true);

                Socket sock = raw;
                if (curTls) {
                    sock = startTls(raw, to, curHost, curPort, curSni);
                    socket = sock;
                }
                sock.setSoTimeout(to);
                InputStream rin = sock.getInputStream();
                OutputStream rout = sock.getOutputStream();

                sendPayload(rout);

                PushbackInputStream pin = new PushbackInputStream(rin, 16);
                LogFilter.Redirect redirect = readUpgradeReply(sock, pin);
                if (redirect != null) {
                    close();
                    if (redirect.host == null) {
                        throw new IOException("the proxy redirected to another path (" + redirect.path
                                + ") - change the path in the payload");
                    }
                    if (hop >= MAX_REDIRECTS) throw new IOException("too many redirects (" + MAX_REDIRECTS + ")");
                    curHost = redirect.host;
                    curPort = redirect.port;
                    curTls = redirect.tls;
                    curSni = redirect.host;
                    TunnelState.hide(curHost);
                    TunnelState.log("Redirect: reconnecting to " + curHost + ":" + curPort
                            + (curTls ? " (TLS)" : " (plain)") + "  [" + (hop + 1) + "/" + MAX_REDIRECTS + "]");
                    continue;
                }
                sock.setSoTimeout(to);

                if (s.wsFraming) {
                    WsFrames.Out fo = new WsFrames.Out(rout);
                    out = fo;
                    in = new WsFrames.In(pin, fo);
                } else {
                    out = rout;
                    in = pin;
                }
                return;
            } catch (Exception e) {
                close();
                throw e;
            }
        }
    }

    @Override public InputStream getInputStream() { return in; }

    @Override public OutputStream getOutputStream() { return out; }

    @Override public Socket getSocket() { return socket; }

    @Override
    public void close() {
        Socket sk = socket;
        if (sk != null) {
            try { sk.close(); } catch (IOException ignored) { }
        }
    }

    // ------------------------------------------------------------------ TLS (with SNI)

    private Socket startTls(Socket raw, int timeout, String proxyHost, int proxyPort, String sni) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        if (s.insecure) {
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
                @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, RANDOM);
        } else {
            ctx.init(null, null, null);
        }
        SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(raw, sni, proxyPort, true);
        boolean engineVerifies = configureTls(ssl, sni, !s.insecure);
        ssl.setSoTimeout(timeout);
        try {
            ssl.startHandshake();
            if (!s.insecure && !engineVerifies
                    && !HttpsURLConnection.getDefaultHostnameVerifier().verify(sni, ssl.getSession())) {
                throw new SSLException("certificate does not match " + sni);
            }
        } catch (SSLException e) {
            throw new IOException("TLS handshake with " + proxyHost + ":" + proxyPort + " (SNI " + sni + ") failed: "
                    + e.getMessage() + (s.insecure ? "" : "  - if the certificate does not belong to the SNI host, "
                    + "tick 'Skip TLS certificate verification'"), e);
        }
        TunnelState.log("SSH: TLS up (" + ssl.getSession().getProtocol() + ", SNI " + sni + ")");
        return ssl;
    }

    /** Sets the SNI explicitly and, when verifying, asks the TLS engine to check the host name. */
    @SuppressWarnings("NewApi")
    private static boolean configureTls(SSLSocket ssl, String sni, boolean verify) {
        boolean verifies = false;
        try {
            SSLParameters p = ssl.getSSLParameters();
            try {
                p.setServerNames(Collections.<SNIServerName>singletonList(new SNIHostName(sni)));
            } catch (Throwable ignored) {
                // old Android or an IP literal: createSocket(host) already set the SNI where possible
            }
            if (verify) {
                p.setEndpointIdentificationAlgorithm("HTTPS");
                verifies = true;
            }
            ssl.setSSLParameters(p);
        } catch (Throwable t) {
            verifies = false;
        }
        return verifies;
    }

    // ------------------------------------------------------------------ payload + reply

    private void sendPayload(OutputStream rout) throws Exception {
        SshPayload.Context c = new SshPayload.Context();
        c.host = s.sshHost;
        c.port = s.sshPort;
        c.sni = s.sni == null ? "" : s.sni;
        c.proxyHost = s.proxyHost;
        c.proxyPort = s.proxyPort;
        byte[] key = new byte[16];
        RANDOM.nextBytes(key);
        c.wsKey = base64(key);

        List<byte[]> parts = SshPayload.expand(s.payload, s.wsFraming, c);
        if (parts.isEmpty()) throw new IOException("the payload is empty after expanding it");
        int total = 0;
        for (byte[] p : parts) total += p.length;
        TunnelState.log("SSH: sending payload (" + total + " bytes, " + parts.size() + " part"
                + (parts.size() == 1 ? "" : "s") + ")");
        if (!SshPayload.endsWithBlankLine(parts)) {
            TunnelState.log("SSH: warning - the payload does not end with a blank line ([crlf][crlf]); "
                    + "an HTTP proxy will keep waiting for the rest of the request");
        }
        for (int i = 0; i < parts.size(); i++) {
            rout.write(parts.get(i));
            rout.flush();
            if (i < parts.size() - 1) Thread.sleep(SPLIT_DELAY_MS);
        }
    }

    /**
     * Consumes the proxy's HTTP reply (101 Switching Protocols, 200 Connection established, ...), including
     * several replies in a row, and logs it: the status line plus only the relevant headers.
     * Anything that is not an HTTP reply (e.g. the "SSH-2.0-..." banner) is left in the stream for JSch.
     *
     * @return the redirect target if the proxy answered with a 3xx + Location, otherwise null
     */
    private LogFilter.Redirect readUpgradeReply(Socket sock, PushbackInputStream in) throws IOException {
        boolean first = true;
        while (true) {
            int old = sock.getSoTimeout();
            if (!first) sock.setSoTimeout(PEEK_MS);
            byte[] p = new byte[5];
            int got = 0;
            boolean timedOut = false;
            try {
                while (got < 5) {
                    int r = in.read(p, got, 5 - got);
                    if (r < 0) break;
                    got += r;
                }
            } catch (SocketTimeoutException e) {
                if (first) throw new IOException("no reply from the proxy within " + (old / 1000) + " s "
                        + "(is the payload complete and does it reach a WebSocket/SSH server?)");
                timedOut = true;
            } finally {
                if (!first) sock.setSoTimeout(old);
            }
            if (got > 0) in.unread(p, 0, got);
            if (got < 5 || timedOut || !"HTTP/".equals(new String(p, 0, 5, LATIN1))) {
                if (first && got == 0) throw new IOException("the proxy closed the connection without replying");
                return null;                                  // SSH banner (or nothing yet) - not our business
            }
            first = false;

            String head = readHead(in);
            String status = head.substring(0, indexOfEol(head));
            List<String[]> headers = parseHeaders(head);
            LogFilter.logReply("Server reply: ", status, headers);
            int code = statusCode(status);
            if (LogFilter.isRedirect(code)) {
                String loc = null;
                for (String[] h : headers) if ("location".equalsIgnoreCase(h[0].trim())) loc = h[1];
                LogFilter.Redirect r = LogFilter.parseLocation(loc);
                if (r == null) throw new IOException("the proxy sent " + status + " without a usable Location");
                return r;
            }
            if (code < 100 || code >= 300) {
                throw new IOException("the proxy rejected the payload: " + status);
            }
        }
    }

    private static List<String[]> parseHeaders(String head) {
        List<String[]> out = new ArrayList<String[]>();
        String[] lines = head.split("\r?\n");
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) out.add(new String[]{lines[i].substring(0, c), lines[i].substring(c + 1).trim()});
        }
        return out;
    }

    private static int indexOfEol(String head) {
        int i = head.indexOf('\n');
        if (i < 0) i = head.length();
        if (i > 0 && head.charAt(i - 1) == '\r') i--;
        return i;
    }

    private static int statusCode(String status) {
        String[] t = status.split(" ");
        if (t.length < 2) return -1;
        try { return Integer.parseInt(t[1]); } catch (NumberFormatException e) { return -1; }
    }

    /** Reads up to and including the blank line that ends an HTTP header block. */
    private static String readHead(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int state = 0;                                         // matches \r\n\r\n or \n\n
        while (sb.length() < MAX_HEAD) {
            int b = in.read();
            if (b < 0) throw new IOException("the proxy closed the connection in the middle of its reply");
            sb.append((char) b);
            if (b == '\n') {
                state++;
                if (state == 2) return sb.toString();
            } else if (b != '\r') {
                state = 0;
            }
        }
        throw new IOException("the proxy's reply is not valid HTTP (header too long)");
    }

    private static String base64(byte[] d) {
        final String A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i += 3) {
            int n = (d[i] & 0xFF) << 16 | (i + 1 < d.length ? (d[i + 1] & 0xFF) << 8 : 0) | (i + 2 < d.length ? d[i + 2] & 0xFF : 0);
            sb.append(A.charAt(n >> 18 & 63)).append(A.charAt(n >> 12 & 63));
            sb.append(i + 1 < d.length ? A.charAt(n >> 6 & 63) : '=').append(i + 2 < d.length ? A.charAt(n & 63) : '=');
        }
        return sb.toString();
    }
}

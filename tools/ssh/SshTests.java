import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.ProtocolRegistry;
import com.example.tunnel.protocol.TunnelProtocol;
import com.example.tunnel.ssh.SshPayload;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** args: <dir containing ports.json>. Exit code 1 if any check fails. */
public class SshTests {
    static int pass, fail;
    static final ByteArrayOutputStream logBuf = new ByteArrayOutputStream();
    static Map<String, Integer> ports = new HashMap<String, Integer>();

    static void check(String name, boolean ok) {
        if (ok) pass++; else fail++;
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
    }

    static String logText() { return new String(logBuf.toByteArray(), StandardCharsets.UTF_8); }

    // ---------------------------------------------------------------- payload expansion (pure)
    static String exp(String t, boolean framed) {
        SshPayload.Context c = new SshPayload.Context();
        c.host = "ssh.example"; c.port = 22; c.sni = "bug.host"; c.proxyHost = "1.2.3.4"; c.proxyPort = 443; c.wsKey = "KEY==";
        StringBuilder sb = new StringBuilder();
        for (byte[] p : SshPayload.expand(t, framed, c)) sb.append(new String(p, StandardCharsets.UTF_8)).append('|');
        return sb.toString();
    }

    static void payloadTests() {
        System.out.println("== payload placeholders ==");
        check("tokens", exp("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]", false).equals("GET / HTTP/1.1\r\nHost: ssh.example\r\n\r\n|"));
        check("case-insensitive tokens", exp("A[CRLF]B[Lf]C[cR]", false).equals("A\r\nB\nC\r|"));
        check("host_port/port/sni/proxy", exp("[host_port] [port] [sni] [proxy]:[proxy_port]", false).equals("ssh.example:22 22 bug.host 1.2.3.4:443|"));
        check("[split] makes parts", exp("AAA[split]BBB[crlf]", false).equals("AAA|BBB\r\n|"));
        check("real newlines without tokens -> CRLF", exp("GET / HTTP/1.1\nHost: x\n\n", false).equals("GET / HTTP/1.1\r\nHost: x\r\n\r\n|"));
        check("real newlines ignored when tokens used", exp("GET / HTTP/1.1[crlf]\nHost: x[crlf]\n[crlf]", false).equals("GET / HTTP/1.1\r\nHost: x\r\n\r\n|"));
        check("\\r\\n escape text", exp("GET /\\r\\nHost: x\\r\\n\\r\\n", false).equals("GET /\r\nHost: x\r\n\r\n|"));
        check("unknown token kept", exp("[foo][crlf]", false).equals("[foo]\r\n|"));
        check("empty -> default raw", exp("  ", false).startsWith("GET / HTTP/1.1\r\nHost: ssh.example\r\nUpgrade: websocket"));
        check("empty -> default framed has key", exp("", true).contains("Sec-WebSocket-Key: KEY==\r\n"));
        SshPayload.Context c = new SshPayload.Context(); c.proxyHost = "p.example"; c.wsKey = "k";
        check("[host] falls back to proxy host", new String(SshPayload.expand("[host]", false, c).get(0)).equals("p.example"));
        check("blank-line detector", SshPayload.endsWithBlankLine(SshPayload.expand("GET /[crlf][crlf]", false, c))
                && !SshPayload.endsWithBlankLine(SshPayload.expand("GET /[crlf]", false, c)));
    }

    // ---------------------------------------------------------------- helpers for the connector tests
    static ProtocolConfig cfg(String front, boolean tls, String payload, boolean framed) {
        ProtocolConfig c = new ProtocolConfig();
        c.sshUser = "tester"; c.sshPassword = "s3cret"; c.sshHost = "ssh.example.test"; c.sshPort = 22;
        c.proxyHost = "127.0.0.1"; c.proxyPort = ports.get(front);
        c.tls = tls; c.sni = tls ? "bug.example.test" : ""; c.insecureTls = true;
        c.payload = payload; c.wsFraming = framed;
        return c;
    }

    static final class Rx implements UpstreamListener {
        final CountDownLatch opened = new CountDownLatch(1), closedL = new CountDownLatch(1);
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        volatile Boolean closedError;
        public void onOpen() { opened.countDown(); }
        public void onData(byte[] d, int o, int l) { synchronized (buf) { buf.write(d, o, l); } }
        public void onClosed(boolean e) { closedError = e; closedL.countDown(); }
        int size() { synchronized (buf) { return buf.size(); } }
        byte[] bytes() { synchronized (buf) { return buf.toByteArray(); } }
    }

    /** Opens a tunnelled connection to the echo server, sends data in engine-sized writes, expects it back unchanged. */
    static boolean echo(UpstreamConnector c, byte[] data, String tag) throws Exception {
        Rx rx = new Rx();
        UpstreamStream s = c.open("127.0.0.1", ports.get("echo"), rx);
        if (!rx.opened.await(25, TimeUnit.SECONDS)) { System.out.println("    [" + tag + "] never opened"); s.close(); return false; }
        for (int i = 0; i < data.length; i += 1400) s.write(data, i, Math.min(1400, data.length - i));
        long end = System.currentTimeMillis() + 30000;
        while (rx.size() < data.length && System.currentTimeMillis() < end) Thread.sleep(10);
        boolean ok = Arrays.equals(data, rx.bytes());
        if (!ok) System.out.println("    [" + tag + "] got " + rx.size() + " of " + data.length + " bytes");
        s.close();
        return ok;
    }

    static byte[] random(int n, long seed) { byte[] b = new byte[n]; new Random(seed).nextBytes(b); return b; }

    static String control(String cmd) throws Exception {
        try (Socket s = new Socket("127.0.0.1", ports.get("control"))) {
            s.getOutputStream().write((cmd + "\n").getBytes()); s.getOutputStream().flush();
            return new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        }
    }

    static UpstreamConnector make(ProtocolConfig c) throws Exception {
        TunnelProtocol p = ProtocolRegistry.require("SSH");
        String err = p.validate(c);
        if (err != null) throw new IOException(err);
        return p.createConnector(null, c);
    }

    // ---------------------------------------------------------------- the tests
    public static void main(String[] a) throws Exception {
        // capture the log lines (stub TunnelState prints to stdout) while still showing them
        final PrintStream real = System.out;
        System.setOut(new PrintStream(new OutputStream() {
            public void write(int b) { logBuf.write(b); real.write(b); }
            public void write(byte[] b, int o, int l) { logBuf.write(b, o, l); real.write(b, o, l); }
        }, true));

        String json = new String(java.nio.file.Files.readAllBytes(new File(a[0], "ports.json").toPath()));
        for (String kv : json.replaceAll("[{}\" ]", "").split(",")) { String[] p = kv.split(":"); ports.put(p[0], Integer.parseInt(p[1])); }

        payloadTests();

        System.out.println("== registry / validation ==");
        check("SSH is registered", "SSH".equals(ProtocolRegistry.require("ssh").id()));
        check("VLESS + VMess still registered", "VLESS".equals(ProtocolRegistry.require("VLESS").id()) && "VMess".equals(ProtocolRegistry.require("vmess").id()));
        ProtocolConfig bad = cfg("plain", false, "", false); bad.sshUser = " ";
        check("empty username rejected", ProtocolRegistry.require("SSH").validate(bad) != null);
        bad = cfg("plain", true, "", false); bad.sni = "";
        check("TLS without SNI rejected", ProtocolRegistry.require("SSH").validate(bad) != null);
        bad = cfg("plain", false, "", false); bad.proxyPort = 0;
        check("bad proxy port rejected", ProtocolRegistry.require("SSH").validate(bad) != null);
        check("Non-TLS does not need an SNI", ProtocolRegistry.require("SSH").validate(cfg("plain", false, "", false)) == null);

        String payload = "GET /ws HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]";

        System.out.println("== SSH over WebSocket, WITHOUT SNI (plain, \"port 80\") ==");
        UpstreamConnector c1 = make(cfg("plain", false, payload, false));
        check("echo 300 KB through ssh channel", echo(c1, random(300_000, 1), "plain"));
        String req = control("REQ plain");
        check("payload reached the proxy with [host] expanded", req.contains("GET /ws HTTP/1.1") && req.contains("Host: ssh.example.test"));
        check("log shows login + host key", logText().contains("SSH: logged in") && logText().contains("host key"));
        check("client half-close (EOF) reaches the target; reply still arrives; clean close", halfClose(c1));
        check("refused target -> onClosed(error)", refused(c1));
        check("session still usable after a refused channel", echo(c1, random(5000, 2), "after-refusal"));

        System.out.println("== 30 parallel flows over ONE ssh session ==");
        check("30 x 200 KB echoes, byte exact", parallel(c1, 30, 200_000));

        System.out.println("== reconnect after the server drops the SSH session ==");
        control("KILL");
        Thread.sleep(500);
        check("new flow reconnects automatically", echo(c1, random(20_000, 3), "reconnect"));
        check("reconnect logged", logText().contains("session was lost") || logText().contains("logged in"));
        c1.getClass().getMethod("close").invoke(c1);

        System.out.println("== SSH over WebSocket, WITH SNI (TLS, \"port 443\") ==");
        ProtocolConfig tc = cfg("tls", true, payload, false);
        UpstreamConnector c2 = make(tc);
        check("echo 300 KB through TLS+SNI", echo(c2, random(300_000, 4), "tls"));
        String sni = control("SNI");
        check("server saw SNI = bug.example.test (" + sni + ")", sni.contains("bug.example.test"));
        check("payload was sent inside TLS", control("REQ tls").contains("Host: ssh.example.test"));
        c2.getClass().getMethod("close").invoke(c2);

        System.out.println("== TLS certificate verification ==");
        ProtocolConfig strict = cfg("tls", true, payload, false); strict.insecureTls = false;
        UpstreamConnector c3 = make(strict);
        Rx r3 = new Rx(); c3.open("127.0.0.1", ports.get("echo"), r3);
        check("self-signed cert refused when verification is on", r3.closedL.await(25, TimeUnit.SECONDS) && Boolean.TRUE.equals(r3.closedError)
                && logText().contains("tick 'Skip TLS certificate verification'"));
        c3.getClass().getMethod("close").invoke(c3);

        System.out.println("== proxy replies 200 + 101 in a row ==");
        UpstreamConnector c4 = make(cfg("double", false, payload, false));
        check("echo through double reply", echo(c4, random(50_000, 5), "double"));
        check("both replies were consumed", logText().contains("proxy replied: HTTP/1.1 200 Connection established")
                && logText().contains("proxy replied: HTTP/1.1 101"));
        c4.getClass().getMethod("close").invoke(c4);

        System.out.println("== real WebSocket framing (default payload, pings, split frames) ==");
        UpstreamConnector c5 = make(cfg("framed", false, "", true));
        check("echo 500 KB through RFC6455 frames", echo(c5, random(500_000, 6), "framed"));
        check("default framed payload carried Sec-WebSocket-Key", control("REQ framed").contains("Sec-WebSocket-Key:"));
        check("server saw only masked client frames, no errors", control("ERR").equals("[]"));
        c5.getClass().getMethod("close").invoke(c5);
        UpstreamConnector c5b = make(cfg("framedtls", true, "", true));
        check("framing inside TLS+SNI", echo(c5b, random(100_000, 7), "framedtls"));
        c5b.getClass().getMethod("close").invoke(c5b);

        System.out.println("== error reporting ==");
        ProtocolConfig wp = cfg("plain", false, payload, false); wp.sshPassword = "nope";
        UpstreamConnector c6 = make(wp);
        Rx r6 = new Rx(); c6.open("127.0.0.1", ports.get("echo"), r6);
        check("wrong password -> error + clear message", r6.closedL.await(25, TimeUnit.SECONDS) && Boolean.TRUE.equals(r6.closedError)
                && logText().contains("SSH login failed"));
        c6.getClass().getMethod("close").invoke(c6);

        UpstreamConnector c7 = make(cfg("plain", false, "GET / HTTP/1.1[crlf]Host: x[crlf][crlf]", false));   // no Upgrade header -> 403
        Rx r7 = new Rx(); c7.open("127.0.0.1", ports.get("echo"), r7);
        check("403 from the proxy -> error + clear message", r7.closedL.await(25, TimeUnit.SECONDS) && Boolean.TRUE.equals(r7.closedError)
                && logText().contains("the proxy rejected the payload: HTTP/1.1 403"));
        c7.getClass().getMethod("close").invoke(c7);

        ProtocolConfig dead = cfg("plain", false, payload, false); dead.proxyPort = ports.get("closed");
        UpstreamConnector c8 = make(dead);
        Rx r8 = new Rx(); c8.open("127.0.0.1", ports.get("echo"), r8);
        check("proxy port closed -> error", r8.closedL.await(25, TimeUnit.SECONDS) && Boolean.TRUE.equals(r8.closedError));
        c8.getClass().getMethod("close").invoke(c8);

        control("QUIT");
        System.out.println();
        System.out.println(pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    /** write everything, closeWrite(): the echo server sees EOF, finishes echoing, closes -> onClosed(false). */
    static boolean halfClose(UpstreamConnector c) throws Exception {
        byte[] data = random(150_000, 77);
        Rx rx = new Rx();
        UpstreamStream s = c.open("127.0.0.1", ports.get("echo"), rx);
        if (!rx.opened.await(25, TimeUnit.SECONDS)) return false;
        for (int i = 0; i < data.length; i += 1400) s.write(data, i, Math.min(1400, data.length - i));
        s.closeWrite();
        boolean closed = rx.closedL.await(30, TimeUnit.SECONDS);
        boolean ok = closed && Boolean.FALSE.equals(rx.closedError) && Arrays.equals(data, rx.bytes());
        if (!ok) System.out.println("    closed=" + closed + " err=" + rx.closedError + " got=" + rx.size());
        s.close();
        return ok;
    }

    static boolean refused(UpstreamConnector c) throws Exception {
        Rx rx = new Rx();
        c.open("127.0.0.1", ports.get("closed"), rx);
        return rx.closedL.await(15, TimeUnit.SECONDS) && Boolean.TRUE.equals(rx.closedError) && rx.opened.getCount() == 1;
    }

    static boolean parallel(final UpstreamConnector c, int n, final int size) throws Exception {
        ExecutorService ex = Executors.newFixedThreadPool(n);
        List<Future<Boolean>> fs = new ArrayList<Future<Boolean>>();
        for (int i = 0; i < n; i++) {
            final int seed = 100 + i;
            fs.add(ex.submit(new Callable<Boolean>() {
                public Boolean call() throws Exception { return echo(c, random(size, seed), "par" + seed); }
            }));
        }
        boolean ok = true;
        for (Future<Boolean> f : fs) ok &= f.get(90, TimeUnit.SECONDS);
        ex.shutdownNow();
        return ok;
    }
}

import com.example.tunnel.engine.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test harness: runs the PacketEngine, reading/writing length-prefixed IP packets on stdin/stdout
 * (a Python script bridges these to a real Linux TUN device). Upstream "tunnels" are plain loopback
 * TCP sockets chosen by a destination mapping, so the engine is exercised against the real kernel
 * TCP stack without needing a VLESS server.
 *
 * usage: E2EHarness 10.0.0.50:80=127.0.0.1:18080 8.8.8.8:53=127.0.0.1:15353 ...
 */
public class E2EHarness {
    static final Map<String, String> MAP = new HashMap<>();
    static final ExecutorService POOL = Executors.newCachedThreadPool();

    static final class SockStream implements UpstreamStream {
        final Socket s = new Socket();
        final UpstreamListener l;
        final ExecutorService wr = Executors.newSingleThreadExecutor();
        final AtomicInteger pend = new AtomicInteger();
        volatile boolean closed;
        OutputStream out;

        SockStream(String target, UpstreamListener l) {
            this.l = l;
            POOL.execute(() -> {
                if (target == null) { l.onClosed(true); return; }
                try {
                    String[] hp = target.split(":");
                    s.connect(new InetSocketAddress(hp[0], Integer.parseInt(hp[1])), 3000);
                    out = s.getOutputStream();
                } catch (IOException e) { l.onClosed(true); return; }
                l.onOpen();
                byte[] buf = new byte[16384];
                try {
                    InputStream in = s.getInputStream();
                    int n;
                    while ((n = in.read(buf)) > 0) l.onData(buf, 0, n);
                    l.onClosed(false);
                } catch (IOException e) { l.onClosed(!closed); }
            });
        }
        public void write(byte[] d, int off, int len) {
            final byte[] c = Arrays.copyOfRange(d, off, off + len);
            pend.addAndGet(len);
            wr.execute(() -> { try { out.write(c); out.flush(); } catch (IOException e) { } finally { pend.addAndGet(-c.length); } });
        }
        public int pendingBytes() { return pend.get(); }
        public void closeWrite() { wr.execute(() -> { try { s.shutdownOutput(); } catch (IOException e) { } }); }
        public void close() { closed = true; try { s.close(); } catch (IOException e) { } wr.shutdown(); }
    }

    public static void main(String[] args) throws Exception {
        for (String a : args) { String[] kv = a.split("="); MAP.put(kv[0], kv[1]); }
        final DataInputStream in = new DataInputStream(new BufferedInputStream(System.in, 1 << 16));
        final DataOutputStream out = new DataOutputStream(new BufferedOutputStream(System.out, 1 << 16));

        PacketSink sink = (b, off, len) -> {
            synchronized (out) { out.writeInt(len); out.write(b, off, len); out.flush(); }
        };
        UpstreamConnector conn = (ip, port, l) -> {
            String t = MAP.get(ip + ":" + port);
            System.err.println("[connector] open " + ip + ":" + port + " -> " + t);
            return new SockStream(t, l);
        };
        PacketEngine.Config cfg = new PacketEngine.Config();
        cfg.dnsUpstream = "8.8.8.8";
        PacketEngine eng = new PacketEngine(sink, conn, cfg, m -> System.err.println("[engine] " + m));
        eng.start();
        Thread dbg = new Thread(() -> { while (true) { try { Thread.sleep(3000); } catch (InterruptedException e) { return; }
            String d = eng.dump(); if (!d.isEmpty()) System.err.println("[dump]\n" + d); } });
        dbg.setDaemon(true); dbg.start();
        byte[] buf = new byte[70000];
        try {
            while (true) {
                int len = in.readInt();
                in.readFully(buf, 0, len);
                eng.onPacket(buf, len);
            }
        } catch (EOFException e) { }
        System.err.println("[harness] flows at exit: " + eng.activeFlows());
        eng.shutdown();
        System.exit(0);
    }
}

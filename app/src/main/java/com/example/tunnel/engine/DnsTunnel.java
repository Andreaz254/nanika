package com.example.tunnel.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

/**
 * Turns the phone's UDP DNS queries into DNS-over-TCP (RFC 7766) carried by one persistent
 * upstream stream, and turns the answers back into UDP packets for the phone.
 */
public final class DnsTunnel {
    private static final long PENDING_TTL_MS = 8000;
    private static final long IDLE_CLOSE_MS = 45000;

    private static final class Pending {
        final int clientIp, clientPort, serverIp, origId;
        final long created;
        Pending(int clientIp, int clientPort, int serverIp, int origId, long created) {
            this.clientIp = clientIp; this.clientPort = clientPort; this.serverIp = serverIp;
            this.origId = origId; this.created = created;
        }
    }

    private final class Conn implements UpstreamListener {
        UpstreamStream stream;
        boolean open;
        final ArrayList<byte[]> backlog = new ArrayList<byte[]>();
        byte[] rx = new byte[2048];
        int rxLen;

        @Override public void onOpen() {
            synchronized (DnsTunnel.this) {
                if (current != this) return;
                open = true;
                for (byte[] f : backlog) stream.write(f, 0, f.length);
                backlog.clear();
            }
        }

        @Override public void onData(byte[] d, int off, int len) {
            synchronized (DnsTunnel.this) {
                if (current != this) return;
                if (rxLen + len > rx.length) {
                    byte[] n = new byte[Math.max(rx.length * 2, rxLen + len)];
                    System.arraycopy(rx, 0, n, 0, rxLen);
                    rx = n;
                }
                System.arraycopy(d, off, rx, rxLen, len);
                rxLen += len;
                while (rxLen >= 2) {
                    int n = Ip.u16(rx, 0);
                    if (rxLen < 2 + n) break;
                    if (n >= 12) deliver(rx, 2, n);
                    System.arraycopy(rx, 2 + n, rx, 0, rxLen - 2 - n);
                    rxLen -= 2 + n;
                }
            }
        }

        @Override public void onClosed(boolean error) {
            synchronized (DnsTunnel.this) {
                if (current == this) {
                    current = null;
                    pending.clear();
                }
            }
        }
    }

    private final PacketEngine eng;
    private final UpstreamConnector connector;
    private final String upstream;
    private final boolean suppressAaaa;
    private final Map<Integer, Pending> pending = new HashMap<Integer, Pending>();
    private final Random rnd = new Random();
    private Conn current;
    private int nextId = rnd.nextInt(65536);
    private long lastUse;

    DnsTunnel(PacketEngine eng, UpstreamConnector connector, String upstream, boolean suppressAaaa) {
        this.eng = eng;
        this.connector = connector;
        this.upstream = upstream;
        this.suppressAaaa = suppressAaaa;
    }

    synchronized void query(int clientIp, int clientPort, int serverIp, byte[] b, int off, int len) {
        if (len < 12) return;
        long now = System.nanoTime() / 1000000L;
        lastUse = now;

        if (suppressAaaa && isAaaa(b, off, len)) {
            byte[] r = emptyAnswer(b, off, len);
            if (r != null) {
                eng.sendUdp(serverIp, 53, clientIp, clientPort, r);
                return;
            }
        }
        if (pending.size() >= 256) return;

        int id = -1;
        for (int i = 0; i < 65536; i++) {                    // unique internal id
            int c = (nextId + i) & 0xFFFF;
            if (!pending.containsKey(c)) { id = c; break; }
        }
        if (id < 0) return;
        nextId = id + 1;

        byte[] frame = new byte[2 + len];
        Ip.p16(frame, 0, len);
        System.arraycopy(b, off, frame, 2, len);
        int origId = Ip.u16(b, off);
        Ip.p16(frame, 2, id);
        pending.put(id, new Pending(clientIp, clientPort, serverIp, origId, now));

        if (current == null) {
            Conn c = new Conn();
            current = c;
            try {
                c.stream = connector.open(upstream, 53, c);
            } catch (RuntimeException e) {
                current = null;
                pending.remove(id);
                eng.log("DNS upstream open failed: " + e);
                return;
            }
        }
        Conn c = current;
        if (c == null) return;                                // upstream failed synchronously
        if (c.open) c.stream.write(frame, 0, frame.length);
        else c.backlog.add(frame);
    }

    private void deliver(byte[] r, int off, int n) {
        int id = Ip.u16(r, off);
        Pending p = pending.remove(id);
        if (p == null) return;
        byte[] out = new byte[n];
        System.arraycopy(r, off, out, 0, n);
        Ip.p16(out, 0, p.origId);
        eng.sendUdp(p.serverIp, 53, p.clientIp, p.clientPort, out);
    }

    synchronized void tick(long now) {
        for (Iterator<Pending> it = pending.values().iterator(); it.hasNext(); ) {
            if (now - it.next().created > PENDING_TTL_MS) it.remove();
        }
        if (current != null && pending.isEmpty() && now - lastUse > IDLE_CLOSE_MS) {
            Conn c = current;
            current = null;
            if (c.stream != null) c.stream.close();
        }
    }

    synchronized void shutdown() {
        Conn c = current;
        current = null;
        pending.clear();
        if (c != null && c.stream != null) c.stream.close();
    }

    // ------------------------------------------------------------------ DNS wire helpers

    /** Returns the offset just past the (single) question, or -1 if malformed. Sets qtype via out[0]. */
    private static int questionEnd(byte[] b, int off, int len, int[] qtype) {
        if (Ip.u16(b, off + 4) != 1) return -1;               // QDCOUNT must be 1
        int p = off + 12, end = off + len;
        while (p < end) {
            int l = b[p] & 0xFF;
            if (l == 0) break;
            if ((l & 0xC0) != 0) return -1;                    // no compression in a question
            p += 1 + l;
        }
        p++;                                                   // root label
        if (p + 4 > end) return -1;
        qtype[0] = Ip.u16(b, p);
        return p + 4;
    }

    private static boolean isAaaa(byte[] b, int off, int len) {
        int[] qt = new int[1];
        return questionEnd(b, off, len, qt) > 0 && qt[0] == 28;
    }

    /** NOERROR response with zero answers for the same question. */
    private static byte[] emptyAnswer(byte[] b, int off, int len) {
        int[] qt = new int[1];
        int qe = questionEnd(b, off, len, qt);
        if (qe < 0) return null;
        int n = qe - off;
        byte[] r = new byte[n];
        System.arraycopy(b, off, r, 0, n);
        int flags = Ip.u16(b, off + 2);
        int rd = flags & 0x0100;
        int opcode = flags & 0x7800;
        Ip.p16(r, 2, 0x8000 | opcode | rd | 0x0080);           // QR, opcode, RD, RA, RCODE=0
        Ip.p16(r, 6, 0);
        Ip.p16(r, 8, 0);
        Ip.p16(r, 10, 0);
        return r;
    }

    /** A plain "A example.com" query (used by the app's connectivity pre-check). */
    public static byte[] probeQuery(int id) {
        byte[] name = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
        byte[] q = new byte[12 + name.length + 4];
        Ip.p16(q, 0, id);
        Ip.p16(q, 2, 0x0100);
        Ip.p16(q, 4, 1);
        System.arraycopy(name, 0, q, 12, name.length);
        Ip.p16(q, 12 + name.length, 1);
        Ip.p16(q, 14 + name.length, 1);
        return q;
    }
}

package com.example.tunnel.engine;

import java.util.concurrent.atomic.AtomicInteger;

/** Builds IPv4/TCP and IPv4/UDP packets with correct checksums. */
final class Packets {
    private Packets() {}

    private static final AtomicInteger IP_ID = new AtomicInteger((int) (System.nanoTime() & 0xFFFF));

    private static void ipHeader(byte[] p, int total, int proto, int src, int dst) {
        p[0] = 0x45;
        p[1] = 0;
        Ip.p16(p, 2, total);
        Ip.p16(p, 4, IP_ID.incrementAndGet() & 0xFFFF);
        Ip.p16(p, 6, 0x4000); // DF
        p[8] = 64;
        p[9] = (byte) proto;
        Ip.p16(p, 10, 0);
        Ip.p32(p, 12, src);
        Ip.p32(p, 16, dst);
        Ip.p16(p, 10, Ip.fold(Ip.sum(p, 0, 20, 0)));
    }

    private static long pseudo(int src, int dst, int proto, int l4len) {
        return (src >>> 16) + (src & 0xFFFF) + (dst >>> 16) + (dst & 0xFFFF) + proto + l4len;
    }

    static byte[] tcp(int src, int dst, int sport, int dport, int seq, int ack, int flags, int window,
                      int mssOpt, byte[] data, int off, int len) {
        int tcpHdr = mssOpt > 0 ? 24 : 20;
        int l4 = tcpHdr + len;
        int total = 20 + l4;
        byte[] p = new byte[total];
        ipHeader(p, total, 6, src, dst);
        int t = 20;
        Ip.p16(p, t, sport);
        Ip.p16(p, t + 2, dport);
        Ip.p32(p, t + 4, seq);
        Ip.p32(p, t + 8, ack);
        p[t + 12] = (byte) ((tcpHdr / 4) << 4);
        p[t + 13] = (byte) flags;
        Ip.p16(p, t + 14, window);
        Ip.p16(p, t + 16, 0);
        Ip.p16(p, t + 18, 0);
        if (mssOpt > 0) {
            p[t + 20] = 2; p[t + 21] = 4;
            Ip.p16(p, t + 22, mssOpt);
        }
        if (len > 0) System.arraycopy(data, off, p, t + tcpHdr, len);
        Ip.p16(p, t + 16, Ip.fold(Ip.sum(p, t, l4, pseudo(src, dst, 6, l4))));
        return p;
    }

    static byte[] udp(int src, int dst, int sport, int dport, byte[] data, int off, int len) {
        int l4 = 8 + len;
        int total = 20 + l4;
        byte[] p = new byte[total];
        ipHeader(p, total, 17, src, dst);
        int t = 20;
        Ip.p16(p, t, sport);
        Ip.p16(p, t + 2, dport);
        Ip.p16(p, t + 4, l4);
        Ip.p16(p, t + 6, 0);
        System.arraycopy(data, off, p, t + 8, len);
        int c = Ip.fold(Ip.sum(p, t, l4, pseudo(src, dst, 17, l4)));
        Ip.p16(p, t + 6, c == 0 ? 0xFFFF : c);
        return p;
    }
}

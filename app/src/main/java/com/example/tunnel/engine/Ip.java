package com.example.tunnel.engine;

/** Small byte/IP helpers. */
final class Ip {
    private Ip() {}

    static int u16(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }

    static int i32(byte[] b, int o) {
        return ((b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    static void p16(byte[] b, int o, int v) { b[o] = (byte) (v >>> 8); b[o + 1] = (byte) v; }

    static void p32(byte[] b, int o, int v) {
        b[o] = (byte) (v >>> 24); b[o + 1] = (byte) (v >>> 16); b[o + 2] = (byte) (v >>> 8); b[o + 3] = (byte) v;
    }

    /** Add 16-bit big-endian words of b[off..off+len) to acc (no folding). */
    static long sum(byte[] b, int off, int len, long acc) {
        int i = off, end = off + len;
        while (end - i > 1) { acc += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); i += 2; }
        if (i < end) acc += (b[i] & 0xFF) << 8;
        return acc;
    }

    static int fold(long acc) {
        while ((acc >>> 16) != 0) acc = (acc & 0xFFFF) + (acc >>> 16);
        return (int) (~acc & 0xFFFF);
    }

    static String str(int ip) {
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "." + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    static int parse(String s) {
        String[] p = s.trim().split("\\.");
        if (p.length != 4) throw new IllegalArgumentException("bad IPv4: " + s);
        int v = 0;
        for (String x : p) {
            int n = Integer.parseInt(x);
            if (n < 0 || n > 255) throw new IllegalArgumentException("bad IPv4: " + s);
            v = (v << 8) | n;
        }
        return v;
    }
}

package com.example.tunnel.vless;

import java.io.IOException;

/** VLESS (version 0) request/response framing for TCP, IPv4 destinations. */
public final class VlessCodec {
    private VlessCodec() {}

    /** "4224f578-6c71-4cf2-ae77-3cf1d8878fed" -> 16 bytes. */
    public static byte[] parseUuid(String s) {
        String h = s.trim().replace("-", "");
        if (h.length() != 32) throw new IllegalArgumentException("UUID must have 32 hex digits");
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int hi = Character.digit(h.charAt(i * 2), 16), lo = Character.digit(h.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("UUID contains a non-hex character");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * Request header: version(1)=0 | uuid(16) | addonsLen(1)=0 | command(1)=1 (TCP) | port(2, BE) |
     * addrType(1)=1 (IPv4) | address(4). Always exactly 26 bytes.
     */
    public static byte[] tcpRequestHeader(byte[] uuid16, String ipv4, int port) {
        if (uuid16.length != 16) throw new IllegalArgumentException("uuid");
        String[] parts = ipv4.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("not an IPv4 address: " + ipv4);
        byte[] h = new byte[26];
        h[0] = 0;
        System.arraycopy(uuid16, 0, h, 1, 16);
        h[17] = 0;
        h[18] = 1;
        h[19] = (byte) (port >>> 8);
        h[20] = (byte) port;
        h[21] = 1;
        for (int i = 0; i < 4; i++) {
            int v = Integer.parseInt(parts[i]);
            if (v < 0 || v > 255) throw new IllegalArgumentException("not an IPv4 address: " + ipv4);
            h[22 + i] = (byte) v;
        }
        return h;
    }

    /**
     * The server's first bytes are a response header (version(1) | addonsLen(1) | addons) that must be
     * stripped before the payload. This works on arbitrarily chunked input.
     */
    public static final class ResponseParser {
        private int state;          // 0 version, 1 addons length, 2 addons, 3 done
        private int addonsLeft;

        public boolean done() { return state == 3; }

        /** Returns how many leading bytes of b[off..off+len) belong to the header. */
        public int consume(byte[] b, int off, int len) throws IOException {
            int i = off, end = off + len;
            while (i < end && state != 3) {
                switch (state) {
                    case 0:
                        if (b[i] != 0) throw new IOException("unexpected VLESS response version " + (b[i] & 0xFF));
                        state = 1;
                        i++;
                        break;
                    case 1:
                        addonsLeft = b[i] & 0xFF;
                        state = addonsLeft == 0 ? 3 : 2;
                        i++;
                        break;
                    default:
                        int n = Math.min(addonsLeft, end - i);
                        addonsLeft -= n;
                        i += n;
                        if (addonsLeft == 0) state = 3;
                        break;
                }
            }
            return i - off;
        }
    }
}

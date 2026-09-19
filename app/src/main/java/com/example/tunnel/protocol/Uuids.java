package com.example.tunnel.protocol;

/** UUID parsing shared by VLESS and VMess (both use a 16-byte user id). */
public final class Uuids {
    private Uuids() {}

    public static byte[] parse(String s) {
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
}

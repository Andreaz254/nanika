package com.example.tunnel;

import android.content.Context;
import android.provider.Settings;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A per-device, per-install identifier ("HWID") used to lock an exported configuration to one phone.
 * Apps cannot read a true hardware serial without privileged system permissions, so this is built from
 * ANDROID_ID (stable per device, user and app-signing key, changes on factory reset) salted with the app id
 * and hashed, so the original ANDROID_ID cannot be recovered from it.
 */
public final class HwId {
    private HwId() {}

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static volatile String cached;

    public static synchronized String get(Context ctx) {
        if (cached != null) return cached;
        String androidId = null;
        try {
            androidId = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        } catch (Exception ignored) { }
        if (androidId == null || androidId.isEmpty() || "9774d56d682e549c".equals(androidId)) {
            androidId = "unknown-" + android.os.Build.FINGERPRINT;   // rare fallback: emulators, broken ROMs
        }
        cached = format(sha256("nanika-hwid:" + androidId));
        return cached;
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(s.getBytes(UTF8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    /** First 16 hex chars, grouped for readability: "A1B2-C3D4-E5F6-0789". */
    private static String format(String fullHex) {
        String h = fullHex.substring(0, 16);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length(); i += 4) {
            if (i > 0) sb.append('-');
            sb.append(h, i, Math.min(i + 4, h.length()));
        }
        return sb.toString();
    }
}

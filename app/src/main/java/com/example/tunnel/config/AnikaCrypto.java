package com.example.tunnel.config;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The ".anika" file format: AES-256-GCM encrypted (and authenticated) JSON.
 *
 *   bytes 0-5   magic  "ANIKA" + format version (1)
 *   bytes 6-17  random 12-byte IV
 *   bytes 18-   ciphertext + 16-byte GCM tag
 *
 * The key is derived from a secret that lives inside the app, so only Nanika can open the files. That
 * keeps the content unreadable in a text editor or a chat preview, and any edit to the file is detected.
 * It is NOT protection against someone who takes the app apart: the secret is part of the app.
 */
public final class AnikaCrypto {
    private AnikaCrypto() {}

    private static final byte[] MAGIC = {'A', 'N', 'I', 'K', 'A', 1};
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String SECRET = "nanika/kitsune/config/v1/7f3a91c2-5be4-4d0e-9a17-2c68d4e0b3f5";

    private static byte[] key() throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] k = SECRET.getBytes(UTF8);
        for (int i = 0; i < 5000; i++) k = md.digest(k);   // a little stretching
        return k;
    }

    public static boolean looksLikeAnika(byte[] data) {
        if (data == null || data.length < MAGIC.length + IV_LEN + 16) return false;
        for (int i = 0; i < MAGIC.length; i++) if (data[i] != MAGIC[i]) return false;
        return true;
    }

    public static byte[] encrypt(String plain) throws IOException {
        try {
            byte[] iv = new byte[IV_LEN];
            RANDOM.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(), "AES"), new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(MAGIC);
            byte[] ct = c.doFinal(plain.getBytes(UTF8));
            byte[] out = new byte[MAGIC.length + IV_LEN + ct.length];
            System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
            System.arraycopy(iv, 0, out, MAGIC.length, IV_LEN);
            System.arraycopy(ct, 0, out, MAGIC.length + IV_LEN, ct.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IOException("encryption failed: " + e.getMessage(), e);
        }
    }

    public static String decrypt(byte[] data) throws IOException {
        if (!looksLikeAnika(data)) throw new IOException("this is not a Nanika (.anika) file");
        try {
            byte[] iv = new byte[IV_LEN];
            System.arraycopy(data, MAGIC.length, iv, 0, IV_LEN);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key(), "AES"), new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(MAGIC);
            int off = MAGIC.length + IV_LEN;
            return new String(c.doFinal(data, off, data.length - off), UTF8);
        } catch (GeneralSecurityException e) {
            throw new IOException("the file is damaged or was changed");
        }
    }
}

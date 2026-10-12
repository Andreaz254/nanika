package com.example.tunnel;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads and writes ".anika" configuration files.
 *
 * Layout:  "ANIKA1" (6 bytes) | salt (16) | iv (12) | AES-256-GCM(ciphertext + 16-byte tag)
 * The key is derived from a secret built into the app plus the random salt, so a .anika file cannot be read or
 * edited in a text editor and any change to it is detected, and it opens on any phone that has this app.
 * (A secret that ships inside the app can in principle be extracted by someone who reverse-engineers it:
 * this keeps casual users out, it is not a replacement for a password-protected vault.)
 */
public final class AnikaCrypto {
    private static final byte[] MAGIC = "ANIKA1".getBytes(Charset.forName("US-ASCII"));
    private static final int SALT = 16, IV = 12, TAG_BITS = 128, ROUNDS = 20000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AnikaCrypto() {}

    private static byte[] key(byte[] salt) throws Exception {
        String secret = "n4n1k4" + "\u00b7" + "tunnel" + "\u00b7" + "0x7F3A" + "\u00b7" + "kitsune-no-more";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] k = md.digest(concat(secret.getBytes(Charset.forName("UTF-8")), salt));
        for (int i = 0; i < ROUNDS; i++) {
            md.reset();
            md.update(k);
            md.update(salt);
            k = md.digest();
        }
        return k;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static boolean looksEncrypted(byte[] data) {
        if (data == null || data.length < MAGIC.length + SALT + IV + 16) return false;
        for (int i = 0; i < MAGIC.length; i++) if (data[i] != MAGIC[i]) return false;
        return true;
    }

    public static byte[] encrypt(String plain) throws Exception {
        byte[] salt = new byte[SALT], iv = new byte[IV];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(salt), "AES"), new GCMParameterSpec(TAG_BITS, iv));
        c.updateAAD(MAGIC);
        byte[] ct = c.doFinal(plain.getBytes(Charset.forName("UTF-8")));
        byte[] out = new byte[MAGIC.length + SALT + IV + ct.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        System.arraycopy(salt, 0, out, MAGIC.length, SALT);
        System.arraycopy(iv, 0, out, MAGIC.length + SALT, IV);
        System.arraycopy(ct, 0, out, MAGIC.length + SALT + IV, ct.length);
        return out;
    }

    /** @throws IllegalArgumentException if this is not a valid, untampered .anika file */
    public static String decrypt(byte[] data) {
        if (!looksEncrypted(data)) throw new IllegalArgumentException("That is not a .anika file");
        try {
            byte[] salt = Arrays.copyOfRange(data, MAGIC.length, MAGIC.length + SALT);
            byte[] iv = Arrays.copyOfRange(data, MAGIC.length + SALT, MAGIC.length + SALT + IV);
            byte[] ct = Arrays.copyOfRange(data, MAGIC.length + SALT + IV, data.length);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key(salt), "AES"), new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(MAGIC);
            return new String(c.doFinal(ct), Charset.forName("UTF-8"));
        } catch (Exception e) {
            throw new IllegalArgumentException("This .anika file is damaged or has been modified");
        }
    }
}

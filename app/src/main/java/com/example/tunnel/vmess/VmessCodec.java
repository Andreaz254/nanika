package com.example.tunnel.vmess;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * VMess "AEAD" client framing (alterId = 0), as implemented by Xray-core / V2Fly (the core v2rayNG embeds).
 * v2rayNG's own default for a VMess profile is security "auto", alterId 0; "auto" resolves to
 * AES-128-GCM on arm64/amd64, which is what this class uses.
 *
 * Wire layout (client -> server):
 *   AEAD-sealed request header (authID | sealed length | connection nonce | sealed header)
 *   then body chunks:  uint16 BE (ciphertext length) | AES-128-GCM(payload)
 * Wire layout (server -> client):
 *   AEAD-sealed response header (sealed length | sealed header), then body chunks as above.
 *
 * Pure Java (JCA only) so it can be tested on a plain JVM. One {@link Session} per TCP flow.
 */
public final class VmessCodec {
    private VmessCodec() {}

    public static final int TAG_LEN = 16;
    /** Largest plaintext per chunk. Xray writes ~8 KiB chunks; staying below that is accepted by every server. */
    public static final int MAX_PLAIN = 8000;

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final byte OPT_CHUNK_STREAM = 0x01;   // "S": standard chunk stream (required for AEAD security)
    private static final int SEC_AES_128_GCM = 3;
    private static final byte CMD_TCP = 1;
    private static final byte ADDR_IPV4 = 1;

    // ------------------------------------------------------------------ KDF (nested HMAC-SHA256)

    private interface Hash { byte[] digest(byte[] data); }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** HMAC over an arbitrary hash function with a 64-byte block (what Go's hmac.New does with a custom hash). */
    private static byte[] hmac(Hash h, byte[] key, byte[] data) {
        if (key.length > 64) key = h.digest(key);
        byte[] ipad = new byte[64 + data.length];
        byte[] opad = new byte[64 + 32];
        for (int i = 0; i < 64; i++) {
            int k = i < key.length ? key[i] : 0;
            ipad[i] = (byte) (k ^ 0x36);
            opad[i] = (byte) (k ^ 0x5c);
        }
        System.arraycopy(data, 0, ipad, 64, data.length);
        byte[] inner = h.digest(ipad);
        System.arraycopy(inner, 0, opad, 64, 32);
        return h.digest(opad);
    }

    /** VMess KDF: each path element wraps the previous HMAC as the hash function of the next one. */
    static byte[] kdf(byte[] key, byte[]... path) {
        final byte[] root = "VMess AEAD KDF".getBytes(UTF8);
        Hash h = new Hash() {
            @Override public byte[] digest(byte[] d) { return hmacSha256(root, d); }
        };
        for (final byte[] p : path) {
            final Hash parent = h;
            h = new Hash() {
                @Override public byte[] digest(byte[] d) { return hmac(parent, p, d); }
            };
        }
        return h.digest(key);
    }

    private static byte[] s(String v) { return v.getBytes(UTF8); }

    static byte[] kdf16(byte[] key, byte[]... path) { return Arrays.copyOf(kdf(key, path), 16); }

    static byte[] kdf12(byte[] key, byte[]... path) { return Arrays.copyOf(kdf(key, path), 12); }

    // ------------------------------------------------------------------ primitives

    /** cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21") */
    public static byte[] cmdKey(byte[] uuid16) {
        if (uuid16.length != 16) throw new IllegalArgumentException("uuid");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(uuid16);
            md.update(s("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] gcm(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] in, int off, int len)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(in, off, len);
    }

    private static byte[] chunkNonce(byte[] iv16, int count) {
        byte[] n = new byte[12];
        n[0] = (byte) (count >>> 8);          // uint16 big-endian counter (wraps like Xray's)
        n[1] = (byte) count;
        System.arraycopy(iv16, 2, n, 2, 10);  // then IV[2:12]
        return n;
    }

    /** 16-byte auth ID: AES-128-ECB(KDF16(cmdKey,"AES Auth ID Encryption"), time(8) | rand(4) | crc32(first 12)). */
    static byte[] createAuthId(byte[] cmdKey, long unixSeconds, byte[] rand4) throws GeneralSecurityException {
        byte[] plain = new byte[16];
        for (int i = 0; i < 8; i++) plain[i] = (byte) (unixSeconds >>> (56 - 8 * i));
        System.arraycopy(rand4, 0, plain, 8, 4);
        CRC32 crc = new CRC32();
        crc.update(plain, 0, 12);
        long v = crc.getValue();
        plain[12] = (byte) (v >>> 24);
        plain[13] = (byte) (v >>> 16);
        plain[14] = (byte) (v >>> 8);
        plain[15] = (byte) v;
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kdf16(cmdKey, s("AES Auth ID Encryption")), "AES"));
        return ecb.doFinal(plain);
    }

    /** Seals the request header: authID | AEAD(len) | connectionNonce(8) | AEAD(header). */
    static byte[] sealHeader(byte[] cmdKey, byte[] header, long unixSeconds, byte[] rand4, byte[] connNonce8)
            throws GeneralSecurityException {
        byte[] authId = createAuthId(cmdKey, unixSeconds, rand4);
        byte[] lenPlain = {(byte) (header.length >>> 8), (byte) header.length};

        byte[] lenKey = kdf16(cmdKey, s("VMess Header AEAD Key_Length"), authId, connNonce8);
        byte[] lenNonce = kdf12(cmdKey, s("VMess Header AEAD Nonce_Length"), authId, connNonce8);
        byte[] lenSealed = gcm(true, lenKey, lenNonce, authId, lenPlain, 0, 2);

        byte[] hdrKey = kdf16(cmdKey, s("VMess Header AEAD Key"), authId, connNonce8);
        byte[] hdrNonce = kdf12(cmdKey, s("VMess Header AEAD Nonce"), authId, connNonce8);
        byte[] hdrSealed = gcm(true, hdrKey, hdrNonce, authId, header, 0, header.length);

        byte[] out = new byte[16 + lenSealed.length + 8 + hdrSealed.length];
        int p = 0;
        System.arraycopy(authId, 0, out, p, 16); p += 16;
        System.arraycopy(lenSealed, 0, out, p, lenSealed.length); p += lenSealed.length;
        System.arraycopy(connNonce8, 0, out, p, 8); p += 8;
        System.arraycopy(hdrSealed, 0, out, p, hdrSealed.length);
        return out;
    }

    private static long fnv1a32(byte[] b, int len) {
        long h = 0x811C9DC5L;
        for (int i = 0; i < len; i++) {
            h ^= (b[i] & 0xFF);
            h = (h * 0x01000193L) & 0xFFFFFFFFL;
        }
        return h;
    }

    // ------------------------------------------------------------------ per-flow session

    /** State for one VMess connection (one TCP flow). The encode side is NOT thread-safe: lock around encode+send. */
    public static final class Session {
        private final byte[] cmdKey;
        private final SecureRandom rnd;
        private final byte[] bodyKey = new byte[16];
        private final byte[] bodyIv = new byte[16];
        private final byte respV;
        private final byte[] respKey;   // SHA256(bodyKey)[:16]
        private final byte[] respIv;    // SHA256(bodyIv)[:16]
        private int sendCount;

        public Session(byte[] uuid16, SecureRandom rnd) {
            this.cmdKey = cmdKey(uuid16);
            this.rnd = rnd;
            rnd.nextBytes(bodyKey);
            rnd.nextBytes(bodyIv);
            byte[] v = new byte[1];
            rnd.nextBytes(v);
            respV = v[0];
            respKey = Arrays.copyOf(sha256(bodyKey), 16);
            respIv = Arrays.copyOf(sha256(bodyIv), 16);
        }

        /** Test hook: deterministic keys. */
        Session(byte[] uuid16, SecureRandom rnd, byte[] key16, byte[] iv16, byte respV) {
            this.cmdKey = cmdKey(uuid16);
            this.rnd = rnd;
            System.arraycopy(key16, 0, bodyKey, 0, 16);
            System.arraycopy(iv16, 0, bodyIv, 0, 16);
            this.respV = respV;
            respKey = Arrays.copyOf(sha256(bodyKey), 16);
            respIv = Arrays.copyOf(sha256(bodyIv), 16);
        }

        /**
         * Sealed request header for a TCP connection to an IPv4 destination.
         * Plain header: ver(1)=1 | IV(16) | key(16) | V(1) | opt(1) | P<<4|sec(1) | 0 | cmd(1)=1 | port(2) |
         *               addrType(1)=1 | ipv4(4) | padding(P) | FNV1a32(4)
         */
        public byte[] requestHeader(String ipv4, int port, long unixSeconds) throws IOException {
            String[] parts = ipv4.split("\\.");
            if (parts.length != 4) throw new IOException("not an IPv4 address: " + ipv4);
            int pad = rnd.nextInt(16);
            byte[] h = new byte[1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 4 + pad + 4];
            int p = 0;
            h[p++] = 1;
            System.arraycopy(bodyIv, 0, h, p, 16); p += 16;
            System.arraycopy(bodyKey, 0, h, p, 16); p += 16;
            h[p++] = respV;
            h[p++] = OPT_CHUNK_STREAM;
            h[p++] = (byte) ((pad << 4) | SEC_AES_128_GCM);
            h[p++] = 0;
            h[p++] = CMD_TCP;
            h[p++] = (byte) (port >>> 8);
            h[p++] = (byte) port;
            h[p++] = ADDR_IPV4;
            for (int i = 0; i < 4; i++) {
                int v;
                try { v = Integer.parseInt(parts[i]); } catch (NumberFormatException e) { v = -1; }
                if (v < 0 || v > 255) throw new IOException("not an IPv4 address: " + ipv4);
                h[p++] = (byte) v;
            }
            if (pad > 0) {
                byte[] r = new byte[pad];
                rnd.nextBytes(r);
                System.arraycopy(r, 0, h, p, pad);
                p += pad;
            }
            long f = fnv1a32(h, p);
            h[p++] = (byte) (f >>> 24);
            h[p++] = (byte) (f >>> 16);
            h[p++] = (byte) (f >>> 8);
            h[p++] = (byte) f;

            byte[] rand4 = new byte[4], connNonce = new byte[8];
            rnd.nextBytes(rand4);
            rnd.nextBytes(connNonce);
            try {
                return sealHeader(cmdKey, h, unixSeconds, rand4, connNonce);
            } catch (GeneralSecurityException e) {
                throw new IOException("VMess header encryption failed: " + e);
            }
        }

        /** One body chunk: uint16 BE (ciphertext length incl. tag) | AES-128-GCM(payload). len must be <= MAX_PLAIN. */
        public byte[] encodeChunk(byte[] data, int off, int len) throws IOException {
            if (len > MAX_PLAIN) throw new IllegalArgumentException("chunk too large");
            try {
                byte[] ct = gcm(true, bodyKey, chunkNonce(bodyIv, sendCount++), null, data, off, len);
                byte[] out = new byte[2 + ct.length];
                out[0] = (byte) (ct.length >>> 8);
                out[1] = (byte) ct.length;
                System.arraycopy(ct, 0, out, 2, ct.length);
                return out;
            } catch (GeneralSecurityException e) {
                throw new IOException("VMess chunk encryption failed: " + e);
            }
        }

        public ResponseDecoder responseDecoder() { return new ResponseDecoder(respKey, respIv, respV); }
    }

    // ------------------------------------------------------------------ response side

    public interface Sink { void data(byte[] b, int off, int len) throws IOException; }

    /** Streaming decoder for the server's bytes: sealed response header, then chunks. Works on any fragmentation. */
    public static final class ResponseDecoder {
        private static final int HDR_LEN = 0, HDR = 1, CHUNK_LEN = 2, CHUNK = 3, EOF = 4;

        private final byte[] respKey, respIv;
        private final byte respV;
        private byte[] buf = new byte[4096];
        private int start, end;
        private int state = HDR_LEN;
        private int need = 2 + TAG_LEN;
        private int recvCount;

        ResponseDecoder(byte[] respKey, byte[] respIv, byte respV) {
            this.respKey = respKey;
            this.respIv = respIv;
            this.respV = respV;
        }

        /** True once the server sent its end-of-stream chunk. */
        public boolean eof() { return state == EOF; }

        /** True once the response header was accepted. */
        public boolean headerDone() { return state >= CHUNK_LEN; }

        public void feed(byte[] b, int off, int len, Sink sink) throws IOException {
            if (state == EOF) return;
            append(b, off, len);
            try {
                while (state != EOF && end - start >= need) step(sink);
            } catch (GeneralSecurityException e) {
                throw new IOException("VMess authentication failed (wrong UUID, or server is not VMess/AEAD): " + e.getMessage());
            }
            if (start == end) { start = end = 0; }
        }

        private void append(byte[] b, int off, int len) {
            if (end + len > buf.length) {
                int live = end - start;
                byte[] nb = buf.length >= live + len ? buf : new byte[Math.max(buf.length * 2, live + len)];
                System.arraycopy(buf, start, nb, 0, live);
                buf = nb;
                start = 0;
                end = live;
            }
            System.arraycopy(b, off, buf, end, len);
            end += len;
        }

        private void step(Sink sink) throws IOException, GeneralSecurityException {
            switch (state) {
                case HDR_LEN: {
                    byte[] key = kdf16(respKey, s("AEAD Resp Header Len Key"));
                    byte[] nonce = kdf12(respIv, s("AEAD Resp Header Len IV"));
                    byte[] pl = gcm(false, key, nonce, null, buf, start, need);
                    start += need;
                    need = (((pl[0] & 0xFF) << 8) | (pl[1] & 0xFF)) + TAG_LEN;
                    if (need < 4 + TAG_LEN) throw new IOException("bad VMess response header length");
                    state = HDR;
                    break;
                }
                case HDR: {
                    byte[] key = kdf16(respKey, s("AEAD Resp Header Key"));
                    byte[] nonce = kdf12(respIv, s("AEAD Resp Header IV"));
                    byte[] h = gcm(false, key, nonce, null, buf, start, need);
                    start += need;
                    if (h[0] != respV) throw new IOException("VMess response header mismatch (server rejected the request)");
                    state = CHUNK_LEN;
                    need = 2;
                    break;
                }
                case CHUNK_LEN: {
                    int size = ((buf[start] & 0xFF) << 8) | (buf[start + 1] & 0xFF);
                    start += 2;
                    if (size < TAG_LEN) throw new IOException("bad VMess chunk length " + size);
                    state = CHUNK;
                    need = size;
                    break;
                }
                default: {   // CHUNK
                    byte[] pt = gcm(false, respKey, chunkNonce(respIv, recvCount++), null, buf, start, need);
                    start += need;
                    state = CHUNK_LEN;
                    need = 2;
                    if (pt.length == 0) { state = EOF; return; }   // empty chunk = end of stream
                    sink.data(pt, 0, pt.length);
                }
            }
        }
    }
}

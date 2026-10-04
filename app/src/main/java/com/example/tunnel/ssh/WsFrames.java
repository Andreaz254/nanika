package com.example.tunnel.ssh;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/** Minimal RFC 6455 binary framing for the (optional) "real WebSocket" mode. */
final class WsFrames {
    private WsFrames() {}

    /** Client side: every write() becomes one masked binary frame. */
    static final class Out extends OutputStream {
        private final OutputStream raw;
        private final SecureRandom rnd = new SecureRandom();

        Out(OutputStream raw) { this.raw = raw; }

        @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }

        @Override public void write(byte[] b, int off, int len) throws IOException {
            if (len > 0) sendFrame(0x2, b, off, len);
        }

        @Override public void flush() throws IOException { synchronized (this) { raw.flush(); } }

        /** The caller (Transport.close) closes the socket; a polite close frame is best effort. */
        @Override public void close() {
            try { sendFrame(0x8, new byte[0], 0, 0); } catch (IOException ignored) { }
        }

        synchronized void sendFrame(int opcode, byte[] b, int off, int len) throws IOException {
            int ext = len < 126 ? 0 : (len <= 0xFFFF ? 2 : 8);
            byte[] f = new byte[2 + ext + 4 + len];
            int p = 0;
            f[p++] = (byte) (0x80 | opcode);
            if (len < 126) {
                f[p++] = (byte) (0x80 | len);
            } else if (len <= 0xFFFF) {
                f[p++] = (byte) (0x80 | 126);
                f[p++] = (byte) (len >>> 8);
                f[p++] = (byte) len;
            } else {
                f[p++] = (byte) (0x80 | 127);
                p += 4;                                   // upper 32 bits stay zero
                f[p++] = (byte) (len >>> 24);
                f[p++] = (byte) (len >>> 16);
                f[p++] = (byte) (len >>> 8);
                f[p++] = (byte) len;
            }
            byte[] mask = new byte[4];
            rnd.nextBytes(mask);
            System.arraycopy(mask, 0, f, p, 4);
            p += 4;
            for (int i = 0; i < len; i++) f[p + i] = (byte) (b[off + i] ^ mask[i & 3]);
            raw.write(f);
            raw.flush();
        }
    }

    /** Server side: yields the payload bytes of data frames, answers pings, ends on a close frame. */
    static final class In extends InputStream {
        private final InputStream raw;
        private final Out out;
        private long remaining;
        private byte[] mask;          // servers must not mask, but tolerate it
        private long pos;
        private boolean eof;

        In(InputStream raw, Out out) { this.raw = raw; this.out = out; }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (eof) return -1;
            while (remaining == 0) {
                if (!nextFrame()) { eof = true; return -1; }
            }
            int n = raw.read(b, off, (int) Math.min(len, remaining));
            if (n < 0) { eof = true; return -1; }
            if (mask != null) for (int i = 0; i < n; i++) b[off + i] ^= mask[(int) ((pos + i) & 3)];
            pos += n;
            remaining -= n;
            return n;
        }

        @Override public int available() throws IOException {
            return remaining > 0 ? (int) Math.min(raw.available(), remaining) : 0;
        }

        private int u8() throws IOException {
            int v = raw.read();
            if (v < 0) throw new EOFException("connection closed inside a WebSocket frame");
            return v;
        }

        private void readFully(byte[] b) throws IOException {
            int got = 0;
            while (got < b.length) {
                int n = raw.read(b, got, b.length - got);
                if (n < 0) throw new EOFException("connection closed inside a WebSocket frame");
                got += n;
            }
        }

        /** Positions at the next data frame's payload. false = the peer closed the stream. */
        private boolean nextFrame() throws IOException {
            while (true) {
                int b0 = raw.read();
                if (b0 < 0) return false;
                int b1 = u8();
                long len = b1 & 0x7F;
                if (len == 126) len = (u8() << 8) | u8();
                else if (len == 127) {
                    len = 0;
                    for (int i = 0; i < 8; i++) len = (len << 8) | u8();
                }
                byte[] m = null;
                if ((b1 & 0x80) != 0) { m = new byte[4]; readFully(m); }
                int op = b0 & 0x0F;
                if (op <= 2) {                               // continuation / text / binary
                    if (len == 0) continue;
                    remaining = len;
                    mask = m;
                    pos = 0;
                    return true;
                }
                if (len > 125) throw new IOException("oversized WebSocket control frame");
                byte[] payload = new byte[(int) len];
                readFully(payload);
                if (m != null) for (int i = 0; i < payload.length; i++) payload[i] ^= m[i & 3];
                if (op == 0x8) return false;                 // close
                if (op == 0x9) out.sendFrame(0xA, payload, 0, payload.length);   // ping -> pong
                // 0xA (pong) and unknown opcodes are ignored
            }
        }
    }
}

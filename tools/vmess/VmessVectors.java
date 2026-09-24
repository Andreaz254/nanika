import com.example.tunnel.vmess.VmessCodec;
import java.lang.reflect.*;
import java.security.SecureRandom;

/** Dumps a deterministic VMess request (header + 2 chunks) as hex, and decodes a server response given as hex. */
public class VmessVectors {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    static byte[] unhex(String h) { byte[] b = new byte[h.length() / 2]; for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16); return b; }
    static class Fixed extends SecureRandom {   // deterministic counter stream
        int c = 0;
        @Override public void nextBytes(byte[] b) { for (int i = 0; i < b.length; i++) b[i] = (byte) (++c * 37 + 11); }
        @Override public int nextInt(int n) { return 5 % n; }
    }
    public static void main(String[] a) throws Exception {
        byte[] uuid = unhex("4224f5786c714cf2ae773cf1d8878fed");
        byte[] key = unhex("000102030405060708090a0b0c0d0e0f"), iv = unhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        Constructor<VmessCodec.Session> k = VmessCodec.Session.class.getDeclaredConstructor(byte[].class, SecureRandom.class, byte[].class, byte[].class, byte.class);
        k.setAccessible(true);
        VmessCodec.Session s = k.newInstance(uuid, new Fixed(), key, iv, (byte) 0x7b);
        if (a[0].equals("dump")) {
            System.out.println("header " + hex(s.requestHeader("142.250.185.46", 443, 1760000000L)));
            System.out.println("chunk0 " + hex(s.encodeChunk("GET / HTTP/1.1\r\n\r\n".getBytes("US-ASCII"), 0, 18)));
            System.out.println("chunk1 " + hex(s.encodeChunk(new byte[0], 0, 0)));
            System.out.println("chunk2 " + hex(s.encodeChunk(new byte[]{1, 2, 3}, 0, 3)));
        } else {
            // decode: stdin hex line = full server stream; feed in awkward fragment sizes
            byte[] in = unhex(new java.util.Scanner(System.in).nextLine().trim());
            for (int frag : new int[]{in.length, 1, 7}) {
                VmessCodec.ResponseDecoder d = s.responseDecoder();
                final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                VmessCodec.Sink sink = (b, off, len) -> out.write(b, off, len);
                for (int i = 0; i < in.length; i += frag) d.feed(in, i, Math.min(frag, in.length - i), sink);
                System.out.println("frag" + frag + " " + hex(out.toByteArray()) + " eof=" + d.eof());
            }
        }
    }
}

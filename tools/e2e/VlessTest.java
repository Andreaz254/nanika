import com.example.tunnel.vless.VlessCodec;
import java.util.Arrays;

public class VlessTest {
    static int fails = 0;
    static void check(String n, boolean ok) { System.out.println((ok ? "PASS " : "FAIL ") + n); if (!ok) fails++; }
    public static void main(String[] a) throws Exception {
        byte[] u = VlessCodec.parseUuid("4224f578-6c71-4cf2-ae77-3cf1d8878fed");
        check("uuid parses to 16 bytes, first=0x42 last=0xed", u.length == 16 && (u[0] & 0xFF) == 0x42 && (u[15] & 0xFF) == 0xed);
        for (String ip : new String[]{"1.1.1.1", "142.250.185.46", "255.0.0.1"}) {
            byte[] h = VlessCodec.tcpRequestHeader(u, ip, 443);
            check("header for " + ip + " is exactly 26 bytes", h.length == 26);
        }
        byte[] h = VlessCodec.tcpRequestHeader(u, "142.250.185.46", 443);
        check("version=0", h[0] == 0);
        check("uuid embedded", Arrays.equals(Arrays.copyOfRange(h, 1, 17), u));
        check("addons length=0, cmd=1 (TCP)", h[17] == 0 && h[18] == 1);
        check("port 443 big-endian = 01 BB", (h[19] & 0xFF) == 0x01 && (h[20] & 0xFF) == 0xBB);
        check("addr type=1 (IPv4)", h[21] == 1);
        check("address bytes 142.250.185.46", (h[22] & 0xFF) == 142 && (h[23] & 0xFF) == 250 && (h[24] & 0xFF) == 185 && (h[25] & 0xFF) == 46);
        byte[] h2 = VlessCodec.tcpRequestHeader(u, "10.0.0.1", 65535);
        check("port 65535 encodes as FF FF", (h2[19] & 0xFF) == 0xFF && (h2[20] & 0xFF) == 0xFF);

        // response parser: header [00 00] then payload; also with 3 addon bytes; also split 1 byte at a time
        byte[] resp = {0, 0, 'H', 'i'};
        VlessCodec.ResponseParser p = new VlessCodec.ResponseParser();
        int c = p.consume(resp, 0, resp.length);
        check("strips 2-byte response header, payload 'Hi' remains", c == 2 && p.done());
        byte[] resp2 = {0, 3, 9, 9, 9, 'X'};
        p = new VlessCodec.ResponseParser(); c = p.consume(resp2, 0, resp2.length);
        check("strips header with 3 addon bytes", c == 5 && p.done());
        p = new VlessCodec.ResponseParser(); int total = 0;
        for (byte b : resp2) total += p.consume(new byte[]{b}, 0, 1) ;
        check("byte-at-a-time chunking consumes exactly the header (5 bytes)", total == 5 && p.done());
        p = new VlessCodec.ResponseParser(); c = p.consume(new byte[]{0}, 0, 1);
        check("header split across messages: not done after 1 byte", c == 1 && !p.done());
        try { new VlessCodec.ResponseParser().consume(new byte[]{7, 0}, 0, 2); check("bad version rejected", false); }
        catch (java.io.IOException e) { check("bad version rejected", true); }
        try { VlessCodec.parseUuid("not-a-uuid"); check("bad uuid rejected", false); } catch (IllegalArgumentException e) { check("bad uuid rejected", true); }
        System.exit(fails == 0 ? 0 : 1);
    }
}

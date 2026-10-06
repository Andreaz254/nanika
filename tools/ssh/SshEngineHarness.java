import com.example.tunnel.engine.*;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.ssh.SshConnector;

import java.io.*;
import java.util.*;

/**
 * Same wiring as tools/e2e/E2EHarness (packets in/out on stdin/stdout, "virtual-ip:port=real-host:port" mappings),
 * but the upstream is the real SshConnector: every flow becomes an SSH direct-tcpip channel to the mapped target.
 * extra args:  proxy=<port>  tls=0|1
 */
public class SshEngineHarness {
    public static void main(String[] args) throws Exception {
        // stdout carries the packet stream: keep it clean (TunnelState's stub logger prints to System.out)
        final OutputStream packetOut = new FileOutputStream(FileDescriptor.out);
        System.setOut(System.err);
        final Map<String, String> map = new HashMap<String, String>();
        final ProtocolConfig pc = new ProtocolConfig();
        pc.sshUser = "tester"; pc.sshPassword = "s3cret"; pc.sshHost = "ssh.example.test";
        pc.proxyHost = "127.0.0.1"; pc.insecureTls = true; pc.sni = "bug.example.test";
        for (String a : args) {
            String[] kv = a.split("=");
            if (kv[0].equals("proxy")) pc.proxyPort = Integer.parseInt(kv[1]);
            else if (kv[0].equals("tls")) pc.tls = kv[1].equals("1");
            else map.put(kv[0], kv[1]);
        }
        final SshConnector ssh = new SshConnector(pc);
        UpstreamConnector conn = new UpstreamConnector() {
            public UpstreamStream open(String ip, int port, UpstreamListener l) {
                String[] hp = map.get(ip + ":" + port).split(":");
                return ssh.open(hp[0], Integer.parseInt(hp[1]), l);
            }
        };

        final DataInputStream in = new DataInputStream(new BufferedInputStream(System.in, 1 << 16));
        final DataOutputStream out = new DataOutputStream(new BufferedOutputStream(packetOut, 1 << 16));
        PacketSink sink = new PacketSink() {
            public void write(byte[] b, int off, int len) throws IOException {
                synchronized (out) { out.writeInt(len); out.write(b, off, len); out.flush(); }
            }
        };
        PacketEngine.Config cfg = new PacketEngine.Config();
        cfg.dnsUpstream = "8.8.8.8";
        final PacketEngine eng = new PacketEngine(sink, conn, cfg, new PacketEngine.Logger() {
            public void log(String m) { System.err.println("[engine] " + m); }
        });
        eng.start();
        byte[] buf = new byte[70000];
        try {
            while (true) {
                int len = in.readInt();
                in.readFully(buf, 0, len);
                eng.onPacket(buf, len);
            }
        } catch (EOFException e) { }
        System.err.println("[harness] flows at exit: " + eng.activeFlows());
        eng.shutdown();
        ssh.close();
        System.exit(0);
    }
}

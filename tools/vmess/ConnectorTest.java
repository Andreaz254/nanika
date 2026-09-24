package com.example.tunnel.vmess;

import com.example.tunnel.engine.*;
import com.example.tunnel.protocol.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import okhttp3.*;
import okio.ByteString;

/** Runs the REAL VmessProtocol/VmessWsConnector against an in-JVM fake VMess server behind a fake WebSocket. */
public class ConnectorTest {
    static int fails; static void check(String n, boolean ok){ System.out.println((ok?"PASS ":"FAIL ")+n); if(!ok) fails++; }
    static byte[] gcm(boolean enc, byte[] k, byte[] n, byte[] aad, byte[] in, int off, int len) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(enc?1:2, new SecretKeySpec(k,"AES"), new GCMParameterSpec(128,n)); if(aad!=null) c.updateAAD(aad); return c.doFinal(in,off,len); }
    static byte[] nonce(byte[] iv,int i){ byte[] n=new byte[12]; n[0]=(byte)(i>>>8); n[1]=(byte)i; System.arraycopy(iv,2,n,2,10); return n; }

    /** Fake server: parses the sealed header, then echoes every payload byte upper-cased, in randomly fragmented WS messages. */
    static class FakeServer implements WebSocket {
        final WebSocketListener l; final byte[] cmdKey; final Random rnd = new Random(1);
        ByteArrayOutputStream in = new ByteArrayOutputStream(); byte[] key, iv, rk, riv; byte V; int state, rcount, scount; int destPort; String destIp;
        final ExecutorService ex = Executors.newSingleThreadExecutor(); volatile boolean closedByClient; int msgs;
        FakeServer(WebSocketListener l, byte[] cmdKey){ this.l=l; this.cmdKey=cmdKey; }
        public synchronized boolean send(ByteString b){ try { in.write(b.toByteArray()); msgs++; pump(); } catch(Exception e){ e.printStackTrace(); fails++; } return true; }
        public boolean close(int c,String r){ closedByClient=true; return true; } public void cancel(){} public long queueSize(){ return 0; }
        void reply(byte[] data) throws Exception {   // deliver in 1..4000 byte fragments
            int p=0; while(p<data.length){ int n=Math.min(data.length-p, 1+rnd.nextInt(4000)); final byte[] f=Arrays.copyOfRange(data,p,p+n); p+=n; ex.submit(() -> l.onMessage(this, ByteString.of(f))); } }
        void pump() throws Exception {
            byte[] b = in.toByteArray(); int pos=0;
            if (state==0) {
                if (b.length < 42) return;
                byte[] authId = Arrays.copyOf(b,16), n8 = Arrays.copyOfRange(b,34,42);
                byte[] lk = VmessCodec.kdf16(cmdKey,"VMess Header AEAD Key_Length".getBytes(),authId,n8), ln = VmessCodec.kdf12(cmdKey,"VMess Header AEAD Nonce_Length".getBytes(),authId,n8);
                byte[] lp = gcm(false,lk,ln,authId,b,16,18); int hl=((lp[0]&255)<<8)|(lp[1]&255);
                if (b.length < 42+hl+16) return;
                byte[] hk = VmessCodec.kdf16(cmdKey,"VMess Header AEAD Key".getBytes(),authId,n8), hn = VmessCodec.kdf12(cmdKey,"VMess Header AEAD Nonce".getBytes(),authId,n8);
                byte[] h = gcm(false,hk,hn,authId,b,42,hl+16);
                iv=Arrays.copyOfRange(h,1,17); key=Arrays.copyOfRange(h,17,33); V=h[33];
                destPort=((h[38]&255)<<8)|(h[39]&255); destIp=(h[41]&255)+"."+(h[42]&255)+"."+(h[43]&255)+"."+(h[44]&255);
                java.security.MessageDigest sh = java.security.MessageDigest.getInstance("SHA-256");
                rk=Arrays.copyOf(sh.digest(key),16); riv=Arrays.copyOf(sh.digest(iv),16);
                byte[] rh={V,0,0,0};
                ByteArrayOutputStream o=new ByteArrayOutputStream();
                o.write(gcm(true,VmessCodec.kdf16(rk,"AEAD Resp Header Len Key".getBytes()),VmessCodec.kdf12(riv,"AEAD Resp Header Len IV".getBytes()),null,new byte[]{0,4},0,2));
                o.write(gcm(true,VmessCodec.kdf16(rk,"AEAD Resp Header Key".getBytes()),VmessCodec.kdf12(riv,"AEAD Resp Header IV".getBytes()),null,rh,0,4));
                reply(o.toByteArray());
                pos = 42+hl+16; state=1;
            }
            while (b.length-pos >= 2) {
                int sz=((b[pos]&255)<<8)|(b[pos+1]&255); if (b.length-pos-2 < sz) break;
                byte[] pt = gcm(false,key,nonce(iv,rcount++),null,b,pos+2,sz); pos += 2+sz;
                if (pt.length==0) continue;
                for(int i=0;i<pt.length;i++) pt[i]=(byte)Character.toUpperCase((char)(pt[i]&255));
                byte[] ct=gcm(true,rk,nonce(riv,scount++),null,pt,0,pt.length);
                ByteBuffer bb=ByteBuffer.allocate(2+ct.length); bb.putShort((short)ct.length); bb.put(ct); reply(bb.array());
            }
            in = new ByteArrayOutputStream(); in.write(b,pos,b.length-pos);
        }
    }

    public static void main(String[] a) throws Exception {
        final String uuidStr = "4224f578-6c71-4cf2-ae77-3cf1d8878fed";
        final byte[] cmdKey = VmessCodec.cmdKey(Uuids.parse(uuidStr));
        OkHttpClient client = new OkHttpClient();
        final FakeServer[] srv = new FakeServer[1]; final Request[] seen = new Request[1];
        client.hook = (r, l) -> { seen[0]=r; srv[0]=new FakeServer(l, cmdKey); new Thread(() -> l.onOpen(srv[0], new Response())).start(); return srv[0]; };

        ProtocolConfig cfg = new ProtocolConfig(); cfg.uuid=uuidStr; cfg.hostHeader="real.example.com"; cfg.sni="bug.example.com"; cfg.path="ws"; cfg.port=443; cfg.tls=true;
        com.example.tunnel.protocol.TunnelProtocol p = ProtocolRegistry.require("vmess");
        check("registry resolves VMess and it is available", p.id().equals("VMess") && p.unavailableReason()==null);
        check("validate rejects bad uuid", p.validate(badCfg()) != null);
        check("validate accepts good uuid", p.validate(cfg) == null);
        UpstreamConnector c = p.createConnector(client, cfg);

        final CountDownLatch opened = new CountDownLatch(1), closed = new CountDownLatch(1);
        final ByteArrayOutputStream got = new ByteArrayOutputStream();
        UpstreamStream s = c.open("142.250.185.46", 443, new UpstreamListener() {
            public void onOpen(){ opened.countDown(); }
            public synchronized void onData(byte[] d,int o,int l){ got.write(d,o,l); }
            public void onClosed(boolean e){ closed.countDown(); } });
        check("onOpen fires", opened.await(5, TimeUnit.SECONDS));
        check("URL + Host header match VLESS logic (https://sni:port/path, Host=server)", seen[0].url.equals("https://bug.example.com:443/ws") && "real.example.com".equals(seen[0].h.get("Host")));

        byte[] big = new byte[300000]; new Random(7).nextBytes(big); for (int i=0;i<big.length;i++) big[i]=(byte)('a'+((big[i]&255)%26));
        s.write("hello vmess".getBytes(), 0, 11);
        s.write(big, 0, big.length);                       // must be split into <=8000-byte chunks
        // concurrent writers: nonce order must still match send order
        Thread[] ts = new Thread[4]; final byte[][] parts = new byte[4][2000];
        for (int t=0;t<4;t++){ Arrays.fill(parts[t], (byte)('a'+t)); final int tt=t; ts[t]=new Thread(() -> { for(int i=0;i<20;i++) s.write(parts[tt],0,2000); }); ts[t].start(); }
        for (Thread t: ts) t.join();
        int expected = 11 + big.length + 4*20*2000;
        long end = System.currentTimeMillis()+10000; while (System.currentTimeMillis()<end) { synchronized(got){ if (got.size()>=expected) break; } Thread.sleep(20); }
        byte[] all; synchronized(got){ all = got.toByteArray(); }
        check("server saw destination 142.250.185.46:443", "142.250.185.46".equals(srv[0].destIp) && srv[0].destPort==443);
        check("received exactly the echoed byte count (" + all.length + ")", all.length==expected);
        check("'HELLO VMESS' first, big payload echoed upper-cased byte-exact",
              new String(all,0,11).equals("HELLO VMESS") && new String(Arrays.copyOfRange(all,11,11+big.length)).equals(new String(big).toUpperCase()));
        s.close();
        check("close() closes the WebSocket", srv[0].closedByClient);
        System.exit(fails==0?0:1);
    }
    static ProtocolConfig badCfg(){ ProtocolConfig c=new ProtocolConfig(); c.uuid="nope"; return c; }
}

package com.example.tunnel.ssh;

import com.example.tunnel.TunnelState;
import com.example.tunnel.engine.UpstreamConnector;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;
import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SocketFactory;
import com.jcraft.jsch.UserInfo;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;

/** One SSH direct-tcpip channel per captured TCP flow. The custom socket performs the configured
 * HTTP payload handshake and then carries the SSH byte stream (the server's raw-after-upgrade mode). */
final class SshWsConnector implements UpstreamConnector {
    private final String sshHost,user,password,proxyHost,targetHost,sni,payload,path;
    private final java.util.concurrent.atomic.AtomicBoolean payloadLogged=new java.util.concurrent.atomic.AtomicBoolean();
    private final int proxyPort; private final boolean tls,insecure;
    SshWsConnector(String sh,String u,String pw,String ph,String th,int pp,String sn,boolean t,boolean ins,String pl,String pa) {
        targetHost=th; sshHost=sh; user=u; password=pw; proxyHost=ph; proxyPort=pp; sni=sn; tls=t; insecure=ins; payload=pl; path=pa;
    }
    @Override public UpstreamStream open(String destIp,int port,UpstreamListener listener) {
        Stream stream=new Stream(destIp,port,listener); new Thread(stream::connect,"ssh-flow-connect").start(); return stream;
    }
    private final class Stream implements UpstreamStream, Runnable {
        final String dest; final int destPort; final UpstreamListener listener; final AtomicBoolean closed=new AtomicBoolean();
        volatile Session session; volatile ChannelDirectTCPIP channel; volatile InputStream in; volatile OutputStream out;
        final Object writeLock=new Object();
        Stream(String d,int p,UpstreamListener l){dest=d;destPort=p;listener=l;}
        void connect(){
            try {
                JSch jsch=new JSch(); Session s=jsch.getSession(user,sshHost,22); s.setPassword(password);
                s.setConfig("StrictHostKeyChecking","no"); s.setConfig("PreferredAuthentications","password,keyboard-interactive");
                s.setServerAliveInterval(20000); s.setServerAliveCountMax(3);
                s.setSocketFactory(new PayloadSocketFactory());
                session=s; if(closed.get())return; s.connect(20000);
                ChannelDirectTCPIP ch=(ChannelDirectTCPIP)s.openChannel("direct-tcpip");
                ch.setHost(dest); ch.setPort(destPort); ch.setOrgIPAddress("127.0.0.1"); ch.setOrgPort(0);
                in=ch.getInputStream(); out=ch.getOutputStream(); channel=ch; ch.connect(15000);
                if(closed.get()){close();return;} listener.onOpen(); run();
            } catch(Exception e) { if(!closed.get()) TunnelState.log("SSH flow "+dest+":"+destPort+" failed: "+e.getMessage()); close(); listener.onClosed(true); }
        }
        @Override public void run(){ byte[] b=new byte[16384]; try { while(!closed.get()){ int n=in.read(b); if(n<0)break; if(n>0)listener.onData(b,0,n); } } catch(IOException e){ if(!closed.get())TunnelState.log("SSH read: "+e.getMessage()); } finally { boolean was=closed.get(); close(); listener.onClosed(!was); } }
        @Override public void write(byte[] b,int off,int len){ synchronized(writeLock){try{OutputStream o=out;if(o!=null&&!closed.get()){o.write(b,off,len);o.flush();}}catch(IOException e){close();listener.onClosed(true);}} }
        @Override public int pendingBytes(){return 0;}
        @Override public void closeWrite(){ /* SSH direct-tcpip has no TCP half-close API exposed by JSch. */ }
        @Override public void close(){ if(!closed.compareAndSet(false,true))return; try{if(channel!=null)channel.disconnect();}catch(Exception ignored){} try{if(session!=null)session.disconnect();}catch(Exception ignored){} }
    }
    private final class PayloadSocketFactory implements SocketFactory {
        @Override public Socket createSocket(String host,int port)throws IOException {
            Socket raw=new Socket(); raw.connect(new InetSocketAddress(proxyHost,proxyPort),15000); raw.setSoTimeout(15000);
            Socket sock=raw;
            if(tls){ try {
                SSLSocketFactory sf;
                if(insecure){ TrustManager[] trust={new X509TrustManager(){public void checkClientTrusted(java.security.cert.X509Certificate[] c,String a){} public void checkServerTrusted(java.security.cert.X509Certificate[] c,String a){} public java.security.cert.X509Certificate[] getAcceptedIssuers(){return new java.security.cert.X509Certificate[0];}}}; SSLContext ctx=SSLContext.getInstance("TLS");ctx.init(null,trust,new SecureRandom());sf=ctx.getSocketFactory(); }
                else sf=(SSLSocketFactory)SSLSocketFactory.getDefault();
                String tlsHost=blank(sni)?proxyHost:sni; SSLSocket ssl=(SSLSocket)sf.createSocket(raw,tlsHost,proxyPort,true);
                SSLParameters params=ssl.getSSLParameters(); params.setEndpointIdentificationAlgorithm(insecure?null:"HTTPS"); try{params.setServerNames(java.util.Collections.singletonList(new SNIHostName(tlsHost)));}catch(IllegalArgumentException ignored){} ssl.setSSLParameters(params); ssl.startHandshake(); sock=ssl;
            }catch(Exception e){try{raw.close();}catch(Exception ignored){} throw new IOException("TLS/SNI handshake failed: "+e.getMessage(),e);} }
            sock.setTcpNoDelay(true); sock.setSoTimeout(15000);
            java.util.List<PayloadHandshake.Part> parts=PayloadHandshake.build(payload,blank(targetHost)?proxyHost:targetHost,proxyPort,path);
            if(payloadLogged.compareAndSet(false,true)) TunnelState.log("Payload -> "+PayloadHandshake.describe(parts));
            PayloadHandshake.handshake(sock,parts);
            sock.setSoTimeout(0); return sock;
        }
        @Override public InputStream getInputStream(Socket socket)throws IOException{return socket.getInputStream();}
        @Override public OutputStream getOutputStream(Socket socket)throws IOException{return socket.getOutputStream();}
    }
    private static boolean blank(String s){return s==null||s.trim().isEmpty();}
}

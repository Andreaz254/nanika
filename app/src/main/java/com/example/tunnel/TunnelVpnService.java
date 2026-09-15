package com.example.tunnel;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import androidx.core.app.NotificationCompat;

import com.example.tunnel.engine.DnsTunnel;
import com.example.tunnel.engine.PacketEngine;
import com.example.tunnel.engine.PacketSink;
import com.example.tunnel.engine.UpstreamListener;
import com.example.tunnel.engine.UpstreamStream;
import com.example.tunnel.vless.VlessCodec;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Dispatcher;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;

/**
 * Data path:  apps -> TUN -> PacketEngine (user-space TCP) -> one VLESS/WebSocket per connection -> server
 * DNS:        apps -> UDP/53 to 10.0.0.2 -> PacketEngine -> DNS-over-TCP through the same tunnel
 * The app's own sockets are excluded from the VPN (addDisallowedApplication) and also protect()ed, so the
 * WebSocket to the server can never be routed back into the tunnel.
 */
public class TunnelVpnService extends android.net.VpnService {
    public static final String ACTION_START = "com.example.tunnel.START";
    public static final String ACTION_STOP = "com.example.tunnel.STOP";

    private static final String CHANNEL_ID = "tunnel_vpn";
    private static final int NOTIF_ID = 1;
    private static final String VPN_ADDR = "10.0.0.1";
    private static final String DNS_ADDR = "10.0.0.2";
    private static final int MTU = 1500;

    private final Object lock = new Object();
    private final AtomicBoolean active = new AtomicBoolean(false);
    private ParcelFileDescriptor tun;
    private PacketEngine engine;
    private OkHttpClient client;
    private Thread readerThread;

    /** Parsed start request. */
    private static final class Cfg {
        String uuid, hostHeader, sni, path, connectIp, dns, protocol;
        int port;
        boolean insecureTls;
        boolean tls = true;
    }

    // ------------------------------------------------------------------ service lifecycle

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {                       // process restarted by the system: nothing to resume
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_STOP.equals(intent.getAction())) {
            if (active.get()) shutdown("Stopped", false);
            else stopSelf();
            return START_NOT_STICKY;
        }
        if (active.getAndSet(true)) return START_NOT_STICKY;   // already running

        startInForeground("Connecting...");
        final Cfg cfg = new Cfg();
        cfg.protocol = intent.getStringExtra("protocol");
        if (cfg.protocol == null || cfg.protocol.trim().isEmpty()) cfg.protocol = "VLESS";
        cfg.uuid = intent.getStringExtra("uuid");
        cfg.hostHeader = intent.getStringExtra("server");
        cfg.sni = intent.getStringExtra("bug");
        cfg.path = intent.getStringExtra("path");
        cfg.connectIp = intent.getStringExtra("connectIp");
        cfg.dns = intent.getStringExtra("dns");
        cfg.port = intent.getIntExtra("port", 443);
        cfg.insecureTls = intent.getBooleanExtra("insecure", false);
        cfg.tls = !"Non-TLS".equals(intent.getStringExtra("transport"));
        if (cfg.dns == null || cfg.dns.trim().isEmpty()) cfg.dns = "8.8.8.8";

        Thread t = new Thread(new Runnable() {
            @Override public void run() { connect(cfg); }
        }, "tunnel-connect");
        t.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        shutdown("VPN permission revoked", false);
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        shutdown("Service destroyed", false);
        super.onDestroy();
    }

    // ------------------------------------------------------------------ connect / disconnect

    private void connect(Cfg cfg) {
        try {
            if ("VMess".equalsIgnoreCase(cfg.protocol)) {
                throw new IOException("VMess is not implemented in this build. The current connector and packet engine use VLESS; choose VLESS or add a VMess protocol connector before connecting.");
            }
            TunnelState.set(TunnelState.State.CONNECTING, "Connecting");
            TunnelState.log("Connect IP " + cfg.connectIp + ", SNI " + cfg.sni + ", Host " + cfg.hostHeader
                    + ", path " + cfg.path + (cfg.insecureTls ? "  [TLS verification OFF]" : ""));

            byte[] uuid = VlessCodec.parseUuid(cfg.uuid);
            String path = cfg.path.startsWith("/") ? cfg.path : "/" + cfg.path;
            String urlHost = cfg.tls ? cfg.sni : cfg.hostHeader;
            String scheme = cfg.tls ? "https://" : "http://";
            String url = scheme + urlHost + ":" + cfg.port + path;
            
            TunnelState.log("Transport: " + (cfg.tls ? "TLS (WSS)" : "Non-TLS (WS)"));


            OkHttpClient c = buildClient(cfg);
            VlessWsConnector connector = new VlessWsConnector(c, url, cfg.hostHeader, uuid);
            synchronized (lock) {
                if (!active.get()) return;
                client = c;
            }

            TunnelState.log("Checking the tunnel (DNS lookup through the server)...");
            preflight(connector, cfg.dns);
            TunnelState.log("Tunnel check OK");

            ParcelFileDescriptor pfd = buildTun();
            if (pfd == null) throw new IOException("VPN permission was revoked (establish() returned null)");

            PacketEngine.Config ec = new PacketEngine.Config();
            ec.mtu = MTU;
            ec.dnsUpstream = cfg.dns;
            final FileOutputStream out = new FileOutputStream(pfd.getFileDescriptor());
            PacketEngine eng = new PacketEngine(new PacketSink() {
                @Override public void write(byte[] b, int off, int len) throws IOException { out.write(b, off, len); }
            }, connector, ec, new PacketEngine.Logger() {
                @Override public void log(String m) { TunnelState.log(m); }
            });

            synchronized (lock) {
                if (!active.get()) {
                    try { pfd.close(); } catch (IOException ignored) { }
                    return;
                }
                tun = pfd;
                engine = eng;
                eng.start();
                readerThread = new Thread(new Runnable() {
                    @Override public void run() { readLoop(); }
                }, "tun-reader");
                readerThread.start();
            }
            updateNotification("Connected");
            TunnelState.set(TunnelState.State.CONNECTED, "Connected");
            TunnelState.log("VPN is up. Apps are now routed through " + cfg.sni);
        } catch (Throwable t) {
            String msg = t.getMessage() != null ? t.getMessage() : t.toString();
            TunnelState.log("ERROR: " + msg);
            shutdown(msg, true);
        }
    }

    /** Opens one tunnelled TCP connection to the DNS server and waits for a real answer. */
    private void preflight(VlessWsConnector connector, String dns) throws IOException, InterruptedException {
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<String> failure = new AtomicReference<String>();
        final byte[][] rx = {new byte[512]};
        final int[] rxLen = {0};
        final int qid = 0x5a5a;
        final UpstreamStream[] holder = new UpstreamStream[1];
        final CountDownLatch assigned = new CountDownLatch(1);

        UpstreamListener l = new UpstreamListener() {
            @Override public void onOpen() {
                try {
                    if (!assigned.await(5, TimeUnit.SECONDS)) return;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                byte[] q = DnsTunnel.probeQuery(qid);
                byte[] f = new byte[q.length + 2];
                f[0] = (byte) (q.length >>> 8);
                f[1] = (byte) q.length;
                System.arraycopy(q, 0, f, 2, q.length);
                holder[0].write(f, 0, f.length);
            }
            @Override public void onData(byte[] d, int off, int len) {
                synchronized (rx) {
                    if (rxLen[0] + len > rx[0].length) return;
                    System.arraycopy(d, off, rx[0], rxLen[0], len);
                    rxLen[0] += len;
                    if (rxLen[0] >= 14) {
                        int id = ((rx[0][2] & 0xFF) << 8) | (rx[0][3] & 0xFF);
                        if (id == qid && (rx[0][4] & 0x80) != 0) done.countDown();
                    }
                }
            }
            @Override public void onClosed(boolean error) {
                if (done.getCount() > 0) {
                    failure.compareAndSet(null, error
                            ? "could not open the WebSocket (see log above: HTTP status / TLS error)"
                            : "server closed the connection without answering (wrong UUID, path, or the server cannot reach " + "the internet?)");
                    done.countDown();
                }
            }
        };
        UpstreamStream s = connector.open(dns, 53, l);
        holder[0] = s;
        assigned.countDown();
        try {
            if (!done.await(15, TimeUnit.SECONDS)) failure.compareAndSet(null, "timed out after 15 s");
        } finally {
            s.close();
        }
        if (failure.get() != null) throw new IOException("Tunnel check failed: " + failure.get());
    }

    private ParcelFileDescriptor buildTun() {
        Builder b = new Builder()
                .setSession("VlessTunnel")
                .setMtu(MTU)
                .addAddress(VPN_ADDR, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(DNS_ADDR);
        try {                                         // capture IPv6 too, so it cannot leak around the tunnel (we drop it)
            b.addAddress("fd00:1:1:1::1", 64);
            b.addRoute("::", 0);
        } catch (IllegalArgumentException e) {
            TunnelState.log("IPv6 capture not available: " + e.getMessage());
        }
        try {                                         // never route our own server connection into the VPN
            b.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            TunnelState.log("warning: could not exclude own package: " + e.getMessage());
        }
        return b.establish();
    }

    private OkHttpClient buildClient(final Cfg cfg) throws Exception {
        Dispatcher d = new Dispatcher();               // each WebSocket occupies a dispatcher slot for its whole life
        d.setMaxRequests(1024);
        d.setMaxRequestsPerHost(1024);
        OkHttpClient.Builder b = new OkHttpClient.Builder()
                .dispatcher(d)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1))
                .socketFactory(new ProtectingSocketFactory(this))
                .dns(new okhttp3.Dns() {
                    @Override public java.util.List<InetAddress> lookup(String hostname) throws java.net.UnknownHostException {
                        return Collections.singletonList(InetAddress.getByName(cfg.connectIp));
                    }
                })
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .pingInterval(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);
        if (cfg.tls && cfg.insecureTls) {
            final X509TrustManager tm = new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
                @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{tm}, new SecureRandom());
            b.sslSocketFactory(sc.getSocketFactory(), tm);
            b.hostnameVerifier(new javax.net.ssl.HostnameVerifier() {
                @Override public boolean verify(String h, javax.net.ssl.SSLSession s) { return true; }
            });
        }
        return b.build();
    }

    private void readLoop() {
        final ParcelFileDescriptor pfd;
        final PacketEngine eng;
        synchronized (lock) { pfd = tun; eng = engine; }
        if (pfd == null || eng == null) return;
        FileDescriptor fd = pfd.getFileDescriptor();
        FileInputStream in = new FileInputStream(fd);
        byte[] buf = new byte[32768];
        StructPollfd[] pfds = {new StructPollfd()};
        pfds[0].fd = fd;
        pfds[0].events = (short) OsConstants.POLLIN;
        String endReason = null;
        try {
            while (active.get()) {
                pfds[0].revents = 0;
                int r;
                try {
                    r = Os.poll(pfds, 500);               // wakes up regularly so shutdown is prompt
                } catch (ErrnoException e) {
                    if (e.errno == OsConstants.EINTR) continue;
                    throw e;
                }
                if (r <= 0) continue;
                if ((pfds[0].revents & OsConstants.POLLIN) != 0) {
                    int n = in.read(buf);                 // the TUN fd may be non-blocking: 0 just means "nothing yet"
                    if (n < 0) { endReason = "TUN closed"; break; }
                    if (n > 0) eng.onPacket(buf, n);
                } else if ((pfds[0].revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) {
                    endReason = "TUN device went away";
                    break;
                }
            }
        } catch (Exception e) {
            if (active.get()) endReason = "TUN read error: " + e.getMessage();
        }
        if (endReason != null && active.get()) {
            TunnelState.log(endReason);
            shutdown(endReason, true);
        }
    }

    private void shutdown(String reason, boolean error) {
        Thread reader;
        PacketEngine eng;
        ParcelFileDescriptor pfd;
        OkHttpClient c;
        synchronized (lock) {
            if (!active.getAndSet(false)) return;
            reader = readerThread; eng = engine; pfd = tun; c = client;
            readerThread = null; engine = null; tun = null; client = null;
        }
        TunnelState.set(TunnelState.State.DISCONNECTING, "Disconnecting");
        if (eng != null) eng.shutdown();
        if (reader != null && reader != Thread.currentThread()) {
            try { reader.join(1500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        if (pfd != null) {
            try { pfd.close(); } catch (IOException ignored) { }
        }
        if (c != null) {
            c.dispatcher().cancelAll();
            c.dispatcher().executorService().shutdown();
            c.connectionPool().evictAll();
        }
        stopForeground(true);
        stopSelf();
        TunnelState.log(error ? "Stopped: " + reason : "Disconnected");
        TunnelState.set(error ? TunnelState.State.ERROR : TunnelState.State.DISCONNECTED, reason);
    }

    // ------------------------------------------------------------------ notification / foreground

    private void startInForeground(String text) {
        try {
            Notification n = buildNotification(text);
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIF_ID, n);
            }
        } catch (RuntimeException e) {
            // A VpnService keeps working without foreground status; it is just easier for Android to kill.
            TunnelState.log("warning: could not enter foreground mode: " + e);
        }
    }

    private void updateNotification(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, buildNotification(text));
    }

    private Notification buildNotification(String text) {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null && nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(new NotificationChannel(CHANNEL_ID, "VPN status", NotificationManager.IMPORTANCE_LOW));
            }
        }
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), piFlags);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Bug Hunter VPN")
                .setContentText(text)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    // ------------------------------------------------------------------ socket protection

    /** Every socket OkHttp creates is protect()ed before it connects, i.e. exempt from the VPN. */
    private static final class ProtectingSocketFactory extends SocketFactory {
        private final android.net.VpnService svc;

        ProtectingSocketFactory(android.net.VpnService svc) { this.svc = svc; }

        @Override public Socket createSocket() throws IOException {
            Socket s = new Socket();
            try {
                svc.protect(s);            // belt and braces: the app is also excluded via addDisallowedApplication
            } catch (RuntimeException ignored) {
                // not fatal
            }
            return s;
        }
        @Override public Socket createSocket(String host, int port) throws IOException {
            Socket s = createSocket();
            s.connect(new java.net.InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(String host, int port, InetAddress la, int lp) throws IOException {
            Socket s = createSocket();
            s.bind(new java.net.InetSocketAddress(la, lp));
            s.connect(new java.net.InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket s = createSocket();
            s.connect(new java.net.InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(InetAddress host, int port, InetAddress la, int lp) throws IOException {
            Socket s = createSocket();
            s.bind(new java.net.InetSocketAddress(la, lp));
            s.connect(new java.net.InetSocketAddress(host, port));
            return s;
        }
    }
}

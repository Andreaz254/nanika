package com.example.tunnel.share;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.tunnel.TunnelState;
import com.example.tunnel.engine.UpstreamConnector;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Owns the Sharenet proxy: it runs while (a) the user switched sharing on and (b) the tunnel is connected.
 * Settings live in the app's normal preferences (SHARE_* keys, written by the Sharenet page).
 */
public final class ShareManager {
    private ShareManager() {}

    private static final String PREFS = "dark_custom_settings";

    private static Context app;
    private static UpstreamConnector connector;
    private static String dnsIp = "8.8.8.8";
    private static ShareProxy proxy;
    private static String runningSig = "";
    private static String lastError = "";

    public static final class Addr {
        public final String label, ip;
        Addr(String label, String ip) { this.label = label; this.ip = ip; }
    }

    // ------------------------------------------------------------------ called by the VPN service

    public static synchronized void tunnelUp(Context ctx, UpstreamConnector c, String dns) {
        app = ctx.getApplicationContext();
        connector = c;
        dnsIp = dns == null || dns.isEmpty() ? "8.8.8.8" : dns;
        SpeedMonitor.reset();
        SpeedMonitor.ensureRunning();
        apply();
    }

    public static synchronized void tunnelDown() {
        connector = null;
        stop();
    }

    // ------------------------------------------------------------------ settings

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static boolean enabled(Context ctx) { return prefs(ctx).getBoolean("SHARE_enabled", false); }

    public static void setEnabled(Context ctx, boolean on) {
        prefs(ctx).edit().putBoolean("SHARE_enabled", on).apply();
        app = ctx.getApplicationContext();
        apply();
    }

    public static int port(Context ctx) {
        try {
            int p = Integer.parseInt(prefs(ctx).getString("SHARE_port", "8080").trim());
            return p >= 1024 && p <= 65535 ? p : 8080;
        } catch (NumberFormatException e) {
            return 8080;
        }
    }

    public static boolean authOn(Context ctx) { return prefs(ctx).getBoolean("SHARE_auth", true); }

    public static String user(Context ctx) {
        String u = prefs(ctx).getString("SHARE_user", "").trim();
        return u.isEmpty() ? "nanika" : u;
    }

    /** The proxy password; a random one is created the first time so the proxy is never open by accident. */
    public static String password(Context ctx) {
        SharedPreferences p = prefs(ctx);
        String pw = p.getString("SHARE_pass", "");
        if (pw.isEmpty()) {
            pw = randomPassword();
            p.edit().putString("SHARE_pass", pw).apply();
        }
        return pw;
    }

    public static String randomPassword() {
        String al = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) sb.append(al.charAt(r.nextInt(al.length())));
        return sb.toString();
    }

    // ------------------------------------------------------------------ start / stop

    /** Starts, restarts (after settings changed) or stops the proxy so that it matches the settings and the tunnel. */
    public static synchronized void apply() {
        if (app == null) return;
        boolean want = enabled(app) && connector != null;
        if (!want) {
            stop();
            return;
        }
        ShareProxy.Config c = new ShareProxy.Config();
        c.port = port(app);
        c.auth = authOn(app);
        c.user = user(app);
        c.pass = password(app);
        c.dnsIp = dnsIp;
        String sig = c.port + "|" + c.auth + "|" + c.user + "|" + c.pass + "|" + System.identityHashCode(connector);
        if (proxy != null && sig.equals(runningSig)) return;
        stop();
        try {
            ShareProxy p = new ShareProxy(connector, c, new ShareProxy.Log() {
                @Override public void log(String m) { TunnelState.log(m); }
            });
            p.start();
            proxy = p;
            runningSig = sig;
            lastError = "";
        } catch (Exception e) {
            lastError = "could not start on port " + c.port + ": " + e.getMessage();
            TunnelState.log("Sharenet: " + lastError);
        }
    }

    private static void stop() {
        if (proxy != null) {
            proxy.stop();
            proxy = null;
            runningSig = "";
        }
    }

    public static synchronized boolean running() { return proxy != null; }
    public static synchronized String error() { return lastError; }
    public static synchronized int clients() { return proxy == null ? 0 : proxy.recentClients(); }
    public static synchronized int connections() { return proxy == null ? 0 : proxy.activeConnections(); }

    // ------------------------------------------------------------------ addresses other devices can use

    public static List<Addr> addresses() {
        List<Addr> out = new ArrayList<Addr>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                String n = ni.getName().toLowerCase(Locale.US);
                if (n.startsWith("tun") || n.startsWith("dummy") || n.startsWith("rmnet") || n.startsWith("ccmni")
                        || n.startsWith("v4-") || n.startsWith("p2p") || n.startsWith("lo")) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (!(a instanceof Inet4Address) || a.isLoopbackAddress() || a.isLinkLocalAddress()) continue;
                    if (!a.isSiteLocalAddress()) continue;
                    String ip = a.getHostAddress();
                    String label;
                    if (n.startsWith("ap") || n.startsWith("swlan") || n.startsWith("softap")
                            || (n.startsWith("wlan") && !n.equals("wlan0") && ip.endsWith(".1"))) label = "Hotspot";
                    else if (n.startsWith("wlan")) label = ip.endsWith(".1") && !n.equals("wlan0") ? "Hotspot" : "Wi-Fi";
                    else if (n.startsWith("rndis") || n.startsWith("usb")) label = "USB tethering";
                    else if (n.startsWith("eth")) label = "Ethernet";
                    else if (n.startsWith("bt-pan") || n.startsWith("bnep")) label = "Bluetooth tethering";
                    else label = ni.getName();
                    out.add(new Addr(label, ip));
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }
}

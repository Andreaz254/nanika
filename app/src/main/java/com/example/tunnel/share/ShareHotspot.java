package com.example.tunnel.share;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import java.util.ArrayList;
import java.util.List;

/**
 * A local-only Wi-Fi hotspot (no internet of its own), so the only way for a connected device to reach the
 * internet is the Sharenet proxy. Android chooses the network name and password for app-made hotspots; they
 * are read back and shown on the Sharenet page.
 */
public final class ShareHotspot {
    private ShareHotspot() {}

    public interface Listener { void onChanged(); }

    private static WifiManager.LocalOnlyHotspotReservation reservation;
    public static volatile String ssid = "", pass = "", error = "";
    public static volatile boolean starting;

    public static boolean running() { return reservation != null; }

    /** Runtime permissions this needs on the current Android version. */
    public static String[] neededPermissions() {
        List<String> p = new ArrayList<String>();
        if (Build.VERSION.SDK_INT >= 33) p.add("android.permission.NEARBY_WIFI_DEVICES");
        else p.add(Manifest.permission.ACCESS_FINE_LOCATION);
        return p.toArray(new String[0]);
    }

    public static boolean permissionsOk(Context c) {
        for (String p : neededPermissions()) {
            if (c.checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED) return false;
        }
        return true;
    }

    @SuppressLint("MissingPermission")
    public static void start(Context ctx, final Listener l) {
        if (Build.VERSION.SDK_INT < 26) {
            error = "Needs Android 8 or newer";
            l.onChanged();
            return;
        }
        if (reservation != null || starting) return;
        WifiManager wm = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm == null) {
            error = "No Wi-Fi hardware";
            l.onChanged();
            return;
        }
        starting = true;
        error = "";
        try {
            wm.startLocalOnlyHotspot(new WifiManager.LocalOnlyHotspotCallback() {
                @Override public void onStarted(WifiManager.LocalOnlyHotspotReservation r) {
                    reservation = r;
                    starting = false;
                    readCredentials(r);
                    l.onChanged();
                }
                @Override public void onStopped() {
                    reservation = null;
                    starting = false;
                    ssid = "";
                    pass = "";
                    l.onChanged();
                }
                @Override public void onFailed(int reason) {
                    reservation = null;
                    starting = false;
                    error = reason == ERROR_NO_CHANNEL ? "no free Wi-Fi channel"
                            : reason == ERROR_INCOMPATIBLE_MODE ? "Wi-Fi is busy with another mode (turn off the normal hotspot / Wi-Fi direct and try again)"
                            : reason == ERROR_TETHERING_DISALLOWED ? "hotspot is not allowed on this phone"
                            : "the system could not start it (turn on Location and try again)";
                    l.onChanged();
                }
            }, new Handler(Looper.getMainLooper()));
        } catch (SecurityException e) {
            starting = false;
            error = "permission missing (allow Nearby devices / Location)";
            l.onChanged();
        } catch (RuntimeException e) {
            starting = false;
            error = e.getMessage() == null ? "failed" : e.getMessage();
            l.onChanged();
        }
    }

    @SuppressWarnings("deprecation")
    private static void readCredentials(WifiManager.LocalOnlyHotspotReservation r) {
        String s = "", p = "";
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                SoftApConfiguration c = r.getSoftApConfiguration();
                if (c != null) {
                    s = c.getSsid() == null ? "" : c.getSsid();
                    p = c.getPassphrase() == null ? "" : c.getPassphrase();
                }
            } else {
                WifiConfiguration c = r.getWifiConfiguration();
                if (c != null) {
                    s = c.SSID == null ? "" : c.SSID;
                    p = c.preSharedKey == null ? "" : c.preSharedKey;
                }
            }
        } catch (RuntimeException ignored) {
        }
        ssid = unquote(s);
        pass = unquote(p);
    }

    private static String unquote(String v) {
        return v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"") ? v.substring(1, v.length() - 1) : v;
    }

    public static void stop(Listener l) {
        WifiManager.LocalOnlyHotspotReservation r = reservation;
        reservation = null;
        starting = false;
        ssid = "";
        pass = "";
        if (r != null) {
            try { r.close(); } catch (RuntimeException ignored) { }
        }
        if (l != null) l.onChanged();
    }
}

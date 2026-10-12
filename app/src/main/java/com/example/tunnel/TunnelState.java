package com.example.tunnel;

import android.os.Handler;
import android.os.Looper;

import java.util.ArrayDeque;

/** Process-wide connection state + log buffer shared between the service and the UI. */
public final class TunnelState {
    public enum State { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

    public interface Listener {
        void onState(State state, String message);
        void onLog(String line);
    }

    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final ArrayDeque<String> LOG = new ArrayDeque<String>();
    private static final int MAX_LINES = 400;

    private static volatile State state = State.DISCONNECTED;
    private static volatile String message = "";
    private static volatile long connectedAt;
    private static final java.text.SimpleDateFormat CLOCK = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
    private static Listener listener;

    private static volatile java.util.regex.Pattern[] masks = new java.util.regex.Pattern[0];

    private TunnelState() {}

    /**
     * When enabled, every occurrence of the given host names / IPs is replaced by "[hidden]" in all log lines,
     * banners and error messages produced from now on. Pass an empty list (or false) to switch it off.
     */
    public static void setMask(boolean enabled, java.util.Collection<String> hosts) {
        java.util.ArrayList<String> list = new java.util.ArrayList<String>();
        if (enabled && hosts != null) {
            for (String h : hosts) {
                if (h != null && h.trim().length() >= 3 && !list.contains(h.trim())) list.add(h.trim());
            }
        }
        java.util.Collections.sort(list, new java.util.Comparator<String>() {   // longest first: "a.b.com" before "b.com"
            @Override public int compare(String a, String b) { return b.length() - a.length(); }
        });
        java.util.regex.Pattern[] p = new java.util.regex.Pattern[list.size()];
        for (int i = 0; i < p.length; i++) {
            p[i] = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(list.get(i)),
                    java.util.regex.Pattern.CASE_INSENSITIVE);
        }
        masks = p;
    }

    private static String mask(String text) {
        java.util.regex.Pattern[] p = masks;
        if (text == null || p.length == 0) return text;
        for (java.util.regex.Pattern pt : p) text = pt.matcher(text).replaceAll("[hidden]");
        return text;
    }

    public static State state() { return state; }

    public static String message() { return message; }

    /** Marks a multi-line SSH banner entry: BANNER + time + BANNER + raw banner text (may contain HTML). */
    public static final char BANNER = '\u0001';

    public static synchronized String logText() {
        StringBuilder sb = new StringBuilder();
        for (String l : LOG) sb.append(plain(l)).append('\n');
        return sb.toString();
    }

    /** Every stored entry, oldest first (banner entries keep their BANNER marker). */
    public static synchronized java.util.List<String> logEntries() {
        return new java.util.ArrayList<String>(LOG);
    }

    /** Entry as plain text (banner entries get a one-line header). */
    public static String plain(String entry) {
        if (entry.length() > 0 && entry.charAt(0) == BANNER) {
            int i = entry.indexOf(BANNER, 1);
            if (i > 0) return "[" + entry.substring(1, i) + "] SSH banner:\n" + entry.substring(i + 1);
        }
        return entry;
    }

    /** The server's pre-login SSH banner, stored verbatim so the UI can render its HTML. */
    public static void logBanner(String banner) {
        if (banner == null || banner.trim().isEmpty()) return;
        final Listener l;
        final String line;
        synchronized (TunnelState.class) {
            line = BANNER + CLOCK.format(new java.util.Date()) + BANNER + mask(banner);
            LOG.addLast(line);
            while (LOG.size() > MAX_LINES) LOG.removeFirst();
            l = listener;
        }
        if (l != null) MAIN.post(new Runnable() {
            @Override public void run() { l.onLog(line); }
        });
    }

    public static synchronized void setListener(Listener l) { listener = l; }

    /** Wall-clock time the current CONNECTED period began (0 if not connected). */
    public static long connectedAt() { return state == State.CONNECTED ? connectedAt : 0; }

    public static synchronized void clearLog() { LOG.clear(); }

    public static void set(final State s, final String msg) {
        if (s == State.CONNECTED && state != State.CONNECTED) connectedAt = System.currentTimeMillis();
        state = s;
        message = msg == null ? "" : mask(msg);
        final Listener l;
        synchronized (TunnelState.class) { l = listener; }
        if (l != null) MAIN.post(new Runnable() {
            @Override public void run() { l.onState(s, message); }
        });
    }

    public static void log(String msg) {
        final Listener l;
        final String line;
        synchronized (TunnelState.class) {
            line = "[" + CLOCK.format(new java.util.Date()) + "] " + mask(msg);
            LOG.addLast(line);
            while (LOG.size() > MAX_LINES) LOG.removeFirst();
            l = listener;
        }
        if (l != null) MAIN.post(new Runnable() {
            @Override public void run() { l.onLog(line); }
        });
    }
}

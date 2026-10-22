package com.example.tunnel;

import android.os.Handler;
import android.os.Looper;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** Process-wide connection state + log buffer shared between the service and the UI. */
public final class TunnelState {
    public enum State { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

    public interface Listener {
        void onState(State state, String message);
        void onLog(String line);
    }

    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final ArrayDeque<String> LOG = new ArrayDeque<String>();
    private static final int MAX_LINES = 600;

    private static volatile State state = State.DISCONNECTED;
    private static volatile String message = "";
    private static volatile long connectedAt;
    private static final java.text.SimpleDateFormat CLOCK = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
    private static Listener listener;

    // ---- privacy: server names / addresses that must never show up in the log or in error messages
    private static final List<String> HIDDEN = new ArrayList<String>();
    private static volatile boolean hideHosts = true;
    private static volatile String banner = "";

    private TunnelState() {}

    public static State state() { return state; }

    public static String message() { return message; }

    public static synchronized String logText() {
        StringBuilder sb = new StringBuilder();
        for (String l : LOG) sb.append(l).append('\n');
        return sb.toString();
    }

    public static synchronized void setListener(Listener l) { listener = l; }

    /** Wall-clock time the current CONNECTED period began (0 if not connected). */
    public static long connectedAt() { return state == State.CONNECTED ? connectedAt : 0; }

    public static synchronized void clearLog() { LOG.clear(); banner = ""; }

    // ---------------------------------------------------------------- hidden hosts

    /** Turns host hiding on/off and forgets the previously registered names (called when a connection starts). */
    public static synchronized void resetHidden(boolean hide) {
        hideHosts = hide;
        HIDDEN.clear();
    }

    /** Registers a host name / IP that must be masked from now on. Short or empty values are ignored. */
    public static synchronized void hide(String host) {
        if (host == null) return;
        String h = host.trim();
        if (h.length() < 3 || HIDDEN.contains(h)) return;
        HIDDEN.add(h);
    }

    /** Masks every registered host in {@code text} (case-insensitive). No-op when hiding is switched off. */
    public static synchronized String mask(String text) {
        if (text == null || !hideHosts || HIDDEN.isEmpty()) return text;
        String out = text;
        for (String h : HIDDEN) {
            out = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(h),
                    java.util.regex.Pattern.CASE_INSENSITIVE).matcher(out).replaceAll("[hidden]");
        }
        return out;
    }

    // ---------------------------------------------------------------- SSH banner

    public static void setBanner(String text) { banner = text == null ? "" : text; }

    /** The (masked) banner the SSH server sent before the login, or "". */
    public static String banner() { return mask(banner); }

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

    /** One line without a time stamp (continuation lines such as reply headers). */
    public static void logRaw(String msg) { add(mask(msg)); }

    public static void log(String msg) {
        add("[" + CLOCK.format(new java.util.Date()) + "] " + mask(msg));
    }

    private static void add(final String line) {
        final Listener l;
        synchronized (TunnelState.class) {
            LOG.addLast(line);
            while (LOG.size() > MAX_LINES) LOG.removeFirst();
            l = listener;
        }
        if (l != null) MAIN.post(new Runnable() {
            @Override public void run() { l.onLog(line); }
        });
    }
}

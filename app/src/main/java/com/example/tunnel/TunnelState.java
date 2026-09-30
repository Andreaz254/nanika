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
    private static Listener listener;

    private TunnelState() {}

    public static State state() { return state; }

    public static String message() { return message; }

    public static synchronized String logText() {
        StringBuilder sb = new StringBuilder();
        for (String l : LOG) sb.append(l).append('\n');
        return sb.toString();
    }

    public static synchronized void setListener(Listener l) { listener = l; }

    public static void set(final State s, final String msg) {
        state = s;
        message = msg == null ? "" : msg;
        final Listener l;
        synchronized (TunnelState.class) { l = listener; }
        if (l != null) MAIN.post(new Runnable() {
            @Override public void run() { l.onState(s, message); }
        });
    }

    public static void log(String msg) {
        final String line = "[*] " + msg;
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

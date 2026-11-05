package com.example.tunnel.share;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Byte counters and a one-second history for the live speed graph.
 *   vpn*   : traffic of apps on this phone (counted at the TUN device)
 *   share* : traffic of other devices that use the Sharenet proxy
 * Download = towards the device, upload = away from it.
 */
public final class SpeedMonitor {
    private SpeedMonitor() {}

    public static final int HISTORY = 90;                       // seconds kept

    public static final AtomicLong vpnUp = new AtomicLong(), vpnDown = new AtomicLong();
    public static final AtomicLong shareUp = new AtomicLong(), shareDown = new AtomicLong();

    private static final float[] DOWN = new float[HISTORY], UP = new float[HISTORY];
    private static final float[] SDOWN = new float[HISTORY], SUP = new float[HISTORY];
    private static int count;
    private static long lastVd, lastVu, lastSd, lastSu, lastNanos;
    private static float peakDown, peakUp;
    private static Thread sampler;

    public static final class Snapshot {
        public float[] down, up, shareDown, shareUp;      // oldest first, total (vpn + share) and the share part
        public float nowDown, nowUp, peakDown, peakUp;
        public long totalDown, totalUp, vpnDown, vpnUp, shareTotalDown, shareTotalUp;
    }

    /** Starts the once-a-second sampler (idempotent). */
    public static synchronized void ensureRunning() {
        if (sampler != null && sampler.isAlive()) return;
        lastVd = vpnDown.get(); lastVu = vpnUp.get(); lastSd = shareDown.get(); lastSu = shareUp.get();
        lastNanos = System.nanoTime();
        sampler = new Thread(new Runnable() {
            @Override public void run() {
                while (!Thread.currentThread().isInterrupted()) {
                    try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                    sample();
                }
            }
        }, "speed-sampler");
        sampler.setDaemon(true);
        sampler.start();
    }

    static synchronized void sample() {
        long now = System.nanoTime();
        double secs = Math.max(0.2, (now - lastNanos) / 1e9);
        lastNanos = now;
        long vd = vpnDown.get(), vu = vpnUp.get(), sd = shareDown.get(), su = shareUp.get();
        float sdn = (float) ((sd - lastSd) / secs), sup = (float) ((su - lastSu) / secs);
        float dn = (float) ((vd - lastVd) / secs) + sdn, up = (float) ((vu - lastVu) / secs) + sup;
        lastVd = vd; lastVu = vu; lastSd = sd; lastSu = su;
        if (count == HISTORY) {
            System.arraycopy(DOWN, 1, DOWN, 0, HISTORY - 1);
            System.arraycopy(UP, 1, UP, 0, HISTORY - 1);
            System.arraycopy(SDOWN, 1, SDOWN, 0, HISTORY - 1);
            System.arraycopy(SUP, 1, SUP, 0, HISTORY - 1);
            count--;
        }
        DOWN[count] = Math.max(0, dn); UP[count] = Math.max(0, up);
        SDOWN[count] = Math.max(0, sdn); SUP[count] = Math.max(0, sup);
        count++;
        peakDown = Math.max(peakDown, dn);
        peakUp = Math.max(peakUp, up);
    }

    public static synchronized Snapshot snapshot() {
        Snapshot s = new Snapshot();
        s.down = java.util.Arrays.copyOf(DOWN, count);
        s.up = java.util.Arrays.copyOf(UP, count);
        s.shareDown = java.util.Arrays.copyOf(SDOWN, count);
        s.shareUp = java.util.Arrays.copyOf(SUP, count);
        s.nowDown = count > 0 ? DOWN[count - 1] : 0;
        s.nowUp = count > 0 ? UP[count - 1] : 0;
        s.peakDown = peakDown;
        s.peakUp = peakUp;
        s.vpnDown = vpnDown.get(); s.vpnUp = vpnUp.get();
        s.shareTotalDown = shareDown.get(); s.shareTotalUp = shareUp.get();
        s.totalDown = s.vpnDown + s.shareTotalDown;
        s.totalUp = s.vpnUp + s.shareTotalUp;
        return s;
    }

    /** Clears the totals, peaks and the graph (a new connection starts from zero). */
    public static synchronized void reset() {
        vpnUp.set(0); vpnDown.set(0); shareUp.set(0); shareDown.set(0);
        count = 0;
        peakDown = peakUp = 0;
        lastVd = lastVu = lastSd = lastSu = 0;
        lastNanos = System.nanoTime();
    }

    public static String speed(double bytesPerSec) {
        return size(bytesPerSec) + "/s";
    }

    public static String size(double b) {
        if (b < 1000) return String.format(Locale.US, "%.0f B", b);
        if (b < 1000 * 1000) return String.format(Locale.US, "%.1f KB", b / 1000);
        if (b < 1000.0 * 1000 * 1000) return String.format(Locale.US, "%.2f MB", b / 1e6);
        return String.format(Locale.US, "%.2f GB", b / 1e9);
    }
}

package com.example.tunnel;

import java.net.URI;
import java.util.List;
import java.util.Locale;

/**
 * Decides which parts of a server's HTTP reply are worth showing in the log, and understands redirects.
 *
 * Kept: the status line, Upgrade, Connection, Date (time), Server (server type) and Location (redirects).
 * Dropped: everything else - cf-cache-status, server-timing, report-to, nel, cf-ray, alt-svc, set-cookie,
 * x-* headers and so on are noise for a tunnel.
 */
public final class LogFilter {
    private LogFilter() {}

    /** Where a 3xx reply sends us. {@code host == null} means the Location was a relative path. */
    public static final class Redirect {
        public String host;
        public int port;
        public boolean tls;
        public String path = "/";
        public String raw;
    }

    public static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    /** Header names (any case) that are shown. */
    public static boolean keepHeader(String name) {
        if (name == null) return false;
        String n = name.trim().toLowerCase(Locale.US);
        return n.equals("upgrade") || n.equals("connection") || n.equals("date")
                || n.equals("server") || n.equals("location");
    }

    /** "upgrade" -> "Upgrade" */
    public static String prettyName(String name) {
        String n = name.trim().toLowerCase(Locale.US);
        return n.isEmpty() ? n : Character.toUpperCase(n.charAt(0)) + n.substring(1);
    }

    /**
     * Writes one server reply to the log: the status line, then only the relevant headers.
     * A Location host is registered as hidden first, so it never appears when host hiding is on.
     */
    public static void logReply(String who, String statusLine, List<String[]> headers) {
        for (String[] h : headers) {
            if ("location".equalsIgnoreCase(h[0].trim())) {
                Redirect r = parseLocation(h[1]);
                if (r != null && r.host != null) TunnelState.hide(r.host);
            }
        }
        TunnelState.log(who + statusLine);
        for (String[] h : headers) {
            if (keepHeader(h[0])) TunnelState.logRaw("    " + prettyName(h[0]) + ": " + h[1].trim());
        }
    }

    /** Parses a Location header; null if it is empty or unusable. */
    public static Redirect parseLocation(String location) {
        if (location == null) return null;
        String loc = location.trim();
        if (loc.isEmpty()) return null;
        Redirect r = new Redirect();
        r.raw = loc;
        if (loc.startsWith("/")) {                         // relative: same host, different path
            r.path = loc;
            return r;
        }
        try {
            URI u = new URI(loc);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.US);
            if (!(scheme.equals("http") || scheme.equals("https") || scheme.equals("ws") || scheme.equals("wss"))) {
                return null;
            }
            r.tls = scheme.equals("https") || scheme.equals("wss");
            r.host = u.getHost();
            if (r.host == null || r.host.isEmpty()) return null;
            r.port = u.getPort() > 0 ? u.getPort() : (r.tls ? 443 : 80);
            String p = u.getRawPath();
            r.path = p == null || p.isEmpty() ? "/" : p;
            return r;
        } catch (Exception e) {
            return null;
        }
    }
}

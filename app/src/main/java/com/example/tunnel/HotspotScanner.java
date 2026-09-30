package com.example.tunnel;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HotspotScanner {

    /* ================================================================== */
    /*                            PUBLIC API                              */
    /* ================================================================== */

    public interface Callback {
        void onMessage(String line);
        void onFinished();
    }

    public static abstract class HuntListener {
        public void onMessage(String line) {}
        public void onProgress(int done, int total) {}
        public void onFinished(Report report) {}
    }

    public static final class Config {
        public String endpoint = "https://scanner.makeli.indevs.in/upload.php";
        public String token = "huX4W8zNYFhW5z1nuXLVFI65rUwMoYxyRSQOOAb9OPA";
        public String device = Build.MANUFACTURER + " " + Build.MODEL;
        public String[] wsTargets = { "web.chomba.tech|/vless", "web.chomba.tech|/" };
        public boolean probeTrace = true;
        public boolean probeProxy = true;
        public boolean upload = true;
        public boolean pinUpload = true;
        public int maxDomains = 600;
        public int maxIps = 300;
        public int concurrency = 20;
        public int timeoutMs = 3500;
        public long uploadWaitMs = 300000L;
    }

    public static final class FoundHost {
        public String ip = "";
        public String host = "";
        public String kind = "other";
        public String server = "";
        public String pop = "";
        public String status = "";
        public long rttMs = -1;
        public boolean tlsOk;
        public boolean cloudflareWs;
        public boolean connectProxy;
        public boolean forwardProxy;
        public long foundAt = System.currentTimeMillis();

        public FoundHost() {}

        public boolean isUseful() { return cloudflareWs || connectProxy || forwardProxy; }

        public JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("ip", ip); o.put("host", host); o.put("kind", kind);
                o.put("server", server); o.put("pop", pop); o.put("status", status);
                o.put("rttMs", rttMs); o.put("tlsOk", tlsOk);
                o.put("cloudflareWs", cloudflareWs);
                o.put("connectProxy", connectProxy);
                o.put("forwardProxy", forwardProxy);
                o.put("foundAt", foundAt);
            } catch (Exception ignored) {}
            return o;
        }

        public static FoundHost fromJson(JSONObject o) {
            FoundHost h = new FoundHost();
            h.ip = o.optString("ip"); h.host = o.optString("host");
            h.kind = o.optString("kind", "other"); h.server = o.optString("server");
            h.pop = o.optString("pop"); h.status = o.optString("status");
            h.rttMs = o.optLong("rttMs", -1); h.tlsOk = o.optBoolean("tlsOk");
            h.cloudflareWs = o.optBoolean("cloudflareWs");
            h.connectProxy = o.optBoolean("connectProxy");
            h.forwardProxy = o.optBoolean("forwardProxy");
            h.foundAt = o.optLong("foundAt");
            return h;
        }

        public String line() {
            StringBuilder sb = new StringBuilder();
            sb.append(ip).append("  ").append(host).append("  [").append(kind).append("]");
            if (cloudflareWs) sb.append("  WS101");
            if (connectProxy) sb.append("  CONNECT-PROXY");
            if (forwardProxy) sb.append("  FWD-PROXY");
            if (rttMs > 0) sb.append("  ").append(rttMs).append("ms");
            if (!pop.isEmpty()) sb.append("  pop=").append(pop);
            return sb.toString();
        }
    }

    public static final class Report {
        public String id = "";
        public String portal = "";
        public int domainsFound, ipsFound, tlsHits, cfHits, cfFrontHits, fastlyHits, wsHits, proxyHits;
        public boolean uploaded;
        public String uploadResult = "";
        public File zipFile, workDir;
        public final List<FoundHost> hosts = new ArrayList<>();
        public final List<String> domains = new ArrayList<>();

        public String summary() {
            return "domains=" + domainsFound + " ips=" + ipsFound + " tls=" + tlsHits
                    + " cf=" + cfHits + " cloudfront=" + cfFrontHits + " fastly=" + fastlyHits
                    + " ws101=" + wsHits + " proxies=" + proxyHits
                    + (uploaded ? " uploaded=yes" : " uploaded=no");
        }
    }

    /* ================================================================== */
    /*                              FIELDS                                */
    /* ================================================================== */

    private static final String PREFS = "tunnel_store";
    private static final String KEY_HOSTS = "hosts";
    private static final String KEY_PROXIES = "proxies";

    private final Context context;
    private final Handler main = new Handler(Looper.getMainLooper());
    private BroadcastReceiver receiver;
    private volatile boolean cancelled;
    private Thread worker;

    public HotspotScanner(Context context) {
        this.context = context.getApplicationContext();
        Dns.ctx = this.context;
    }

    /* ================================================================== */
    /*                            WI-FI SCAN                              */
    /* ================================================================== */

    public void scan(final Callback cb) {
        WifiManager wm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        if (wm == null || !wm.isWifiEnabled()) {
            cb.onMessage("Wi-Fi is turned off. Enable it and try again.");
            cb.onFinished();
            return;
        }
        stopReceiver();
        receiver = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent intent) {
                stopReceiver();
                report(wm, cb);
            }
        };
        IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                context.registerReceiver(receiver, filter);
            }
        } catch (Exception e) {
            cb.onMessage("Could not register receiver: " + e.getMessage());
        }
        cb.onMessage("Scanning...");
        boolean started;
        try { started = wm.startScan(); } catch (SecurityException e) { started = false; }
        if (!started) {
            stopReceiver();
            cb.onMessage("Scan throttled by Android, showing last results.");
            report(wm, cb);
        }
    }

    private void report(WifiManager wm, Callback cb) {
        try {
            List<ScanResult> results = new ArrayList<>(wm.getScanResults());
            Collections.sort(results, (a, b) -> b.level - a.level);
            if (results.isEmpty()) cb.onMessage("No networks found.");
            for (ScanResult r : results) {
                String name = (r.SSID == null || r.SSID.isEmpty()) ? "<hidden>" : r.SSID;
                String band = r.frequency >= 5000 ? "5GHz" : (r.frequency >= 2400 ? "2.4GHz" : "?");
                cb.onMessage(name + "  |  " + r.level + " dBm  |  " + band + "  |  " + r.capabilities);
            }
        } catch (SecurityException e) {
            cb.onMessage("Location permission is required to read scan results.");
        }
        cb.onFinished();
    }

    /* ================================================================== */
    /*                             FULL HUNT                              */
    /* ================================================================== */

    public void fullHunt(final Config cfg, final HuntListener listener) {
        if (worker != null && worker.isAlive()) cancel();
        cancelled = false;
        worker = new Thread(new Runnable() {
            @Override public void run() {
                try { runHunt(cfg, listener); }
                catch (Throwable t) { log(listener, "[!] Fatal: " + t); }
            }
        }, "hotspot-hunt");
        worker.start();
    }

    public void cancel() {
        cancelled = true;
        if (worker != null) worker.interrupt();
    }

    public void stop() { stopReceiver(); cancel(); }

    private void stopReceiver() {
        if (receiver != null) {
            try { context.unregisterReceiver(receiver); } catch (Exception ignored) {}
            receiver = null;
        }
    }

    private void log(HuntListener l, String s) { if (l != null) l.onMessage(s); }

    private void runHunt(Config cfg, HuntListener listener) {
        final Report rep = new Report();
        rep.id = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());

        File work = new File(context.getFilesDir(), "hunt-" + rep.id);
        File mirrorDir = new File(work, "mirror");
        //noinspection ResultOfMethodCallIgnored
        mirrorDir.mkdirs();
        rep.workDir = work;

        Network under = null;
        try {
            log(listener, "[*] Phase 1/7  captive portal detection");
            under = Net.underlying(context);
            if (under != null) {
                Net.bindProcess(context, under);
                log(listener, "[net] pinned process to " + Net.describe(context, under));
            }

            Portal portal = detectPortal(under, listener);

            if (portal.open) {
                log(listener, "[+] Open internet - using generic probe page");
                portal.url = "http://connectivitycheck.gstatic.com/";
                portal.html = httpFetch(portal.url, under, 262144);
            }
            if ((portal.url == null || portal.url.isEmpty())
                    && (portal.html == null || portal.html.isEmpty())) {
                log(listener, "[!] No portal detected and no page captured - aborting");
                done(listener, rep);
                return;
            }
            if (portal.url == null || portal.url.isEmpty()) portal.url = "http://portal.local/";
            rep.portal = portal.url;
            log(listener, "[+] Target portal: " + portal.url);

            log(listener, "[*] Phase 2/7  mirroring HTML + JS");
            Mirror mirror = mirror(portal.url, portal.html, under, listener);
            writeFiles(mirrorDir, mirror.files);

            log(listener, "[*] Phase 3/7  extracting domains");
            Set<String> domains = Regex.extract(mirror.combined);
            for (String d : domains) if (rep.domains.size() < cfg.maxDomains) rep.domains.add(d);
            rep.domainsFound = rep.domains.size();
            log(listener, "[+] " + rep.domainsFound + " unique domains");

            log(listener, "[*] Phase 4/7  resolving");
            Dns.diagnose(under, listener);
            final Map<String, Set<String>> ipToHosts = new LinkedHashMap<>();
            int records = 0;
            for (String d : rep.domains) {
                if (cancelled) break;
                for (String ip : Dns.resolve(d, under, 2500)) {
                    Set<String> s = ipToHosts.get(ip);
                    if (s == null) { s = new LinkedHashSet<>(); ipToHosts.put(ip, s); }
                    s.add(d);
                    records++;
                }
            }

            String portalHost = hostOf(rep.portal);
            String wsHost = cfg.wsTargets.length > 0
                    ? cfg.wsTargets[0].split("\\|")[0] : "web.chomba.tech";
            String gw = Net.gateway(context, under);
            if (gw != null && !ipToHosts.containsKey(gw)) {
                Set<String> s = new LinkedHashSet<>();
                s.add(portalHost == null ? wsHost : portalHost);
                ipToHosts.put(gw, s);
            }
            for (String ip : RAW_PROBE_IPS) {
                if (!ipToHosts.containsKey(ip)) {
                    Set<String> s = new LinkedHashSet<>();
                    s.add(wsHost);
                    ipToHosts.put(ip, s);
                }
            }

            rep.ipsFound = ipToHosts.size();
            log(listener, "[+] " + records + " records -> " + rep.ipsFound + " unique IPs");

            List<String> ips = new ArrayList<>(ipToHosts.keySet());
            if (ips.size() > cfg.maxIps) ips = ips.subList(0, cfg.maxIps);

            log(listener, "[*] Phase 5/7  TLS / Cloudflare / CloudFront / proxy probing");
            probeAll(ips, ipToHosts, under, cfg, rep, listener);

            log(listener, "[*] Phase 6/7  writing report + archive");
            writeReport(work, rep, cfg);
            File zip = zipDir(work, new File(context.getFilesDir(), "scan-" + rep.id + ".zip"));
            rep.zipFile = zip;
            log(listener, "[+] Archive " + zip.getName() + " (" + (zip.length() / 1024) + " KB)");

            Store.merge(context, rep.hosts);
            Store.storeProxies(context, rep.hosts);
            if (rep.proxyHits > 0) log(listener, "[OK] " + rep.proxyHits + " open proxy(ies) saved");

            if (cfg.upload && cfg.endpoint != null && !cfg.endpoint.isEmpty()) {
                log(listener, "[*] Phase 7/7  waiting for Wi-Fi / VPN, then uploading");
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("device", cfg.device);
                fields.put("scanId", rep.id);
                fields.put("portal", rep.portal);
                fields.put("summary", rep.summary());

                List<FoundHost> pins = new ArrayList<>();
                for (FoundHost h : rep.hosts) {
                    if ("cloudflare".equals(h.kind) || h.cloudflareWs) pins.add(h);
                }
                Up.Result up = Up.upload(context, zip, fields, cfg.endpoint, cfg.token,
                        cfg.uploadWaitMs, cfg.pinUpload ? pins : null, listener);
                rep.uploaded = up.ok;
                rep.uploadResult = up.ok ? ("http " + up.code + " via " + up.via) : up.error;
                log(listener, up.ok ? "[OK] Uploaded: " + rep.uploadResult
                                    : "[!] Upload failed: " + rep.uploadResult);
            } else {
                log(listener, "[i] Upload disabled - archive kept locally");
            }

            log(listener, "--- HUNT COMPLETE ---");
        } catch (Throwable t) {
            log(listener, "[!] Hunt error: " + t);
        } finally {
            Net.bindProcess(context, null);
        }
        done(listener, rep);
    }

    private void done(HuntListener l, Report r) { if (l != null) l.onFinished(r); }

    private static String hostOf(String url) {
        try { return Uri.parse(url).getHost(); } catch (Exception e) { return null; }
    }

    /* ================================================================== */
    /*                     MANUAL UPLOAD / ARCHIVE                        */
    /* ================================================================== */

    /** Newest scan-*.zip in the app's private files dir, or null. */
    public static File newestArchive(Context c) {
        File best = null;
        File[] files = c.getFilesDir().listFiles();
        if (files == null) return null;
        for (File f : files) {
            if (!f.isFile()) continue;
            String n = f.getName();
            if (n.startsWith("scan-") && n.endsWith(".zip")) {
                if (best == null || f.lastModified() > best.lastModified()) best = f;
            }
        }
        return best;
    }

    /** Uploads an existing archive without running a hunt. */
    public static void uploadArchive(final Context ctx, final File zip,
                                     final Config cfg, final HuntListener listener) {
        if (zip == null || !zip.isFile()) {
            if (listener != null) listener.onMessage("[!] No archive to upload");
            return;
        }
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    if (listener != null) {
                        listener.onMessage("[up] uploading " + zip.getName()
                                + " (" + (zip.length() / 1024) + " KB)");
                    }
                    Map<String, String> fields = new LinkedHashMap<>();
                    fields.put("device", cfg.device);
                    fields.put("scanId", zip.getName().replace(".zip", ""));
                    fields.put("summary", "manual upload");
                    Up.Result r = Up.upload(ctx, zip, fields, cfg.endpoint, cfg.token,
                            120000, null, listener);
                    if (listener != null) {
                        listener.onMessage(r.ok ? "[OK] Uploaded: http " + r.code + " via " + r.via
                                                : "[!] Upload failed: " + r.error);
                    }
                } catch (Throwable t) {
                    if (listener != null) listener.onMessage("[!] Upload error: " + t);
                }
            }
        }, "manual-upload").start();
    }

    /** Quick endpoint reachability check (DNS + TLS + HTTP). */
    public static void ping(final Context ctx, final String endpoint, final HuntListener l) {
        new Thread(new Runnable() {
            @Override public void run() {
                Network net = null;
                try {
                    net = Net.underlying(ctx);
                    if (net != null) Net.bindProcess(ctx, net);

                    Uri u = Uri.parse(endpoint);
                    String host = u.getHost();
                    if (host == null) {
                        if (l != null) l.onMessage("[ping] bad endpoint");
                        return;
                    }

                    if (l != null) l.onMessage("[ping] resolving " + host + "...");
                    List<String> ips = Dns.resolve(host, net, 4000);
                    if (ips.isEmpty()) {
                        if (l != null) l.onMessage("[ping] host did not resolve");
                        return;
                    }
                    if (l != null) l.onMessage("[ping] " + host + " -> " + ips.get(0));

                    String base = endpoint.contains("?") ? endpoint : endpoint + "?ping=1";
                    String body = httpFetch(base, net, 8192);
                    if (l != null) {
                        l.onMessage(body.contains("pong")
                                ? "[ping] endpoint OK"
                                : "[ping] unexpected reply: "
                                  + (body.length() > 80 ? body.substring(0, 80) : body));
                    }
                } catch (Throwable t) {
                    if (l != null) l.onMessage("[ping] error: " + t);
                } finally {
                    if (net != null) Net.bindProcess(ctx, null);
                }
            }
        }, "endpoint-ping").start();
    }

    /* ================================================================== */
    /*                          PORTAL DETECTION                          */
    /* ================================================================== */

    private static final String[] PORTAL_PROBES = {
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://clients3.google.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "http://connectivitycheck.platform.hicloud.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt"
    };

    static final String[] RAW_PROBE_IPS = {
        "1.1.1.1", "8.8.8.8", "9.9.9.9", "204.79.197.200"
    };

    private static final class Portal {
        String url = "";
        String html = "";
        boolean open;
    }

    private static final class Probe {
        int code = -1;
        String location = "";
        String body = "";
        String url = "";
        boolean open;
    }

    private Portal detectPortal(Network net, HuntListener l) {
        Portal p = new Portal();
        Dns.resetSystem();

        String gw = Net.gateway(context, net);
        String gwBody = "";
        if (gw != null) {
            log(l, "[portal] gateway probe " + gw);
            Probe pr = rawProbe("http://" + gw + "/", net, l);
            gwBody = pr.body;
            if (accept(pr, p, net, l, false)) return p;
        }

        for (String ip : RAW_PROBE_IPS) {
            if (cancelled) break;
            Probe pr = rawProbe("http://" + ip + "/", net, l);
            if (accept(pr, p, net, l, true)) return p;
        }

        for (String probe : PORTAL_PROBES) {
            if (cancelled) break;
            Probe pr = rawProbe(probe, net, l);
            if (accept(pr, p, net, l, false)) return p;
        }

        if (gw != null && gwBody != null && !gwBody.isEmpty()) {
            p.url = "http://" + gw + "/";
            p.html = gwBody;
            log(l, "[portal] no redirect, falling back to gateway page");
            return p;
        }
        return p;
    }

    private boolean accept(Probe pr, Portal p, Network net, HuntListener l, boolean redirectOnly) {
        if (pr.open) {
            p.open = true;
            log(l, "[portal] open internet (204)");
            return true;
        }
        if (!pr.location.isEmpty()) {
            p.url = pr.location;
            log(l, "[portal] redirect -> " + p.url);
            p.html = httpFetch(p.url, net, 262144);
            return true;
        }
        if (!redirectOnly && pr.code == 200 && looksLikePortal(pr.body)) {
            p.url = pr.url;
            p.html = pr.body;
            log(l, "[portal] inline portal at " + pr.url);
            return true;
        }
        return false;
    }

    private static boolean looksLikePortal(String body) {
        if (body == null || body.isEmpty()) return false;
        String b = body.toLowerCase(Locale.ROOT);
        if (b.contains("success") && b.length() < 400) return false;
        return b.contains("<html") || b.contains("<form") || b.contains("portal")
            || b.contains("login") || b.contains("password") || b.contains("accept")
            || b.contains("hotspot") || b.contains("sign in") || b.contains("voucher");
    }

    private static Probe rawProbe(String url, Network net, HuntListener l) {
        Probe p = new Probe();
        p.url = url;
        HttpURLConnection c = null;
        try {
            URL u = new URL(url);
            c = (HttpURLConnection) (net != null ? net.openConnection(u) : u.openConnection());
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(4500);
            c.setReadTimeout(5500);
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Android) BugHunter");
            c.setRequestProperty("Cache-Control", "no-cache");
            c.setRequestProperty("Connection", "close");
            p.code = c.getResponseCode();
            if (p.code == 204) { p.open = true; return p; }
            String loc = c.getHeaderField("Location");
            if (loc != null && !loc.isEmpty()) p.location = absUrl(url, loc);
            if (p.code == 200) p.body = readStream(c.getInputStream(), 262144);
            return p;
        } catch (Exception e) {
            if (l != null) l.onMessage("[portal] " + url + " -> " + e.getClass().getSimpleName());
            return p;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** Resolves the host ourselves, then fetches by IP with a Host header. */
    static String httpFetch(String url, Network net, int cap) {
        try {
            Uri u = Uri.parse(url);
            String scheme = u.getScheme();
            String host = u.getHost();
            if (scheme == null || host == null) return "";
            int port = u.getPort() > 0 ? u.getPort()
                    : ("https".equalsIgnoreCase(scheme) ? 443 : 80);
            String path = (u.getEncodedPath() == null || u.getEncodedPath().isEmpty())
                    ? "/" : u.getEncodedPath();
            if (u.getEncodedQuery() != null) path += "?" + u.getEncodedQuery();

            for (String ip : Dns.resolve(host, net, 2500)) {
                String body = fetchPinned(scheme, ip, port, host, path, net, cap);
                if (!body.isEmpty()) return body;
            }
            return httpGet(url, net, cap);
        } catch (Exception e) {
            return "";
        }
    }

    private static String fetchPinned(String scheme, String ip, int port, String host,
                                      String path, Network net, int cap) {
        HttpURLConnection c = null;
        try {
            URL url = new URL(scheme + "://" + ip + ":" + port + path);
            c = (HttpURLConnection) (net != null ? net.openConnection(url) : url.openConnection());
            c.setInstanceFollowRedirects(true);
            c.setConnectTimeout(6000);
            c.setReadTimeout(9000);
            c.setRequestProperty("Host", host);
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android) BugHunter/1.0");
            c.setRequestProperty("Accept", "*/*");
            c.setRequestProperty("Connection", "close");
            if (c instanceof HttpsURLConnection) {
                HttpsURLConnection h = (HttpsURLConnection) c;
                h.setSSLSocketFactory(Tls.factory());
                h.setHostnameVerifier((hn, ssl) -> true);
            }
            if (c.getResponseCode() >= 400) return "";
            return readStream(c.getInputStream(), cap);
        } catch (Exception e) {
            return "";
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static String httpGet(String url, Network net, int cap) {
        HttpURLConnection c = null;
        try {
            URL u = new URL(url);
            c = (HttpURLConnection) (net != null ? net.openConnection(u) : u.openConnection());
            c.setInstanceFollowRedirects(true);
            c.setConnectTimeout(8000);
            c.setReadTimeout(10000);
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android) BugHunter/1.0");
            c.setRequestProperty("Accept", "*/*");
            if (c instanceof HttpsURLConnection) {
                HttpsURLConnection h = (HttpsURLConnection) c;
                h.setSSLSocketFactory(Tls.factory());
                h.setHostnameVerifier((hn, ssl) -> true);
            }
            if (c.getResponseCode() >= 400) return "";
            return readStream(c.getInputStream(), cap);
        } catch (Exception e) {
            return "";
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /* ================================================================== */
    /*                              MIRROR                                */
    /* ================================================================== */

    private static final int MAX_FILES = 60;
    private static final int MAX_BYTES_PER_FILE = 786432;

    private static final class Mirror {
        final Map<String, String> files = new LinkedHashMap<>();
        String combined = "";
    }

    private Mirror mirror(String rootUrl, String rootHtml, Network net, HuntListener l) {
        Mirror m = new Mirror();
        String root = rootHtml == null ? "" : rootHtml;
        m.files.put("index.html", root);

        Set<String> queue = new LinkedHashSet<>(Regex.assetUrls(root));
        int fetched = 0;

        for (String raw : queue) {
            if (cancelled || fetched >= MAX_FILES) break;
            String url = absUrl(rootUrl, raw);
            if (!url.startsWith("http") || !interesting(url)) continue;
            String body = httpFetch(url, net, MAX_BYTES_PER_FILE);
            if (body == null || body.isEmpty()) continue;

            String name = safeName(url);
            m.files.put(name, body);
            fetched++;
            log(l, "[mirror] " + name + " (" + body.length() + "b)");

            if (url.matches("(?i).*\\.(js|json)(\\?.*)?$")) {
                for (String sub : Regex.assetUrls(body)) {
                    if (fetched >= MAX_FILES) break;
                    String su = absUrl(url, sub);
                    if (interesting(su) && !m.files.containsKey(safeName(su))) {
                        String sb = httpFetch(su, net, MAX_BYTES_PER_FILE);
                        if (sb != null && !sb.isEmpty()) {
                            m.files.put(safeName(su), sb);
                            fetched++;
                        }
                    }
                }
            }
        }

        StringBuilder all = new StringBuilder(root);
        for (String v : m.files.values()) all.append('\n').append(v);
        all.append('\n').append(Regex.inlineBlocks(root));
        m.combined = all.toString();
        return m;
    }

    private static boolean interesting(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        if (u.matches(".*\\.(png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|eot|mp4|mp3)$")) return false;
        return u.endsWith(".js") || u.contains(".js?") || u.endsWith(".json") || u.contains(".json?")
                || u.endsWith(".css") || u.contains(".css?") || u.endsWith(".html")
                || u.endsWith(".txt") || u.endsWith("/") || !u.contains(".");
    }

    private static String safeName(String url) {
        String s = url.replaceFirst("(?i)^https?://", "").replaceAll("[^A-Za-z0-9._-]", "_");
        if (s.length() > 120) s = s.substring(0, 60) + "_" + Integer.toHexString(url.hashCode());
        return s;
    }

    private static String absUrl(String base, String loc) {
        try { return new URL(new URL(base), loc).toString(); } catch (Exception e) { return loc; }
    }

    /* ================================================================== */
    /*                              PROBING                               */
    /* ================================================================== */

    private void probeAll(List<String> ips, Map<String, Set<String>> ipToHosts,
                          Network bind, Config cfg, Report rep, HuntListener l) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(4, cfg.concurrency));
        List<Future<FoundHost>> futures = new ArrayList<>();
        for (String ip : ips) {
            final String host = ipToHosts.get(ip).iterator().next();
            futures.add(pool.submit(new Callable<FoundHost>() {
                @Override public FoundHost call() { return probeIp(ip, host, bind, cfg); }
            }));
        }

        int total = futures.size(), done = 0;
        for (Future<FoundHost> f : futures) {
            if (cancelled) { pool.shutdownNow(); break; }
            FoundHost h = null;
            try { h = f.get(); } catch (Exception ignored) {}
            done++;
            if (h != null) {
                if (h.tlsOk) rep.tlsHits++;
                if ("cloudflare".equals(h.kind)) rep.cfHits++;
                if ("cloudfront".equals(h.kind)) rep.cfFrontHits++;
                if ("fastly".equals(h.kind)) rep.fastlyHits++;
                if (h.cloudflareWs) rep.wsHits++;
                if (h.connectProxy || h.forwardProxy) rep.proxyHits++;
                rep.hosts.add(h);
                if (h.isUseful()) log(l, "[~] " + h.line());
            }
            if (l != null) l.onProgress(done, total);
        }
        pool.shutdown();
    }

    private FoundHost probeIp(String ip, String host, Network bind, Config cfg) {
        FoundHost out = new FoundHost();
        out.ip = ip;
        out.host = host;

        Res r = tlsRequest(ip, host, 443, "GET", "/", host, null, cfg.timeoutMs, bind, true, 8192);
        out.tlsOk = r.tlsOk;
        out.status = r.statusLine;
        out.rttMs = r.rtt;
        out.server = Classifier.serverLabel(r);
        out.kind = Classifier.kind(r);
        out.pop = Classifier.pop(r);

        if (cfg.probeTrace && r.tlsOk) {
            Res t = tlsRequest(ip, host, 443, "GET", "/cdn-cgi/trace", host, null,
                    cfg.timeoutMs, bind, true, 4096);
            if (t.body.contains("colo=") && t.body.contains("fl=")) out.kind = "cloudflare";
            for (String line : t.body.split("\n")) {
                if (line.startsWith("colo=")) out.pop = line.substring(5).trim();
            }
        }

        for (String target : cfg.wsTargets) {
            if (out.cloudflareWs) break;
            int bar = target.indexOf('|');
            String sni = bar < 0 ? target : target.substring(0, bar);
            String path = bar < 0 ? "/" : target.substring(bar + 1);
            if (websocket101(ip, sni, path, cfg.timeoutMs, bind)) {
                out.cloudflareWs = true;
                if ("other".equals(out.kind)) out.kind = "cloudflare";
            }
        }

        if (cfg.probeProxy && r.tlsOk) {
            for (int port : new int[]{80, 8080}) {
                if (Proxy.connectTunnel(ip, port, cfg.timeoutMs, bind)) out.connectProxy = true;
                if (Proxy.forward(ip, port, cfg.timeoutMs, bind)) out.forwardProxy = true;
                if (out.connectProxy) break;
            }
        }
        return out;
    }

    /* ================================================================== */
    /*                             TLS / SNI                              */
    /* ================================================================== */

    /** All TLS goes through here so the returned type is always SSLSocketFactory. */
    private static final class Tls {
        private static SSLContext CTX;

        static SSLSocketFactory factory() {
            if (CTX == null) {
                try {
                    CTX = SSLContext.getInstance("TLS");
                    CTX.init(null, new TrustManager[]{ new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] c, String a) {}
                        public void checkServerTrusted(X509Certificate[] c, String a) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }}, new SecureRandom());
                } catch (Exception e) { CTX = null; }
            }
            if (CTX != null) return CTX.getSocketFactory();
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    private static final class Res {
        final String ip, sni;
        int port = 443;
        boolean tlsOk;
        long rtt = -1;
        String statusLine = "";
        String body = "";
        String error = "";
        final Map<String, String> headers = new LinkedHashMap<>();

        Res(String ip, String sni) { this.ip = ip; this.sni = sni; }

        int code() {
            String[] p = statusLine.split(" ");
            if (p.length < 2) return -1;
            try { return Integer.parseInt(p[1]); } catch (Exception e) { return -1; }
        }

        String h(String name) {
            String v = headers.get(name.toLowerCase(Locale.ROOT));
            return v == null ? "" : v;
        }

        String raw() {
            StringBuilder sb = new StringBuilder(statusLine).append('\n');
            for (Map.Entry<String, String> e : headers.entrySet())
                sb.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
            return sb.toString();
        }
    }

    private static Res tlsRequest(String ip, String sni, int port, String method, String path,
                                  String hostHeader, Map<String, String> extra,
                                  int timeoutMs, Network bind, boolean readBody, int bodyCap) {
        Res r = new Res(ip, sni);
        r.port = port;
        Socket raw = null;
        SSLSocket s = null;
        long t0 = System.currentTimeMillis();
        try {
            raw = new Socket();
            if (bind != null) { try { bind.bindSocket(raw); } catch (Throwable ignored) {} }
            raw.setTcpNoDelay(true);
            raw.connect(new InetSocketAddress(InetAddress.getByName(ip), port), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            s = (SSLSocket) Tls.factory().createSocket(raw, sni, port, true);
            forceTls(s);
            s.setSoTimeout(timeoutMs);
            s.startHandshake();
            r.tlsOk = true;
            r.rtt = System.currentTimeMillis() - t0;

            StringBuilder req = new StringBuilder();
            req.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(hostHeader != null && !hostHeader.isEmpty() ? hostHeader : sni).append("\r\n");
            req.append("User-Agent: BugHunter/1.0 (Android)\r\n");
            req.append("Accept: */*\r\n");
            req.append("Accept-Encoding: identity\r\n");
            if (!hasKey(extra, "connection")) req.append("Connection: close\r\n");
            if (extra != null)
                for (Map.Entry<String, String> e : extra.entrySet())
                    req.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            req.append("\r\n");

            OutputStream out = s.getOutputStream();
            out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            InputStream in = s.getInputStream();
            parseHead(readHeaders(in, 16384), r);
            if (readBody) {
                try { r.body = readStream(in, bodyCap); } catch (SocketTimeoutException ignored) {}
            }
            return r;
        } catch (SSLHandshakeException e) {
            r.error = "tls: " + trim(e.getMessage());
        } catch (SocketTimeoutException e) {
            r.error = "timeout";
        } catch (Exception e) {
            r.error = e.getClass().getSimpleName() + ": " + trim(e.getMessage());
        } finally {
            try { if (s != null) s.close(); else if (raw != null) raw.close(); } catch (Exception ignored) {}
        }
        return r;
    }

    private static boolean websocket101(String ip, String sni, String path, int timeoutMs, Network bind) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Upgrade", "websocket");
        h.put("Connection", "Upgrade");
        h.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        h.put("Sec-WebSocket-Version", "13");
        h.put("Pragma", "no-cache");
        h.put("Cache-Control", "no-cache");
        return tlsRequest(ip, sni, 443, "GET", path, sni, h, timeoutMs, bind, false, 0).code() == 101;
    }

    private static boolean hasKey(Map<String, String> m, String key) {
        if (m == null) return false;
        for (String k : m.keySet()) if (k.equalsIgnoreCase(key)) return true;
        return false;
    }

    private static void forceTls(SSLSocket s) {
        try {
            List<String> sup = Arrays.asList(s.getSupportedProtocols());
            List<String> want = new ArrayList<>();
            for (String p : new String[]{"TLSv1.3", "TLSv1.2"}) if (sup.contains(p)) want.add(p);
            if (!want.isEmpty()) s.setEnabledProtocols(want.toArray(new String[0]));
        } catch (Exception ignored) {}
    }

    private static String readHeaders(InputStream in, int cap) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
        int b0 = -1, b1 = -1, b2 = -1, x;
        while ((x = in.read()) != -1) {
            bos.write(x);
            if (b0 == '\r' && b1 == '\n' && b2 == '\r' && x == '\n') break;
            b0 = b1; b1 = b2; b2 = x;
            if (bos.size() > cap) break;
        }
        return new String(bos.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private static void parseHead(String head, Res r) {
        if (head == null || head.isEmpty()) return;
        String[] lines = head.split("\r\n");
        r.statusLine = lines.length > 0 ? lines[0].trim() : "";
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c <= 0) continue;
            String k = lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT);
            String v = lines[i].substring(c + 1).trim();
            String old = r.headers.get(k);
            r.headers.put(k, old == null ? v : old + ", " + v);
        }
    }

    private static String readStream(InputStream in, int cap) throws Exception {
        if (in == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n, left = cap;
        while (left > 0 && (n = in.read(buf, 0, Math.min(buf.length, left))) != -1) {
            bos.write(buf, 0, n);
            left -= n;
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String trim(String s) {
        if (s == null) return "";
        return s.length() > 90 ? s.substring(0, 90) : s;
    }

    /* ================================================================== */
    /*                           CLASSIFIER                               */
    /* ================================================================== */

    private static final class Classifier {
        static String kind(Res r) {
            if (r == null) return "other";
            String h = r.raw().toLowerCase(Locale.ROOT);
            String server = r.h("server").toLowerCase(Locale.ROOT);
            String via = r.h("via").toLowerCase(Locale.ROOT);
            String xcache = r.h("x-cache").toLowerCase(Locale.ROOT);

            if (h.contains("cf-ray") || h.contains("cf-cache-status") || h.contains("cf-request-id")
                    || h.contains("cf-apo-via") || h.contains("cf-worker") || server.contains("cloudflare"))
                return "cloudflare";
            if (h.contains("x-amz-cf-id") || h.contains("x-amz-cf-pop") || via.contains("cloudfront")
                    || xcache.contains("cloudfront") || server.contains("cloudfront"))
                return "cloudfront";
            if (h.contains("x-fastly-request-id") || h.contains("fastly-") || xcache.contains("fastly")
                    || via.contains("fastly") || (h.contains("x-served-by") && h.contains("cache-")))
                return "fastly";
            if (h.contains("akamai-grn") || h.contains("x-akamai") || server.contains("akamaighost"))
                return "akamai";
            return "other";
        }

        static String serverLabel(Res r) {
            String s = r.h("server");
            if (s.isEmpty()) return "unknown";
            return s.length() > 40 ? s.substring(0, 40) : s;
        }

        static String pop(Res r) {
            String p = r.h("cf-ray");
            if (!p.isEmpty() && p.contains("-")) return p.substring(p.indexOf('-') + 1);
            p = r.h("x-amz-cf-pop");
            if (!p.isEmpty()) return p;
            return r.h("x-served-by");
        }
    }

    /* ================================================================== */
    /*                            OPEN PROXY                              */
    /* ================================================================== */

    private static final class Proxy {
        static boolean connectTunnel(String ip, int port, int timeoutMs, Network bind) {
            String st = talk(ip, port, timeoutMs, bind,
                    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                  + "User-Agent: BugHunter/1.0\r\nProxy-Connection: keep-alive\r\n\r\n");
            return st != null && st.contains(" 200");
        }

        static boolean forward(String ip, int port, int timeoutMs, Network bind) {
            String st = talk(ip, port, timeoutMs, bind,
                    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                  + "User-Agent: BugHunter/1.0\r\nAccept: */*\r\n"
                  + "Proxy-Connection: keep-alive\r\nConnection: close\r\n\r\n");
            return st != null && (st.contains(" 200") || st.contains(" 301") || st.contains(" 302"));
        }

        private static String talk(String ip, int port, int timeoutMs, Network bind, String req) {
            Socket s = null;
            try {
                s = new Socket();
                if (bind != null) { try { bind.bindSocket(s); } catch (Throwable ignored) {} }
                s.setTcpNoDelay(true);
                s.connect(new InetSocketAddress(InetAddress.getByName(ip), port), timeoutMs);
                s.setSoTimeout(timeoutMs);
                OutputStream out = s.getOutputStream();
                out.write(req.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                InputStream in = s.getInputStream();
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int b;
                while ((b = in.read()) != -1 && bos.size() < 512) {
                    bos.write(b);
                    if (b == '\n') break;
                }
                String line = new String(bos.toByteArray(), StandardCharsets.ISO_8859_1).trim();
                return line.startsWith("HTTP/") ? line : null;
            } catch (Exception e) {
                return null;
            } finally {
                try { if (s != null) s.close(); } catch (Exception ignored) {}
            }
        }
    }

    /* ================================================================== */
    /*                   MULTI-STRATEGY DNS RESOLVER                      */
    /* ================================================================== */

    private static final class Dns {

        static Context ctx;

        private static final String[] PUBLIC = { "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222" };
        private static final Map<String, List<String>> CACHE = new ConcurrentHashMap<>();
        private static volatile boolean systemDead = false;
        private static volatile int systemFails = 0;

        static void resetSystem() { systemDead = false; systemFails = 0; }

        static List<String> resolve(String host, Network net, int timeoutMs) {
            if (host == null || host.isEmpty()) return Collections.emptyList();
            if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return Collections.singletonList(host);

            List<String> cached = CACHE.get(host);
            if (cached != null) return cached;

            List<String> out = new ArrayList<>();

            if (!systemDead) {
                try {
                    for (InetAddress a : InetAddress.getAllByName(host)) out.add(a.getHostAddress());
                    systemFails = 0;
                } catch (Exception e) {
                    systemFails++;
                    if (systemFails >= 3) systemDead = true;
                }
            }

            if (out.isEmpty()) {
                for (String srv : servers(net)) {
                    out.addAll(udp(host, srv, net, timeoutMs, 1));
                    out.addAll(udp(host, srv, net, timeoutMs, 28));
                    if (!out.isEmpty()) break;
                }
            }
            if (out.isEmpty()) {
                for (String srv : servers(net)) {
                    out.addAll(tcp(host, srv, net, timeoutMs, 1));
                    if (!out.isEmpty()) break;
                }
            }
            if (out.isEmpty()) out.addAll(doh(host, net, timeoutMs));

            if (!out.isEmpty()) {
                if (CACHE.size() > 5000) CACHE.clear();
                CACHE.put(host, out);
            }
            return out;
        }

        static void diagnose(Network net, HuntListener l) {
            if (l == null) return;
            l.onMessage("[dns] servers: " + servers(net));
            List<String> viaSystem = new ArrayList<>();
            try {
                for (InetAddress a : InetAddress.getAllByName("cloudflare.com")) {
                    viaSystem.add(a.getHostAddress());
                }
            } catch (Exception e) { viaSystem.clear(); }
            l.onMessage("[dns] system resolver: "
                    + (viaSystem.isEmpty() ? "DEAD" : "ok " + viaSystem.get(0)));

            String gw = Net.gateway(ctx, net);
            if (gw != null) {
                l.onMessage("[dns] gateway " + gw + " udp: "
                        + (udp("cloudflare.com", gw, net, 2000, 1).isEmpty() ? "no answer" : "ok"));
            }
            for (String s : new String[]{"1.1.1.1", "8.8.8.8"}) {
                l.onMessage("[dns] " + s + " udp: "
                        + (udp("cloudflare.com", s, net, 2000, 1).isEmpty() ? "no answer" : "ok"));
            }
            l.onMessage("[dns] doh: "
                    + (doh("cloudflare.com", net, 3000).isEmpty() ? "no answer" : "ok"));
        }

        static List<String> servers(Network net) {
            LinkedHashSet<String> set = new LinkedHashSet<>();
            try {
                if (ctx != null && net != null) {
                    ConnectivityManager cm =
                            (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                    if (cm != null) {
                        LinkProperties lp = cm.getLinkProperties(net);
                        if (lp != null) {
                            for (InetAddress a : lp.getDnsServers()) set.add(a.getHostAddress());
                            for (RouteInfo r : lp.getRoutes()) {
                                if (r.isDefaultRoute() && r.getGateway() != null) {
                                    set.add(r.getGateway().getHostAddress());
                                }
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {}
            for (String s : PUBLIC) set.add(s);
            return new ArrayList<>(set);
        }

        private static List<String> udp(String host, String server, Network net, int timeoutMs, int type) {
            List<String> out = new ArrayList<>();
            DatagramSocket sock = null;
            try {
                sock = new DatagramSocket();
                if (net != null) { try { net.bindSocket(sock); } catch (Throwable ignored) {} }
                sock.setSoTimeout(timeoutMs);
                int id = (int) (Math.random() * 0xffff);
                byte[] q = buildQuery(host, type, id);
                InetAddress srv = InetAddress.getByName(server);
                sock.send(new DatagramPacket(q, q.length, srv, 53));
                byte[] buf = new byte[1500];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                sock.receive(resp);
                out.addAll(parseAnswer(buf, resp.getLength(), id));
            } catch (Exception ignored) {
            } finally {
                if (sock != null) sock.close();
            }
            return out;
        }

        private static List<String> tcp(String host, String server, Network net, int timeoutMs, int type) {
            Socket s = null;
            try {
                s = new Socket();
                if (net != null) { try { net.bindSocket(s); } catch (Throwable ignored) {} }
                s.connect(new InetSocketAddress(InetAddress.getByName(server), 53), timeoutMs);
                s.setSoTimeout(timeoutMs);
                int id = (int) (Math.random() * 0xffff);
                byte[] q = buildQuery(host, type, id);
                DataOutputStream out = new DataOutputStream(s.getOutputStream());
                out.writeShort(q.length);
                out.write(q);
                out.flush();
                DataInputStream in = new DataInputStream(s.getInputStream());
                int len = in.readUnsignedShort();
                byte[] buf = new byte[Math.min(len, 4096)];
                in.readFully(buf, 0, buf.length);
                return parseAnswer(buf, buf.length, id);
            } catch (Exception e) {
                return new ArrayList<>();
            } finally {
                try { if (s != null) s.close(); } catch (Exception ignored) {}
            }
        }

        private static byte[] buildQuery(String host, int type, int id) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            b.write((id >> 8) & 0xff);
            b.write(id & 0xff);
            b.write(0x01); b.write(0x00);
            b.write(0); b.write(1);
            b.write(0); b.write(0); b.write(0); b.write(0);
            b.write(0); b.write(0); b.write(0); b.write(0);
            for (String label : host.split("\\.")) {
                byte[] lb = label.getBytes(StandardCharsets.US_ASCII);
                if (lb.length == 0 || lb.length > 63) continue;
                b.write(lb.length);
                b.write(lb, 0, lb.length);
            }
            b.write(0);
            b.write((type >> 8) & 0xff); b.write(type & 0xff);
            b.write(0); b.write(1);
            return b.toByteArray();
        }

        private static List<String> parseAnswer(byte[] b, int len, int id) {
            List<String> out = new ArrayList<>();
            if (len < 12) return out;
            if ((((b[0] & 0xff) << 8) | (b[1] & 0xff)) != id) return out;
            if ((b[3] & 0x0f) != 0) return out;

            int qd = ((b[4] & 0xff) << 8) | (b[5] & 0xff);
            int an = ((b[6] & 0xff) << 8) | (b[7] & 0xff);
            int off = 12;
            for (int i = 0; i < qd && off < len; i++) off = skipName(b, off, len) + 4;

            for (int i = 0; i < an && off + 10 <= len; i++) {
                off = skipName(b, off, len);
                if (off + 10 > len) break;
                int rtype = ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
                int rdlen = ((b[off + 8] & 0xff) << 8) | (b[off + 9] & 0xff);
                off += 10;
                if (off + rdlen > len) break;
                if (rtype == 1 && rdlen == 4) {
                    out.add((b[off] & 0xff) + "." + (b[off + 1] & 0xff) + "."
                          + (b[off + 2] & 0xff) + "." + (b[off + 3] & 0xff));
                } else if (rtype == 28 && rdlen == 16) {
                    StringBuilder sb = new StringBuilder();
                    for (int k = 0; k < 16; k += 2) {
                        if (k > 0) sb.append(':');
                        sb.append(Integer.toHexString(((b[off + k] & 0xff) << 8) | (b[off + k + 1] & 0xff)));
                    }
                    out.add(sb.toString());
                }
                off += rdlen;
            }
            return out;
        }

        private static int skipName(byte[] b, int off, int len) {
            while (off < len) {
                int l = b[off] & 0xff;
                if (l == 0) return off + 1;
                if ((l & 0xc0) == 0xc0) return off + 2;
                off += 1 + l;
            }
            return off;
        }

        private static List<String> doh(String host, Network net, int timeoutMs) {
            List<String> out = new ArrayList<>();
            String[] pairs = { "1.1.1.1|cloudflare-dns.com", "8.8.8.8|dns.google", "9.9.9.9|dns.quad9.net" };
            for (String pair : pairs) {
                String ip = pair.substring(0, pair.indexOf('|'));
                String h = pair.substring(pair.indexOf('|') + 1);
                for (int type : new int[]{1, 28}) {
                    Map<String, String> hdrs = new LinkedHashMap<>();
                    hdrs.put("Accept", "application/dns-json");
                    Res r = tlsRequest(ip, h, 443, "GET",
                            "/dns-query?name=" + host + "&type=" + (type == 1 ? "A" : "AAAA"),
                            h, hdrs, timeoutMs, net, true, 8192);
                    if (!r.tlsOk || r.body.isEmpty()) continue;
                    try {
                        JSONArray arr = new JSONObject(r.body).optJSONArray("Answer");
                        if (arr == null) continue;
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject a = arr.getJSONObject(i);
                            if (a.optInt("type") == type) {
                                String d = a.optString("data");
                                if (!d.isEmpty() && !out.contains(d)) out.add(d);
                            }
                        }
                    } catch (Exception ignored) {}
                    if (!out.isEmpty()) return out;
                }
            }
            return out;
        }
    }

    /* ================================================================== */
    /*                              NETWORK                               */
    /* ================================================================== */

    private static final class Net {

        static void bindProcess(Context ctx, Network net) {
            try {
                ConnectivityManager cm =
                        (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) cm.bindProcessToNetwork(net);
            } catch (Throwable ignored) {}
        }

        static Network underlying(Context ctx) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return null;
            try {
                for (Network n : cm.getAllNetworks()) {
                    NetworkCapabilities c = cm.getNetworkCapabilities(n);
                    if (c == null) continue;
                    if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                    if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            || c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                            || c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return n;
                }
            } catch (Exception ignored) {}
            return cm.getActiveNetwork();
        }

        static String gateway(Context ctx, Network net) {
            try {
                ConnectivityManager cm =
                        (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm == null || net == null) return null;
                LinkProperties lp = cm.getLinkProperties(net);
                if (lp == null) return null;
                for (RouteInfo r : lp.getRoutes()) {
                    if (r.isDefaultRoute() && r.getGateway() != null) {
                        return r.getGateway().getHostAddress();
                    }
                }
                for (InetAddress a : lp.getDnsServers()) return a.getHostAddress();
            } catch (Throwable ignored) {}
            return null;
        }

        static List<Network> usable(Context ctx, boolean preferNonVpn) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            List<Network> t1 = new ArrayList<>(), t2 = new ArrayList<>(), t3 = new ArrayList<>();
            if (cm == null) return t3;
            try {
                for (Network n : cm.getAllNetworks()) {
                    NetworkCapabilities c = cm.getNetworkCapabilities(n);
                    if (c == null) continue;
                    if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                    boolean validated = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                    boolean vpn = c.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                    if (validated && (!preferNonVpn || !vpn)) t1.add(n);
                    else if (validated) t2.add(n);
                    else t3.add(n);
                }
            } catch (Exception ignored) {}
            List<Network> all = new ArrayList<>();
            all.addAll(t1); all.addAll(t2); all.addAll(t3);
            return all;
        }

        static Network await(Context ctx, long timeoutMs, boolean preferNonVpn, HuntListener l) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return null;

            Network quick = first(usable(ctx, preferNonVpn));
            if (quick != null) return quick;

            if (l != null) l.onMessage("[net] waiting for Wi-Fi / VPN / portal login...");
            final Network[] best = new Network[1];
            ConnectivityManager.NetworkCallback cb = null;
            try {
                cb = new ConnectivityManager.NetworkCallback() {
                    @Override public void onCapabilitiesChanged(Network n, NetworkCapabilities c) {
                        if (c != null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                            synchronized (best) { if (best[0] == null) best[0] = n; }
                        }
                    }
                    @Override public void onLost(Network n) {
                        synchronized (best) { if (n.equals(best[0])) best[0] = null; }
                    }
                };
                cm.registerNetworkCallback(new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), cb);
            } catch (Exception ignored) {}

            try {
                long deadline = System.currentTimeMillis() + timeoutMs;
                while (System.currentTimeMillis() < deadline && !Thread.currentThread().isInterrupted()) {
                    synchronized (best) { if (best[0] != null) return best[0]; }
                    Network n = first(usable(ctx, preferNonVpn));
                    if (n != null) return n;
                    Thread.sleep(1000);
                }
            } catch (InterruptedException ignored) {
            } finally {
                if (cb != null) { try { cm.unregisterNetworkCallback(cb); } catch (Exception ignored) {} }
            }
            return first(usable(ctx, false));
        }

        static String describe(Context ctx, Network n) {
            try {
                ConnectivityManager cm =
                        (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                NetworkCapabilities c = cm == null ? null : cm.getNetworkCapabilities(n);
                if (c == null) return "unknown";
                StringBuilder sb = new StringBuilder();
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) sb.append("wifi");
                else if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) sb.append("cell");
                else if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) sb.append("vpn");
                else if (c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) sb.append("eth");
                else sb.append("net");
                sb.append(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                        ? "/validated" : "/unvalidated");
                return sb.toString();
            } catch (Throwable t) { return "unknown"; }
        }

        private static Network first(List<Network> l) { return l.isEmpty() ? null : l.get(0); }
    }

    /* ================================================================== */
    /*                              UPLOAD                                */
    /* ================================================================== */

    private static final class Up {

        static final class Result {
            boolean ok;
            int code;
            String body = "";
            String error = "";
            String via = "";
        }

        static Result upload(Context ctx, File zip, Map<String, String> fields, String endpoint,
                             String token, long waitMs, List<FoundHost> pins, HuntListener l) {
            Result last = new Result();
            if (zip == null || !zip.isFile()) { last.error = "no archive"; return last; }

            for (int attempt = 1; attempt <= 3; attempt++) {
                Network net = Net.await(ctx, attempt == 1 ? waitMs : 30000, attempt == 1, l);
                if (net == null) {
                    last.error = "no network";
                    if (l != null) l.onMessage("[up] no network yet");
                    continue;
                }
                Net.bindProcess(ctx, net);
                try {
                    String host = Uri.parse(endpoint).getHost();
                    for (String ip : Dns.resolve(host, net, 4000)) {
                        Result r = pinned(ip, zip, fields, endpoint, token);
                        if (r.ok) { r.via = "pinned:" + ip; return r; }
                        last = r;
                        if (l != null) l.onMessage("[up] pinned " + ip + " -> " + r.error);
                    }
                    List<Network> nets = new ArrayList<>();
                    nets.add(net);
                    for (Network n : Net.usable(ctx, attempt == 1)) if (!n.equals(net)) nets.add(n);
                    for (Network n : nets) {
                        Result r = multipart(n, zip, fields, endpoint, token);
                        r.via = "network";
                        if (r.ok) return r;
                        last = r;
                        if (l != null) l.onMessage("[up] failed on " + n + " -> " + r.error);
                    }
                } finally {
                    Net.bindProcess(ctx, null);
                }
            }

            if (pins != null && !pins.isEmpty()) {
                if (l != null) l.onMessage("[up] trying discovered edges...");
                for (FoundHost h : pins) {
                    Result r = pinned(h.ip, zip, fields, endpoint, token);
                    if (r.ok) { r.via = "edge:" + h.ip; return r; }
                    last = r;
                }
            }
            return last;
        }

        private static Result multipart(Network net, File zip, Map<String, String> fields,
                                        String endpoint, String token) {
            Result res = new Result();
            HttpURLConnection c = null;
            String boundary = "----BH" + UUID.randomUUID().toString().replace("-", "");
            try {
                URL url = new URL(endpoint);
                c = (HttpURLConnection) net.openConnection(url);
                c.setRequestMethod("POST");
                c.setDoOutput(true);
                c.setConnectTimeout(15000);
                c.setReadTimeout(180000);
                c.setUseCaches(false);
                c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                c.setRequestProperty("Accept", "application/json");
                c.setRequestProperty("User-Agent", "BugHunter/1.0 (Android)");
                if (token != null && !token.isEmpty()) c.setRequestProperty("X-Scanner-Token", token);
                if (c instanceof HttpsURLConnection) {
                    HttpsURLConnection h = (HttpsURLConnection) c;
                    h.setSSLSocketFactory(Tls.factory());
                    h.setHostnameVerifier((hn, ssl) -> true);
                }

                ByteArrayOutputStream head = new ByteArrayOutputStream();
                writeFields(head, fields, boundary, token);
                c.setFixedLengthStreamingMode(head.size() + filePartLength(zip, boundary));

                OutputStream os = new BufferedOutputStream(c.getOutputStream());
                os.write(head.toByteArray());
                writeFilePart(os, zip, boundary);
                os.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
                os.flush();
                os.close();

                res.code = c.getResponseCode();
                InputStream in = res.code < 400 ? c.getInputStream() : c.getErrorStream();
                res.body = readStream(in, 65536);
                res.ok = res.code >= 200 && res.code < 300 && res.body.contains("\"ok\":true");
                if (!res.ok) res.error = "http " + res.code;
                return res;
            } catch (Exception e) {
                res.error = e.getClass().getSimpleName() + ": " + e.getMessage();
                return res;
            } finally {
                if (c != null) c.disconnect();
            }
        }

        private static Result pinned(String ip, File zip, Map<String, String> fields,
                                     String endpoint, String token) {
            Result res = new Result();
            Socket raw = null;
            SSLSocket s = null;
            try {
                Uri u = Uri.parse(endpoint);
                String host = u.getHost();
                boolean tls = !"http".equalsIgnoreCase(u.getScheme());
                int port = u.getPort() > 0 ? u.getPort() : (tls ? 443 : 80);
                String path = (u.getPath() == null || u.getPath().isEmpty()) ? "/" : u.getPath();

                String boundary = "----BHP" + UUID.randomUUID().toString().replace("-", "");
                ByteArrayOutputStream body = new ByteArrayOutputStream();
                writeFields(body, fields, boundary, token);
                writeFilePart(body, zip, boundary);
                body.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
                byte[] payload = body.toByteArray();

                raw = new Socket();
                raw.setTcpNoDelay(true);
                raw.connect(new InetSocketAddress(ip, port), 15000);
                raw.setSoTimeout(180000);

                OutputStream out;
                if (tls) {
                    s = (SSLSocket) Tls.factory().createSocket(raw, host, port, true);
                    forceTls(s);
                    s.setSoTimeout(180000);
                    s.startHandshake();
                    out = s.getOutputStream();
                } else {
                    out = raw.getOutputStream();
                }

                StringBuilder req = new StringBuilder();
                req.append("POST ").append(path).append(" HTTP/1.1\r\n");
                req.append("Host: ").append(host).append("\r\n");
                req.append("User-Agent: BugHunter/1.0 (Android)\r\n");
                req.append("Accept: application/json\r\n");
                req.append("Content-Type: multipart/form-data; boundary=").append(boundary).append("\r\n");
                req.append("Content-Length: ").append(payload.length).append("\r\n");
                if (token != null && !token.isEmpty()) req.append("X-Scanner-Token: ").append(token).append("\r\n");
                req.append("Connection: close\r\n\r\n");

                out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
                out.write(payload);
                out.flush();

                InputStream in = tls ? s.getInputStream() : raw.getInputStream();
                String all = readStream(in, 131072);
                int sp = all.indexOf(' ');
                if (sp > 0) {
                    try { res.code = Integer.parseInt(all.substring(sp + 1, sp + 4).trim()); }
                    catch (Exception ignored) {}
                }
                res.body = all;
                res.ok = res.code >= 200 && res.code < 300 && all.contains("\"ok\":true");
                if (!res.ok) res.error = "pinned http " + res.code;
                return res;
            } catch (Exception e) {
                res.error = e.getClass().getSimpleName() + ": " + e.getMessage();
                return res;
            } finally {
                try { if (s != null) s.close(); else if (raw != null) raw.close(); } catch (Exception ignored) {}
            }
        }

        private static void writeFields(OutputStream os, Map<String, String> fields,
                                        String boundary, String token) throws Exception {
            Map<String, String> f = new LinkedHashMap<>();
            if (fields != null) f.putAll(fields);
            if (token != null && !token.isEmpty()) f.put("token", token);
            for (Map.Entry<String, String> e : f.entrySet()) {
                os.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
                os.write(("Content-Disposition: form-data; name=\"" + e.getKey() + "\"\r\n\r\n")
                        .getBytes(StandardCharsets.UTF_8));
                os.write((e.getValue() == null ? "" : e.getValue()).getBytes(StandardCharsets.UTF_8));
                os.write("\r\n".getBytes(StandardCharsets.UTF_8));
            }
        }

        private static long filePartLength(File f, String boundary) {
            String h = "--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"file\"; filename=\"" + f.getName() + "\"\r\n"
                    + "Content-Type: application/zip\r\n\r\n";
            return h.getBytes(StandardCharsets.UTF_8).length + f.length() + 2;
        }

        private static void writeFilePart(OutputStream os, File f, String boundary) throws Exception {
            os.write(("--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"file\"; filename=\"" + f.getName() + "\"\r\n"
                    + "Content-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            InputStream in = new FileInputStream(f);
            byte[] buf = new byte[32768];
            int n;
            while ((n = in.read(buf)) != -1) os.write(buf, 0, n);
            in.close();
            os.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }
    }

    /* ================================================================== */
    /*                            APP MEMORY                              */
    /* ================================================================== */

    public static final class Store {

        private static SharedPreferences p(Context c) {
            return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        }

        static synchronized void merge(Context c, List<FoundHost> hosts) {
            Map<String, FoundHost> map = new LinkedHashMap<>();
            for (FoundHost h : read(c, KEY_HOSTS)) map.put(h.ip + "|" + h.host, h);
            for (FoundHost h : hosts) {
                String k = h.ip + "|" + h.host;
                if (!map.containsKey(k) || h.isUseful()) map.put(k, h);
            }
            write(c, KEY_HOSTS, new ArrayList<>(map.values()));
        }

        static synchronized void storeProxies(Context c, List<FoundHost> hosts) {
            Map<String, FoundHost> map = new LinkedHashMap<>();
            for (FoundHost h : read(c, KEY_PROXIES)) map.put(h.ip + ":" + h.host, h);
            for (FoundHost h : hosts) {
                if (h.connectProxy || h.forwardProxy) map.put(h.ip + ":" + h.host, h);
            }
            write(c, KEY_PROXIES, new ArrayList<>(map.values()));
        }

        public static synchronized List<FoundHost> hosts(Context c) { return read(c, KEY_HOSTS); }

        public static synchronized List<FoundHost> proxies(Context c) { return read(c, KEY_PROXIES); }

        public static synchronized void clear(Context c) {
            p(c).edit().remove(KEY_HOSTS).remove(KEY_PROXIES).apply();
        }

        private static List<FoundHost> read(Context c, String key) {
            List<FoundHost> out = new ArrayList<>();
            try {
                JSONArray arr = new JSONArray(p(c).getString(key, "[]"));
                for (int i = 0; i < arr.length(); i++) out.add(FoundHost.fromJson(arr.getJSONObject(i)));
            } catch (Exception ignored) {}
            return out;
        }

        private static void write(Context c, String key, List<FoundHost> hosts) {
            JSONArray arr = new JSONArray();
            for (FoundHost h : hosts) arr.put(h.toJson());
            p(c).edit().putString(key, arr.toString()).apply();
        }
    }

    /* ================================================================== */
    /*                              REGEX                                 */
    /* ================================================================== */

    private static final class Regex {

        private static final String TLD =
            "co\\.ke|or\\.ke|ne\\.ke|ac\\.ke|sc\\.ke|go\\.ke|me\\.ke|co\\.uk|org\\.uk|me\\.uk|ac\\.uk|gov\\.uk|"
          + "co\\.za|org\\.za|com\\.au|net\\.au|org\\.au|com\\.br|com\\.ng|com\\.gh|com\\.eg|co\\.tz|co\\.ug|co\\.in|co\\.id|"
          + "com|net|org|io|me|be|tech|dev|app|xyz|info|biz|site|online|store|shop|cloud|live|link|pro|top|website|"
          + "space|fun|club|one|page|blog|wiki|zone|plus|team|host|press|world|today|digital|agency|media|email|"
          + "co|us|uk|ke|tz|ug|ng|gh|za|in|id|ru|de|fr|nl|pl|it|es|se|no|dk|fi|ch|at|cz|gr|pt|ro|hu|ie|is|lt|lv|ee|"
          + "jp|cn|kr|sg|my|ph|vn|th|tr|ae|sa|il|eg|ma|ca|mx|ar|cl|br|pe|au|nz";

        private static final Pattern DOMAIN = Pattern.compile(
            "(?i)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+" + TLD + ")(?![a-z0-9-])");

        private static final Pattern EXCLUDE = Pattern.compile(
            "\\.(jpg|jpeg|png|gif|ico|svg|css|js|mp4|woff|woff2|ttf)$",
            Pattern.CASE_INSENSITIVE);

        private static final Pattern ASSET = Pattern.compile(
            "(?i)(?:src|href|data-src|action|poster|content)\\s*=\\s*[\"']([^\"'\\s]+)[\"']");

        private static final Pattern INLINE = Pattern.compile(
            "(?is)<script[^>]*>(.*?)</script>|<style[^>]*>(.*?)</style>");

        static Set<String> extract(CharSequence text) {
            Set<String> out = new LinkedHashSet<>();
            if (text == null || text.length() == 0) return out;
            Matcher m = DOMAIN.matcher(text);
            while (m.find()) {
                String d = m.group(1).toLowerCase(Locale.ROOT);
                if (d.length() > 253) continue;
                if (EXCLUDE.matcher(d).find()) continue;
                out.add(d);
            }
            return out;
        }

        static Set<String> assetUrls(CharSequence html) {
            Set<String> out = new LinkedHashSet<>();
            if (html == null) return out;
            Matcher m = ASSET.matcher(html);
            while (m.find()) {
                String u = m.group(1).trim();
                if (u.isEmpty() || u.startsWith("data:") || u.startsWith("#")
                        || u.startsWith("javascript:")) continue;
                if (u.length() > 400) continue;
                out.add(u);
            }
            return out;
        }

        static String inlineBlocks(CharSequence html) {
            if (html == null) return "";
            StringBuilder sb = new StringBuilder();
            Matcher m = INLINE.matcher(html);
            while (m.find()) {
                if (m.group(1) != null) sb.append(m.group(1)).append('\n');
                if (m.group(2) != null) sb.append(m.group(2)).append('\n');
            }
            return sb.toString();
        }
    }

    /* ================================================================== */
    /*                          ZIP + REPORT                              */
    /* ================================================================== */

    private static void writeFiles(File dir, Map<String, String> files) {
        for (Map.Entry<String, String> e : files.entrySet()) {
            FileOutputStream fos = null;
            try {
                fos = new FileOutputStream(new File(dir, e.getKey()));
                fos.write(e.getValue().getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {
            } finally {
                try { if (fos != null) fos.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void writeReport(File dir, Report rep, Config cfg) throws Exception {
        List<FoundHost> sorted = new ArrayList<>(rep.hosts);
        Collections.sort(sorted, (a, b) -> Boolean.compare(b.isUseful(), a.isUseful()));

        StringBuilder txt = new StringBuilder();
        txt.append("BugHunter scan report\n");
        txt.append("scan id  : ").append(rep.id).append('\n');
        txt.append("device   : ").append(cfg.device).append('\n');
        txt.append("portal   : ").append(rep.portal).append('\n');
        txt.append("summary  : ").append(rep.summary()).append("\n\n");
        txt.append("== WORKING HOSTS ==\n");
        for (FoundHost h : sorted) if (h.isUseful()) txt.append(h.line()).append('\n');
        txt.append("\n== OPEN PROXIES ==\n");
        for (FoundHost h : sorted)
            if (h.connectProxy || h.forwardProxy)
                txt.append(h.ip).append("  ").append(h.host)
                   .append(h.connectProxy ? "  connect" : "").append(h.forwardProxy ? "  forward" : "")
                   .append('\n');
        txt.append("\n== ALL PROBED ==\n");
        for (FoundHost h : sorted) txt.append(h.line()).append('\n');
        txt.append("\n== DOMAINS ==\n");
        for (String d : rep.domains) txt.append(d).append('\n');
        writeFile(dir, "report.txt", txt.toString());

        JSONObject json = new JSONObject();
        json.put("scanId", rep.id);
        json.put("device", cfg.device);
        json.put("portal", rep.portal);
        json.put("summary", rep.summary());
        json.put("generatedAt", System.currentTimeMillis());
        JSONArray hosts = new JSONArray();
        for (FoundHost h : rep.hosts) hosts.put(h.toJson());
        json.put("hosts", hosts);
        json.put("domains", new JSONArray(rep.domains));
        writeFile(dir, "report.json", json.toString(2));

        StringBuilder prox = new StringBuilder();
        for (FoundHost h : sorted)
            if (h.connectProxy || h.forwardProxy)
                prox.append(h.ip).append("  ").append(h.host)
                    .append(h.connectProxy ? "  connect" : "").append(h.forwardProxy ? "  forward" : "")
                    .append('\n');
        writeFile(dir, "open_proxies.txt", prox.toString());

        StringBuilder vless = new StringBuilder();
        for (FoundHost h : sorted)
            if (h.cloudflareWs)
                vless.append("vless://<uuid>@").append(h.ip)
                     .append(":443?encryption=none&security=tls&type=ws&host=")
                     .append(h.host).append("&path=%2Fvless&sni=").append(h.host)
                     .append("#").append(h.host).append("\n");
        writeFile(dir, "vless_candidates.txt", vless.toString());
    }

    private static void writeFile(File dir, String name, String content) throws Exception {
        FileOutputStream fos = new FileOutputStream(new File(dir, name));
        try { fos.write(content.getBytes(StandardCharsets.UTF_8)); }
        finally { fos.close(); }
    }

    private static File zipDir(File dir, File out) throws Exception {
        ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out)));
        try { addDir(dir, dir, zos); } finally { zos.close(); }
        return out;
    }

    private static void addDir(File root, File dir, ZipOutputStream zos) throws Exception {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        byte[] buf = new byte[16384];
        for (File f : kids) {
            if (f.isDirectory()) { addDir(root, f, zos); continue; }
            String rel = root.toURI().relativize(f.toURI()).getPath();
            if (rel.isEmpty() || rel.endsWith("/")) continue;
            ZipEntry e = new ZipEntry(rel);
            e.setTime(f.lastModified());
            zos.putNextEntry(e);
            InputStream in = new BufferedInputStream(new FileInputStream(f));
            try {
                int n;
                while ((n = in.read(buf)) != -1) zos.write(buf, 0, n);
            } finally { in.close(); }
            zos.closeEntry();
        }
    }
}

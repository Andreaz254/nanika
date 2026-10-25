package com.example.tunnel.update;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Checks updates.freessh.indevs.in for a newer release and downloads it. All methods are blocking (run them
 * off the UI thread); the caller marshals callbacks back to the UI thread itself.
 *
 * Expected server reply (GET, JSON): {"version":"1.17","file":"nanika-v1.17.apk","sha256":"...","size":123}
 * "url" may be given explicitly instead of "file"; otherwise it is built as CHECK_URL + "downloads/" + file.
 */
public final class UpdateManager {
    private UpdateManager() {}

    public static final String CHECK_URL = "https://updates.freessh.indevs.in/";
    private static final int TIMEOUT_MS = 8000;
    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static final class Info {
        public final String version, file, url, sha256;
        public final long size;
        public Info(String version, String file, String url, String sha256, long size) {
            this.version = version;
            this.file = file;
            this.url = url;
            this.sha256 = sha256;
            this.size = size;
        }
    }

    public interface CheckListener {
        void onUpdateAvailable(Info info);
        /** Also called for any error (offline, timeout, bad reply) - by design this is always silent. */
        void onNoUpdate();
    }

    public interface DownloadListener {
        void onProgress(int percent);
        void onDone(File file);
        void onError(String message);
    }

    public static void check(String currentVersion, CheckListener l) {
        try {
            String body = httpGet(CHECK_URL);
            JSONObject j = new JSONObject(body);
            String version = j.optString("version", "").trim();
            String file = j.optString("file", "").trim();
            String urlPath = j.optString("url", file.isEmpty() ? "" : "downloads/" + file).trim();
            String sha256 = j.optString("sha256", "").trim();
            long size = j.optLong("size", 0);
            if (version.isEmpty() || (file.isEmpty() && urlPath.isEmpty())) {
                l.onNoUpdate();
                return;
            }
            if (compare(version, currentVersion) <= 0) {
                l.onNoUpdate();
                return;
            }
            String full = urlPath.toLowerCase(Locale.US).startsWith("http")
                    ? urlPath : CHECK_URL.replaceAll("/+$", "") + "/" + urlPath.replaceAll("^/+", "");
            if (!full.toLowerCase(Locale.US).startsWith("https://")) {
                l.onNoUpdate();                      // refuse a non-HTTPS download URL - treat like no update
                return;
            }
            l.onUpdateAvailable(new Info(version, file, full, sha256, size));
        } catch (Exception e) {
            l.onNoUpdate();                          // offline, timeout, bad JSON, ... -> ignore silently
        }
    }

    /** Positive if {@code a} is newer than {@code b}, comparing dot-separated numeric parts ("1.9" < "1.17"). */
    public static int compare(String a, String b) {
        String[] pa = (a == null ? "" : a).split("\\.");
        String[] pb = (b == null ? "" : b).split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int x = part(pa, i), y = part(pb, i);
            if (x != y) return x - y;
        }
        return 0;
    }

    private static int part(String[] p, int i) {
        if (i >= p.length) return 0;
        try {
            return Integer.parseInt(p[i].replaceAll("[^0-9]", ""));
        } catch (Exception e) {
            return 0;
        }
    }

    private static String httpGet(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(TIMEOUT_MS);
        c.setReadTimeout(TIMEOUT_MS);
        c.setRequestProperty("Accept", "application/json");
        try {
            int code = c.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            return new String(readAll(c.getInputStream(), 1 << 16).toByteArray(), "UTF-8");
        } finally {
            c.disconnect();
        }
    }

    /** Downloads to {@code dest} (via a .part temp file), verifying sha256 if the server gave one. */
    public static void download(Info info, File dest, DownloadListener l) {
        if (!info.url.toLowerCase(Locale.US).startsWith("https://")) {
            l.onError("refusing an insecure (non-HTTPS) download URL");
            return;
        }
        HttpURLConnection c = null;
        File tmp = new File(dest.getParentFile(), dest.getName() + ".part");
        try {
            c = (HttpURLConnection) new URL(info.url).openConnection();
            c.setConnectTimeout(TIMEOUT_MS);
            c.setReadTimeout(20000);
            int code = c.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            long total = c.getContentLengthLong();
            if (total <= 0) total = info.size;
            MessageDigest md = info.sha256.isEmpty() ? null : MessageDigest.getInstance("SHA-256");
            File parent = dest.getParentFile();
            if (parent != null) parent.mkdirs();
            try (InputStream in = c.getInputStream(); OutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[1 << 16];
                long done = 0;
                int n, lastPct = -1;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    if (md != null) md.update(buf, 0, n);
                    done += n;
                    if (total > 0) {
                        int pct = (int) Math.min(100, done * 100 / total);
                        if (pct != lastPct) {
                            lastPct = pct;
                            l.onProgress(pct);
                        }
                    }
                }
            }
            if (md != null) {
                String got = hex(md.digest());
                if (!got.equalsIgnoreCase(info.sha256)) {
                    tmp.delete();
                    l.onError("the downloaded file's hash does not match - try again");
                    return;
                }
            }
            if (dest.exists()) dest.delete();
            if (!tmp.renameTo(dest)) {
                l.onError("could not save the downloaded file");
                return;
            }
            l.onDone(dest);
        } catch (Exception e) {
            tmp.delete();
            l.onError(e.getMessage() != null ? e.getMessage() : e.toString());
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static ByteArrayOutputStream readAll(InputStream in, int cap) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
            if (bo.size() > cap) throw new IOException("response too large");
        }
        return bo;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}

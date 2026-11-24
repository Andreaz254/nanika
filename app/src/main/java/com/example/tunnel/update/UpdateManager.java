package com.example.tunnel.update;

import org.json.JSONArray;
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
 * Checks the latest GitHub Release of a PUBLIC repository for a newer APK and downloads it. All methods are
 * blocking (run them off the UI thread); the caller marshals callbacks back to the UI thread itself.
 *
 * Release rules: the tag is the version ("v1.7" or "1.7"), and the release has one asset whose name ends in
 * ".apk". Drafts and pre-releases are ignored by GitHub's "latest" endpoint.
 */
public final class UpdateManager {
    private UpdateManager() {}

    /** EDIT THESE TWO: the GitHub account and the (public) repository that holds your releases. */
    public static final String GITHUB_OWNER = "YOUR_GITHUB_USERNAME";
    public static final String GITHUB_REPO = "nanika-releases";

    public static final String CHECK_URL =
            "https://api.github.com/repos/" + Andreaz254 + "/" + nanika + "/releases/latest";
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
            JSONObject j = new JSONObject(httpGet(CHECK_URL));
            if (j.optBoolean("draft", false) || j.optBoolean("prerelease", false)) {
                l.onNoUpdate();
                return;
            }
            String version = j.optString("tag_name", "").trim().replaceFirst("^[vV]", "");
            JSONArray assets = j.optJSONArray("assets");
            if (version.isEmpty() || assets == null) {
                l.onNoUpdate();
                return;
            }
            if (compare(version, currentVersion) <= 0) {
                l.onNoUpdate();
                return;
            }
            JSONObject apk = null;
            for (int i = 0; i < assets.length(); i++) {
                JSONObject a = assets.optJSONObject(i);
                if (a != null && a.optString("name", "").toLowerCase(Locale.US).endsWith(".apk")) {
                    apk = a;
                    break;
                }
            }
            if (apk == null) {
                l.onNoUpdate();
                return;
            }
            String file = new File(apk.optString("name", "nanika-v" + version + ".apk")).getName();
            String url = apk.optString("browser_download_url", "").trim();
            long size = apk.optLong("size", 0);
            // GitHub reports "sha256:<hex>" for each asset; verified after the download when present.
            String digest = apk.optString("digest", "").trim();
            String sha256 = digest.toLowerCase(Locale.US).startsWith("sha256:") ? digest.substring(7) : "";
            if (!url.toLowerCase(Locale.US).startsWith("https://")) {
                l.onNoUpdate();                      // refuse a non-HTTPS download URL - treat like no update
                return;
            }
            l.onUpdateAvailable(new Info(version, file, url, sha256, size));
        } catch (Exception e) {
            l.onNoUpdate();                          // offline, rate-limited, bad JSON, ... -> ignore silently
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
        c.setRequestProperty("Accept", "application/vnd.github+json");
        c.setRequestProperty("User-Agent", "Nanika-Updater");
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
            c.setRequestProperty("User-Agent", "Nanika-Updater");
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

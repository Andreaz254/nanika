package com.example.tunnel.config;

import android.content.SharedPreferences;
import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Import / export of one protocol configuration (SSH, VLESS or VMess):
 *   .anika file  - encrypted, every protocol
 *   JSON         - plain, VLESS and VMess (the same JSON the .anika file holds)
 *   vless:// and vmess:// links - clipboard
 * Only the known setting names are ever read or written, so a file can never touch other app settings.
 */
public final class ConfigIO {
    private ConfigIO() {}

    public static final String DEFAULT_SSH_HOST = "naruto.freessh.indevs.in";
    public static final String APP_ID = "nanika";

    private static final String[] SSH_KEYS = {"sshHost", "user", "pass", "proxyHost", "proxyPort", "sni",
            "payload", "transport", "wsFrames", "expiry", "message", "hideServer", "hideHost", "lockAll"};
    private static final String[] WS_KEYS = {"uuid", "server", "connectIp", "port", "sni", "path",
            "transport", "insecure", "expiry", "message", "hideServer", "hideHost", "lockAll"};
    private static final Set<String> BOOL_KEYS = new HashSet<String>(Arrays.asList("wsFrames", "insecure", "hideServer", "hideHost", "lockAll"));
    private static final Pattern DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_VALUE = 8000;

    public static String[] keys(String proto) {
        return "SSH".equalsIgnoreCase(proto) ? SSH_KEYS : WS_KEYS;
    }

    private static String canon(String proto) {
        if ("SSH".equalsIgnoreCase(proto)) return "SSH";
        if ("VLESS".equalsIgnoreCase(proto)) return "VLESS";
        return "VMess";
    }

    // ------------------------------------------------------------------ protection set by the creator

    /** A protection flag of an imported configuration: hideServer, hideHost or lockAll. */
    public static boolean flag(SharedPreferences prefs, String proto, String name) {
        return prefs.getBoolean(canon(proto) + "_" + name, false);
    }

    /** True if the creator protected this configuration in any way (it then cannot be exported again). */
    public static boolean anyLock(SharedPreferences prefs, String proto) {
        return flag(prefs, proto, "hideServer") || flag(prefs, proto, "hideHost") || flag(prefs, proto, "lockAll");
    }

    /**
     * Whether a settings field must not be shown.
     *  Hide server : SSH "Server Address" / VLESS-VMess "Server / Host Header"
     *  Hide host   : proxy host, SNI and the payload (SSH) / connect host and SNI (VLESS, VMess)
     *  (Lock all hides the whole page, so it is handled by the page itself.)
     */
    public static boolean isHidden(SharedPreferences prefs, String proto, String key) {
        String P = canon(proto);
        boolean ssh = P.equals("SSH");
        if (flag(prefs, P, "hideServer") && key.equals(ssh ? "sshHost" : "server")) return true;
        if (flag(prefs, P, "hideHost")) {
            if (key.equals("sni")) return true;
            if (ssh ? (key.equals("proxyHost") || key.equals("payload")) : key.equals("connectIp")) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ JSON <-> preferences

    public static JSONObject toJson(SharedPreferences prefs, String proto) throws JSONException {
        String P = canon(proto);
        JSONObject cfg = new JSONObject();
        for (String k : keys(P)) {
            String pk = P + "_" + k;
            if (BOOL_KEYS.contains(k)) {
                if (prefs.contains(pk)) cfg.put(k, prefs.getBoolean(pk, false));
            } else {
                String v = prefs.getString(pk, null);
                if (v == null && k.equals("sshHost")) v = DEFAULT_SSH_HOST;
                if (v != null) cfg.put(k, v);
            }
        }
        JSONObject root = new JSONObject();
        root.put("app", APP_ID);
        root.put("type", P);
        root.put("version", 1);
        root.put("exported", System.currentTimeMillis());
        root.put("config", cfg);
        return root;
    }

    /**
     * Writes the settings of {@code root} into the preferences. Returns an error text, or null on success.
     * {@code deviceHwid} is this phone's own {@link com.example.tunnel.HwId}; if the file was restricted to a
     * different device, nothing is written and an error is returned.
     */
    public static String fromJson(SharedPreferences prefs, String proto, JSONObject root, String deviceHwid) {
        String P = canon(proto);
        String app = root.optString("app", "");
        if (!(app.equalsIgnoreCase(APP_ID) || app.equalsIgnoreCase("bughunter"))) {
            return "this file is not a Nanika configuration";
        }
        String type = root.optString("type", "");
        if (!type.equalsIgnoreCase(P)) {
            return "this is a " + (type.isEmpty() ? "unknown" : type) + " configuration, not " + P;
        }
        JSONObject cfg = root.optJSONObject("config");
        if (cfg == null) return "the file has no settings in it";

        String requiredHwid = cfg.optString("hwid", "").trim();
        if (!requiredHwid.isEmpty()) {
            String mine = deviceHwid == null ? "" : deviceHwid.trim();
            if (!requiredHwid.equalsIgnoreCase(mine)) {
                return "this configuration is locked to another device (HWID mismatch)";
            }
        }

        String expiry = cfg.optString("expiry", "").trim();
        if (!expiry.isEmpty() && !DATE.matcher(expiry).matches()) return "the expiry date in the file is invalid";

        SharedPreferences.Editor e = prefs.edit();
        int written = 0;
        for (String k : keys(P)) {
            String pk = P + "_" + k;
            e.remove(pk);
            if (!cfg.has(k)) continue;
            if (BOOL_KEYS.contains(k)) {
                Object o = cfg.opt(k);
                e.putBoolean(pk, o instanceof Boolean ? (Boolean) o : "true".equalsIgnoreCase(String.valueOf(o)));
                written++;
            } else {
                String v = cfg.optString(k, "");
                if (v.length() > MAX_VALUE) v = v.substring(0, MAX_VALUE);
                e.putString(pk, v);
                written++;
            }
        }
        if (written == 0) return "the file contains no settings for " + P;
        e.apply();
        return null;
    }

    // ------------------------------------------------------------------ file bytes

    public static byte[] toAnika(JSONObject root) throws IOException {
        return AnikaCrypto.encrypt(root.toString());
    }

    public static byte[] toJsonFile(JSONObject root) throws IOException {
        try {
            return root.toString(2).getBytes(UTF8);
        } catch (JSONException e) {
            throw new IOException(e.getMessage());
        }
    }

    /** Reads either an encrypted .anika file or plain JSON. */
    public static JSONObject parseFile(byte[] data) throws IOException {
        try {
            if (AnikaCrypto.looksLikeAnika(data)) return new JSONObject(AnikaCrypto.decrypt(data));
            String s = new String(data, UTF8).trim();
            if (s.startsWith("\uFEFF")) s = s.substring(1);
            if (s.startsWith("{")) return new JSONObject(s);
        } catch (JSONException e) {
            throw new IOException("the file is not a valid configuration");
        }
        throw new IOException("this is not a Nanika configuration file");
    }

    // ------------------------------------------------------------------ vless:// links

    /** Parses a vless:// link into setting names -> values. Throws IllegalArgumentException with a user message. */
    public static Map<String, String> parseVless(String link) {
        String s = link == null ? "" : link.trim();
        if (!s.toLowerCase(Locale.US).startsWith("vless://")) throw new IllegalArgumentException("not a vless:// link");
        s = s.substring(8);
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);
        String query = "";
        int q = s.indexOf('?');
        if (q >= 0) { query = s.substring(q + 1); s = s.substring(0, q); }
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);
        int at = s.lastIndexOf('@');
        if (at < 1) throw new IllegalArgumentException("the link has no UUID");
        String uuid = decode(s.substring(0, at)).trim();
        String[] hp = hostPort(s.substring(at + 1));
        Map<String, String> qp = queryParams(query);

        String type = qp.containsKey("type") ? qp.get("type").toLowerCase(Locale.US) : "tcp";
        if (!type.equals("ws")) {
            throw new IllegalArgumentException("only WebSocket links (type=ws) are supported, this one is type=" + type);
        }
        String sec = qp.containsKey("security") ? qp.get("security").toLowerCase(Locale.US) : "none";
        if (!(sec.equals("tls") || sec.equals("none") || sec.isEmpty())) {
            throw new IllegalArgumentException("security=" + sec + " is not supported (only tls or none)");
        }
        boolean tls = sec.equals("tls");
        String hostParam = qp.containsKey("host") ? qp.get("host") : "";
        String sni = qp.containsKey("sni") ? qp.get("sni") : "";
        if (sni.isEmpty()) sni = !hostParam.isEmpty() ? hostParam : hp[0];

        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("uuid", uuid);
        m.put("connectIp", hp[0]);
        m.put("port", hp[1]);
        m.put("transport", tls ? "TLS" : "Non-TLS");
        m.put("sni", sni);
        m.put("server", !hostParam.isEmpty() ? hostParam : sni);
        m.put("path", qp.containsKey("path") && !qp.get("path").isEmpty() ? qp.get("path") : "/");
        return m;
    }

    public static String buildVless(Map<String, String> v) {
        boolean tls = !"Non-TLS".equals(v.get("transport"));
        String connect = nz(v.get("connectIp"), nz(v.get("server"), ""));
        String port = nz(v.get("port"), "443");
        StringBuilder sb = new StringBuilder("vless://");
        sb.append(nz(v.get("uuid"), "")).append('@');
        sb.append(connect.indexOf(':') >= 0 && !connect.startsWith("[") ? "[" + connect + "]" : connect);
        sb.append(':').append(port);
        sb.append("?encryption=none&security=").append(tls ? "tls" : "none");
        if (tls && !nz(v.get("sni"), "").isEmpty()) sb.append("&sni=").append(encode(v.get("sni")));
        sb.append("&type=ws");
        if (!nz(v.get("server"), "").isEmpty()) sb.append("&host=").append(encode(v.get("server")));
        sb.append("&path=").append(encode(nz(v.get("path"), "/")));
        sb.append("#Nanika");
        return sb.toString();
    }

    // ------------------------------------------------------------------ vmess:// links

    public static Map<String, String> parseVmess(String link) {
        String s = link == null ? "" : link.trim();
        if (!s.toLowerCase(Locale.US).startsWith("vmess://")) throw new IllegalArgumentException("not a vmess:// link");
        s = s.substring(8);
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);
        JSONObject j;
        try {
            String b64 = s.trim().replace('-', '+').replace('_', '/');
            j = new JSONObject(new String(Base64.decode(b64, Base64.DEFAULT), UTF8));
        } catch (Exception e) {
            throw new IllegalArgumentException("the vmess:// link could not be decoded");
        }
        String net = j.optString("net", "tcp").toLowerCase(Locale.US);
        if (!net.equals("ws")) {
            throw new IllegalArgumentException("only WebSocket links (net=ws) are supported, this one is net=" + net);
        }
        String add = j.optString("add", "").trim();
        String id = j.optString("id", "").trim();
        if (add.isEmpty() || id.isEmpty()) throw new IllegalArgumentException("the link has no address or UUID");
        String port = j.optString("port", "443").trim();
        boolean tls = j.optString("tls", "").equalsIgnoreCase("tls");
        String host = j.optString("host", "").trim();
        String sni = j.optString("sni", "").trim();
        if (sni.isEmpty()) sni = !host.isEmpty() ? host : add;

        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("uuid", id);
        m.put("connectIp", add);
        m.put("port", port.isEmpty() ? "443" : port);
        m.put("transport", tls ? "TLS" : "Non-TLS");
        m.put("sni", sni);
        m.put("server", !host.isEmpty() ? host : sni);
        String path = j.optString("path", "").trim();
        m.put("path", path.isEmpty() ? "/" : path);
        return m;
    }

    public static String buildVmess(Map<String, String> v) {
        boolean tls = !"Non-TLS".equals(v.get("transport"));
        try {
            JSONObject j = new JSONObject();
            j.put("v", "2");
            j.put("ps", "Nanika");
            j.put("add", nz(v.get("connectIp"), nz(v.get("server"), "")));
            j.put("port", nz(v.get("port"), "443"));
            j.put("id", nz(v.get("uuid"), ""));
            j.put("aid", "0");
            j.put("scy", "auto");
            j.put("net", "ws");
            j.put("type", "none");
            j.put("host", nz(v.get("server"), ""));
            j.put("path", nz(v.get("path"), "/"));
            j.put("tls", tls ? "tls" : "");
            j.put("sni", tls ? nz(v.get("sni"), "") : "");
            return "vmess://" + Base64.encodeToString(j.toString().getBytes(UTF8), Base64.NO_WRAP);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ link <-> preferences

    /** The current VLESS / VMess settings as a share link. */
    public static String exportLink(SharedPreferences prefs, String proto) {
        String P = canon(proto);
        Map<String, String> v = new LinkedHashMap<String, String>();
        for (String k : new String[]{"uuid", "server", "connectIp", "port", "sni", "path", "transport"}) {
            String x = prefs.getString(P + "_" + k, null);
            if (x != null) v.put(k, x.trim());
        }
        return "VLESS".equals(P) ? buildVless(v) : buildVmess(v);
    }

    /** Applies a link. Returns an error text or null. Keeps the DNS / insecure / expiry settings as they are. */
    public static String importLink(SharedPreferences prefs, String proto, String text) {
        String P = canon(proto);
        String t = text == null ? "" : text.trim();
        if (t.isEmpty()) return "the clipboard is empty";
        int nl = t.indexOf('\n');
        if (nl > 0) t = t.substring(0, nl).trim();
        Map<String, String> m;
        try {
            m = "VLESS".equals(P) ? parseVless(t) : parseVmess(t);
        } catch (IllegalArgumentException e) {
            String low = t.toLowerCase(Locale.US);
            if ("VLESS".equals(P) && low.startsWith("vmess://")) return "this is a vmess:// link - import it in VMess";
            if ("VMess".equals(P) && low.startsWith("vless://")) return "this is a vless:// link - import it in VLESS";
            return e.getMessage();
        }
        SharedPreferences.Editor e = prefs.edit();
        for (Map.Entry<String, String> en : m.entrySet()) e.putString(P + "_" + en.getKey(), en.getValue());
        e.apply();
        return null;
    }

    // ------------------------------------------------------------------ small helpers

    private static String nz(String s, String def) { return s == null || s.isEmpty() ? def : s; }

    private static String[] hostPort(String hp) {
        String host, port = "443";
        if (hp.startsWith("[")) {                       // [ipv6]:port
            int end = hp.indexOf(']');
            if (end < 0) throw new IllegalArgumentException("the link has an invalid address");
            host = hp.substring(1, end);
            if (hp.length() > end + 2 && hp.charAt(end + 1) == ':') port = hp.substring(end + 2);
        } else {
            int c = hp.lastIndexOf(':');
            if (c >= 0) { host = hp.substring(0, c); port = hp.substring(c + 1); } else host = hp;
        }
        host = decode(host).trim();
        if (host.isEmpty()) throw new IllegalArgumentException("the link has no address");
        int p;
        try { p = Integer.parseInt(port.trim()); } catch (NumberFormatException e) { p = -1; }
        if (p < 1 || p > 65535) throw new IllegalArgumentException("the link has an invalid port");
        return new String[]{host, String.valueOf(p)};
    }

    private static Map<String, String> queryParams(String query) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        if (query == null || query.isEmpty()) return m;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String k = decode(eq < 0 ? pair : pair.substring(0, eq)).trim().toLowerCase(Locale.US);
            String v = eq < 0 ? "" : decode(pair.substring(eq + 1));
            if (!k.isEmpty()) m.put(k, v);
        }
        return m;
    }

    private static String decode(String s) {
        try { return URLDecoder.decode(s, "UTF-8"); } catch (UnsupportedEncodingException e) { return s; }
        catch (IllegalArgumentException e) { return s; }
    }

    private static String encode(String s) {
        try { return URLEncoder.encode(s, "UTF-8").replace("+", "%20"); } catch (UnsupportedEncodingException e) { return s; }
    }
}

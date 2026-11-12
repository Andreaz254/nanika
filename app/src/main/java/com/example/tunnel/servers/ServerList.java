package com.example.tunnel.servers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The server list, fetched with an HTTPS GET from servers.freessh.indevs.in when the app starts and refreshed
 * while the picker is open.
 *
 * Accepted JSON (either a top-level array or {"servers":[...]}):
 *   {"servers":[
 *     {"name":"Kenya 1",
 *      "protocols":{
 *        "ssh":  {"sshHost":"ws-server1.example.com","user":"u1","pass":"p1"},
 *        "vless":{"server":"ws-server1.example.com","uuid":"..."},
 *        "vmess":{"server":"ws-server1.example.com","uuid":"..."}}}]}
 * A protocol is supported when it appears under "protocols". "protocols" may also be a plain list of names
 * ("protocols":["ssh","vless"]) with the values in sibling keys ("ssh":{...}).
 *
 * ONLY the server itself is taken from the list: SSH sshHost / user / pass and VLESS / VMess server (host header) /
 * uuid. Every other key (proxy host, ports, SNI, transport, path, payload, connectIp ...) is ignored even when the
 * server sends it: the proxy, payload, port and SNI always come from the user's own configuration. The values are
 * used when connecting; they are never written into the settings pages.
 */
public final class ServerList {
    public static final String HOST = "servers.freessh.indevs.in";
    public static final String URL = "https://" + HOST + "/";
    private static final String CACHE_KEY = "servers_json";
    private static final String API_TOKEN = "PASTE_YOUR_TOKEN";

    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private static final List<String> SSH_KEYS = java.util.Arrays.asList("sshHost", "user", "pass");
    private static final List<String> WS_KEYS = java.util.Arrays.asList("server", "uuid");

    private ServerList() {}

    public static List<String> allowed(String proto) {
        return "SSH".equals(proto) ? SSH_KEYS : WS_KEYS;
    }

    public static final class Server {
        public final String name;
        /** "SSH" / "VLESS" / "VMess" -> settings to apply (may be empty). */
        public final Map<String, Map<String, String>> protos;

        Server(String name, Map<String, Map<String, String>> protos) {
            this.name = name;
            this.protos = protos;
        }

        public boolean supports(String proto) { return protos.containsKey(proto); }
        public Map<String, String> config(String proto) {
            Map<String, String> m = protos.get(proto);
            return m == null ? Collections.<String, String>emptyMap() : m;
        }

        /** "SSH WebSocket  •  VLESS  •  VMess" */
        public String protocolSummary() {
            StringBuilder sb = new StringBuilder();
            for (String p : new String[]{"SSH", "VLESS", "VMess"}) {
                if (!supports(p)) continue;
                if (sb.length() > 0) sb.append("  \u2022  ");
                sb.append(label(p));
            }
            return sb.length() == 0 ? "no protocols" : sb.toString();
        }
    }

    public static String label(String proto) {
        return "SSH".equals(proto) ? "SSH WebSocket" : proto;
    }

    /** "vmess", "VMess", "ssh websocket", "ssh-ws" ... -> "VMess" / "VLESS" / "SSH", or null. */
    public static String canonicalProto(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toLowerCase(Locale.US).replace("-", "").replace("_", "").replace(" ", "");
        if (s.equals("vmess")) return "VMess";
        if (s.equals("vless")) return "VLESS";
        if (s.equals("ssh") || s.equals("sshws") || s.equals("sshwebsocket") || s.equals("websocket") || s.equals("sshovercws")) return "SSH";
        return null;
    }

    // ------------------------------------------------------------------ parsing

    /** @throws IllegalArgumentException when the text is not a usable server list */
    public static List<Server> parse(String text) {
        try {
            JSONArray arr;
            String t = text.trim();
            if (t.startsWith("[")) {
                arr = new JSONArray(t);
            } else {
                JSONObject root = new JSONObject(t);
                arr = root.optJSONArray("servers");
                if (arr == null) throw new IllegalArgumentException("no \"servers\" list");
            }
            List<Server> out = new ArrayList<Server>();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) continue;
                String name = o.optString("name", "").trim();
                if (name.isEmpty() || name.length() > 60) continue;
                Map<String, Map<String, String>> protos = new LinkedHashMap<String, Map<String, String>>();
                Object p = o.opt("protocols");
                if (p instanceof JSONObject) {
                    JSONObject po = (JSONObject) p;
                    Iterator<String> it = po.keys();
                    while (it.hasNext()) {
                        String k = it.next();
                        String proto = canonicalProto(k);
                        if (proto == null) continue;
                        protos.put(proto, clean(proto, po.optJSONObject(k)));
                    }
                } else if (p instanceof JSONArray) {
                    JSONArray pa = (JSONArray) p;
                    for (int j = 0; j < pa.length(); j++) {
                        String proto = canonicalProto(pa.optString(j, ""));
                        if (proto == null) continue;
                        JSONObject cfg = null;
                        Iterator<String> it = o.keys();
                        while (it.hasNext()) {                    // settings in a sibling key: "ssh": {...}
                            String k = it.next();
                            if (proto.equals(canonicalProto(k)) && o.optJSONObject(k) != null) cfg = o.optJSONObject(k);
                        }
                        protos.put(proto, clean(proto, cfg));
                    }
                }
                if (!protos.isEmpty()) out.add(new Server(name, protos));
            }
            return out;
        } catch (org.json.JSONException e) {
            throw new IllegalArgumentException("not valid JSON");
        }
    }

    /** Keeps only the allowed keys (server address, credentials, uuid). */
    private static Map<String, String> clean(String proto, JSONObject cfg) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        if (cfg == null) return m;
        for (String k : allowed(proto)) {
            if (!cfg.has(k)) continue;
            Object raw = cfg.opt(k);
            if (raw == null || raw == JSONObject.NULL) continue;
            String v = String.valueOf(raw).trim();
            if (v.isEmpty() || v.length() > 300) continue;
            m.put(k, v);
        }
        return m;
    }

    // ------------------------------------------------------------------ cache + fetch

    /** The list from the last successful fetch, or null if there never was one. */
    public static List<Server> load(SharedPreferences prefs) {
        String cached = prefs.getString(CACHE_KEY, null);
        if (cached == null) return null;
        try {
            return parse(cached);
        } catch (RuntimeException e) {
            return null;
        }
    }

    public interface Listener { void onList(List<Server> servers); }

    public static void fetch(Context ctx, SharedPreferences prefs, Listener ok) {
        fetch(ctx, prefs, ok, null);
    }

    /**
     * HTTPS GET in the background. {@code ok} runs on the main thread with the new list; {@code fail} (may be null)
     * runs there when nothing usable came back (no internet, bad answer). The saved list stays in use then.
     */
    public static void fetch(final Context ctx, final SharedPreferences prefs, final Listener ok, final Runnable fail) {
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(URL).openConnection();
                    c.setInstanceFollowRedirects(false);
                    c.setConnectTimeout(7000);
                    c.setReadTimeout(12000);
                    c.setRequestProperty("Accept", "application/json");
                    c.setRequestProperty("Authorization", "Bearer " + API_TOKEN);
                    c.setRequestProperty("User-Agent", "Nanika");
                    if (c.getResponseCode() == 200) {
                        ByteArrayOutputStream bo = new ByteArrayOutputStream();
                        try (InputStream in = c.getInputStream()) {
                            byte[] buf = new byte[4096];
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                bo.write(buf, 0, n);
                                if (bo.size() > 256 * 1024) throw new IOException("too large");
                            }
                        }
                        final String text = bo.toString("UTF-8");
                        final List<Server> list = parse(text);              // throws if unusable: then nothing is saved
                        prefs.edit().putString(CACHE_KEY, text).apply();
                        MAIN.post(new Runnable() {
                            @Override public void run() { ok.onList(list); }
                        });
                        return;
                    }
                } catch (Exception ignored) {
                    // no internet / bad answer: fall through to the failure callback
                }
                if (fail != null) MAIN.post(fail);
            }
        }, "server-list").start();
    }
}

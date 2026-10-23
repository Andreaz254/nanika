package com.example.tunnel.ssh;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Expands the user's payload template into the bytes sent to the proxy.
 *
 * Placeholders (case-insensitive):
 *   [crlf] [cr] [lf] [lfcr]   line breaks
 *   [host]        SSH server host (falls back to the proxy host)
 *   [port]        SSH server port
 *   [host_port]   [host]:[port]
 *   [sni]         the SNI / TLS host field
 *   [proxy]       proxy host            [proxy_port]  proxy port
 *   [ws_key]      random Sec-WebSocket-Key
 *   [split]       send what comes before it as its own TCP write, pause, continue
 *
 * Real line breaks typed in the field: if the payload uses any of [crlf]/[cr]/[lf]/[lfcr] they are ignored
 * (they are only for readability); otherwise every real line break becomes CRLF.
 * The two-character sequences \r and \n are accepted as well.
 */
public final class SshPayload {
    public static final String DEFAULT_RAW =
            "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]";
    public static final String DEFAULT_FRAMED =
            "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]"
                    + "Sec-WebSocket-Key: [ws_key][crlf]Sec-WebSocket-Version: 13[crlf][crlf]";

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final Pattern LINE_TOKEN = Pattern.compile("(?i)\\[(crlf|cr|lf|lfcr)\\]");
    private static final Pattern TOKEN = Pattern.compile("(?i)\\[([a-z_]+)\\]");
    private static final char SPLIT = '\u0000';

    public static final class Context {
        public String host;        // value of [host]
        public int port = 22;      // value of [port]
        public String sni = "";
        public String proxyHost = "";
        public int proxyPort;
        public String wsKey = "";
        public String method = "GET";
        public String protocolVersion = "HTTP/1.1";
    }

    private SshPayload() {}

    /** Returns the parts to send, in order (a payload without [split] has exactly one part). */
    public static List<byte[]> expand(String template, boolean framed, Context ctx) {
        String t = template == null ? "" : template;
        if (t.trim().isEmpty()) t = framed ? DEFAULT_FRAMED : DEFAULT_RAW;

        t = t.replace("\\r\\n", "[crlf]").replace("\\n", "[lf]").replace("\\r", "[cr]");
        if (LINE_TOKEN.matcher(t).find()) {
            t = t.replace("\r", "").replace("\n", "");
        } else {
            t = t.replace("\r\n", "\n").replace('\r', '\n').replace("\n", "[crlf]");
        }

        String host = ctx.host == null || ctx.host.isEmpty() ? ctx.proxyHost : ctx.host;
        Matcher m = TOKEN.matcher(t);
        StringBuilder sb = new StringBuilder();
        int last = 0;
        while (m.find()) {
            String name = m.group(1).toLowerCase();
            String val;
            if (name.equals("crlf")) val = "\r\n";
            else if (name.equals("cr")) val = "\r";
            else if (name.equals("lf")) val = "\n";
            else if (name.equals("lfcr")) val = "\n\r";
            else if (name.equals("host")) val = host;
            else if (name.equals("port")) val = String.valueOf(ctx.port);
            else if (name.equals("host_port")) val = host + ":" + ctx.port;
            else if (name.equals("sni")) val = ctx.sni == null ? "" : ctx.sni;
            else if (name.equals("proxy")) val = ctx.proxyHost;
            else if (name.equals("proxy_port")) val = String.valueOf(ctx.proxyPort);
            else if (name.equals("ws_key")) val = ctx.wsKey;
            else if (name.equals("method")) val = ctx.method == null || ctx.method.isEmpty() ? "GET" : ctx.method;
            else if (name.equals("protocol")) val = ctx.protocolVersion == null || ctx.protocolVersion.isEmpty() ? "HTTP/1.1" : ctx.protocolVersion;
            else if (name.equals("split")) val = String.valueOf(SPLIT);
            else val = m.group();                         // unknown token: keep it as typed
            sb.append(t, last, m.start()).append(val);
            last = m.end();
        }
        sb.append(t, last, t.length());

        List<byte[]> parts = new ArrayList<byte[]>();
        for (String part : sb.toString().split(String.valueOf(SPLIT), -1)) {
            if (!part.isEmpty()) parts.add(part.getBytes(UTF8));
        }
        return parts;
    }

    /** True if the parts end with a blank line (the end of an HTTP request). */
    public static boolean endsWithBlankLine(List<byte[]> parts) {
        if (parts.isEmpty()) return false;
        String last = new String(parts.get(parts.size() - 1), UTF8);
        return last.endsWith("\r\n\r\n") || last.endsWith("\n\n");
    }
}

package com.example.tunnel.ssh;

import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds the HTTP "payload" (including [split] multi-part payloads) and performs the handshake.
 *
 * Supported tokens: [host] [host_port] [port] [path] [ua] [crlf] [cr] [lf]
 *                   [split] (short pause) [delay_split] (1.5 s pause) [instant_split] (no pause)
 *
 * Handshake rules (this is what injector-style clients do):
 *  - every part is written as its own TCP write, in order;
 *  - the proxy may answer each part with its own HTTP response (e.g. "200 OK" for a /cdn-cgi/trace
 *    request). Those intermediate responses are read and discarded;
 *  - the handshake succeeds on the first "HTTP/1.x 101" response, and no byte after its blank line is consumed
 *    (that is the start of the SSH banner).
 */
final class PayloadHandshake {
    static final String DEFAULT_UA =
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
    private static final Pattern SPLIT = Pattern.compile("\\[(split|instant_split|delay_split)\\]");
    private static final int SPLIT_MS = 250, DELAY_SPLIT_MS = 1500;
    private static final int FIRST_WAIT_MS = 15000, AFTER_ERROR_WAIT_MS = 3000;

    private PayloadHandshake() {}

    static final class Part {
        final String data; final int delayMs;
        Part(String data, int delayMs) { this.data = data; this.delayMs = delayMs; }
    }

    static List<Part> build(String payload, String host, int port, String path) {
        String p = payload == null ? "" : payload.trim();
        String uri = (path == null || path.trim().isEmpty()) ? "/" : path.trim();
        if (!uri.startsWith("/")) uri = "/" + uri;
        if (p.isEmpty()) {
            p = "GET " + uri + " HTTP/1.1[crlf]Host: " + host + "[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf][crlf]";
        }
        p = p.replace("[host_port]", host + ":" + port).replace("[host]", host)
                .replace("[port]", String.valueOf(port)).replace("[path]", uri).replace("[ua]", DEFAULT_UA)
                .replace("[crlf]", "\r\n").replace("[cr]", "\r").replace("[lf]", "\n").replace("\\r\\n", "\r\n");

        List<Part> parts = new ArrayList<>();
        Matcher m = SPLIT.matcher(p);
        int last = 0, pending = 0;
        while (m.find()) {
            addPart(parts, p.substring(last, m.start()), pending);
            String t = m.group(1);
            pending = "instant_split".equals(t) ? 0 : ("delay_split".equals(t) ? DELAY_SPLIT_MS : SPLIT_MS);
            last = m.end();
        }
        addPart(parts, p.substring(last), pending);
        // Single-part payloads: make sure the request is terminated. Multi-part payloads are sent exactly as written
        // (a final part may intentionally stay "open", e.g. with a huge Content-Length).
        if (parts.size() == 1 && !parts.get(0).data.endsWith("\r\n\r\n"))
            parts.set(0, new Part(parts.get(0).data + "\r\n\r\n", 0));
        return parts;
    }

    private static void addPart(List<Part> parts, String s, int delay) {
        if (!s.isEmpty()) parts.add(new Part(s, parts.isEmpty() ? 0 : delay));
    }

    static void send(OutputStream out, List<Part> parts) throws IOException {
        for (Part part : parts) {
            if (part.delayMs > 0) {
                try { Thread.sleep(part.delayMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new InterruptedIOException(); }
            }
            out.write(part.data.getBytes("ISO-8859-1"));
            out.flush();
        }
    }

    /** Sends every part, then waits for the HTTP 101. A send failure (proxy slammed the door mid-payload) is not
     *  fatal by itself: whatever the proxy answered is still read, so the real reason (e.g. 403) is reported. */
    static void handshake(Socket sock, List<Part> parts) throws IOException {
        IOException sendError = null;
        try { send(sock.getOutputStream(), parts); } catch (InterruptedIOException e) { throw e; } catch (IOException e) { sendError = e; }
        awaitUpgrade(sock, sendError);
    }

    /** Reads responses until an HTTP 101. Throws with every status line seen, so failures are diagnosable. */
    static void awaitUpgrade(Socket sock, IOException sendError) throws IOException {
        InputStream in = sock.getInputStream();
        List<String> seen = new ArrayList<>();
        int wait = FIRST_WAIT_MS;
        while (true) {
            sock.setSoTimeout(wait);
            String head;
            try { head = readHead(in); }
            catch (EOFException | java.net.SocketException e) { throw new IOException("Proxy closed during payload handshake" + describeSeen(seen) + (sendError != null ? " (send: " + sendError.getMessage() + ")" : "")); }
            catch (SocketTimeoutException e) { throw new IOException("No HTTP 101 from proxy" + describeSeen(seen)); }
            String first = head.split("\r\n", 2)[0];
            if (!first.startsWith("HTTP/")) continue;          // leftover body bytes - ignore
            seen.add(first);
            int code = statusCode(first);
            if (code == 101) return;
            if (code >= 400) wait = AFTER_ERROR_WAIT_MS;        // an error: do not wait the full timeout for a 101
            drainBody(in, head, code);
            if (seen.size() > 8) throw new IOException("Proxy handshake rejected" + describeSeen(seen));
        }
    }

    private static String describeSeen(List<String> seen) { return seen.isEmpty() ? " (no response)" : ": " + String.join(" | ", seen); }

    private static int statusCode(String statusLine) {
        String[] t = statusLine.split(" ");
        try { return t.length > 1 ? Integer.parseInt(t[1].trim()) : -1; } catch (NumberFormatException e) { return -1; }
    }

    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(); int tail = 0;
        while (b.size() < 32768) {
            int c = in.read(); if (c < 0) throw new EOFException();
            b.write(c); tail = ((tail << 8) | c) & 0xFFFFFFFF;
            if (tail == 0x0D0A0D0A) return b.toString("ISO-8859-1");
        }
        throw new IOException("Response header too large");
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) { int c = in.read(); if (c < 0) throw new EOFException(); if (c == '\n') break; if (c != '\r') sb.append((char) c); }
        return sb.toString();
    }

    private static void skip(InputStream in, long n) throws IOException {
        byte[] buf = new byte[4096];
        while (n > 0) { int r = in.read(buf, 0, (int) Math.min(buf.length, n)); if (r < 0) throw new EOFException(); n -= r; }
    }

    private static void drainBody(InputStream in, String head, int code) throws IOException {
        if ((code >= 100 && code < 200) || code == 204 || code == 304) return;
        long cl = -1; boolean chunked = false;
        for (String line : head.split("\r\n")) {
            String l = line.toLowerCase(Locale.ROOT);
            if (l.startsWith("content-length:")) { try { cl = Long.parseLong(l.substring(15).trim()); } catch (NumberFormatException ignored) {} }
            else if (l.startsWith("transfer-encoding:") && l.contains("chunked")) chunked = true;
        }
        if (chunked) {
            while (true) {
                int n; try { n = Integer.parseInt(readLine(in).split(";")[0].trim(), 16); } catch (NumberFormatException e) { return; }
                if (n == 0) { while (!readLine(in).isEmpty()) { } return; }
                skip(in, n); readLine(in);
            }
        } else if (cl > 0) skip(in, cl);
    }

    /** Printable form of the parts for the log (CRLF shown as \r\n). */
    static String describe(List<Part> parts) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) sb.append(" ~split ").append(parts.get(i).delayMs).append("ms~ ");
            sb.append(parts.get(i).data.replace("\r", "\\r").replace("\n", "\\n"));
        }
        return sb.toString();
    }
}

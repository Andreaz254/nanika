package com.example.tunnel.ssh;

/** Ready-made payload templates offered from the SSH page's "Inject payload" menu. */
public final class InjectPayloads {
    private InjectPayloads() {}

    public static final String CLOUDFLARE =
            "GET ws://example.com HTTP/1.1[crlf]Host: [host][crlf]Service: SSH[crlf]ModeX: Bypass[crlf]"
                    + "Upgrade: websocket[crlf][crlf]";

    public static final String ENHANCED =
            "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: example.com[crlf]Service: SSH[crlf]ModeX: Bypass[crlf]"
                    + "Upgrade: websocket[crlf][crlf]";

    public static final String DIRECT =
            "[method] [host_port] [protocol][crlf]Host: [host][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]";
}

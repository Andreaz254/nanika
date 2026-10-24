package com.example.tunnel.ui;

import android.os.Build;
import android.text.Html;

import java.util.regex.Pattern;

/**
 * Turns a banner / message into displayable text.
 *  - Plain text is returned untouched (shown as it is).
 *  - HTML is rendered with its colours and styles, and the layout of the text is preserved: line breaks
 *    stay line breaks and runs of spaces stay aligned, so ASCII art keeps its shape.
 */
public final class HtmlText {
    private HtmlText() {}

    private static final Pattern HAS_TAG = Pattern.compile("(?is)<\\s*/?\\s*[a-z][a-z0-9]*(\\s[^>]*)?/?>");
    private static final Pattern HAS_BR = Pattern.compile("(?i)<\\s*br\\s*/?>");
    private static final Pattern DROP = Pattern.compile("(?is)<\\s*(script|style|head)[^>]*>.*?<\\s*/\\s*\\1\\s*>");
    private static final Pattern PRE = Pattern.compile("(?i)<\\s*/?\\s*pre[^>]*>");
    private static final Pattern DIV_OPEN = Pattern.compile("(?i)<\\s*(html|body)[^>]*>|<\\s*/\\s*(html|body)\\s*>");

    public static boolean isHtml(String s) {
        return s != null && HAS_TAG.matcher(s).find();
    }

    /** Plain text -> as is; HTML -> styled text. Never returns null. */
    public static CharSequence render(String raw) {
        if (raw == null) return "";
        String s = raw.replace("\r\n", "\n").replace('\r', '\n');
        if (!isHtml(s)) return s;
        return fromHtml(preserveLayout(s));
    }

    /** Plain-text version of {@link #render} (tags removed). */
    public static String plain(String raw) {
        return render(raw).toString();
    }

    static String preserveLayout(String s) {
        s = DROP.matcher(s).replaceAll("");
        s = PRE.matcher(s).replaceAll("");
        s = DIV_OPEN.matcher(s).replaceAll("");
        boolean explicitBreaks = HAS_BR.matcher(s).find();   // the author used <br>: the raw newlines are only formatting
        StringBuilder out = new StringBuilder(s.length() + s.length() / 4);
        boolean inTag = false;
        boolean prevSpace = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inTag) {
                out.append(c == '\n' ? ' ' : c);
                if (c == '>') inTag = false;
                continue;
            }
            if (c == '<') {
                inTag = true;
                out.append(c);
                prevSpace = false;
            } else if (c == '\n') {
                if (!explicitBreaks) out.append("<br>");
                prevSpace = false;
            } else if (c == '\t') {
                out.append("&nbsp;&nbsp;&nbsp;&nbsp;");
                prevSpace = false;
            } else if (c == ' ') {
                out.append(prevSpace ? "&nbsp;" : " ");
                prevSpace = true;
            } else {
                out.append(c);
                prevSpace = false;
            }
        }
        return out.toString();
    }

    @SuppressWarnings("deprecation")
    private static CharSequence fromHtml(String html) {
        CharSequence t = Build.VERSION.SDK_INT >= 24
                ? Html.fromHtml(html, Html.FROM_HTML_MODE_LEGACY)
                : Html.fromHtml(html);
        int end = t.length();
        while (end > 0 && (t.charAt(end - 1) == '\n' || t.charAt(end - 1) == ' ')) end--;   // trailing breaks
        return t.subSequence(0, end);
    }
}

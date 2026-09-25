package com.example.tunnel;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;

import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.ProtocolRegistry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class MainActivity extends AppCompatActivity implements TunnelState.Listener {

    private static final int ORANGE = Color.rgb(242, 107, 33);
    private static final int GREEN = Color.rgb(30, 160, 98);
    private static final int RED = Color.rgb(238, 56, 62);
    private static final String[] PROTOCOLS = {"SSH", "VLESS", "VMess"};
    private static final String[] DNS_PRESETS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"};

    private interface Pick { void on(String value); }

    // Theme colours
    private int BG, CARD, TEXT, MUTED, BORDER, SOFT;

    private SharedPreferences prefs;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String page = "home";
    private String protocol;

    private FrameLayout root;
    private FrameLayout toolbarHolder;
    private LinearLayout body;
    private ScrollView scroll;
    private View scrim;
    private LinearLayout drawer;

    // Home widgets
    private View ringView;
    private LinearLayout discView;
    private ImageView discIcon;
    private TextView discText;
    private ImageView statusIcon;
    private TextView statusText;
    private View dotView;
    private ImageView dotSpinner;
    private TextView logView;
    private final LinearLayout[] cardBox = new LinearLayout[3];
    private final ImageView[] cardIcon = new ImageView[3];
    private final TextView[] cardLabel = new TextView[3];
    private final View[] cardBadge = new View[3];

    private Intent pendingStart;
    private boolean userStopped, wasConnected, autoRetrying;
    private int reconnectAttempts;

    private final ActivityResultLauncher<Intent> vpnPermission = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == RESULT_OK) {
                    launch();
                } else {
                    pendingStart = null;
                    TunnelState.log("VPN permission denied - cannot start");
                    TunnelState.set(TunnelState.State.ERROR, "VPN permission denied");
                }
            });

    private final ActivityResultLauncher<String> notificationPermission = registerForActivityResult(
            new ActivityResultContracts.RequestPermission(), granted -> askVpnPermission());

    // ================================================================== lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("dark_custom_settings", MODE_PRIVATE);
        protocol = prefs.getString("protocol", "SSH");
        applyTheme();
        buildShell();
        show("home");
    }

    @Override
    protected void onStart() {
        super.onStart();
        TunnelState.setListener(this);
        if (logView != null) renderLog();
        refreshHome();
    }

    @Override
    protected void onDestroy() {
        TunnelState.setListener(null);
        ui.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (drawer.getVisibility() == View.VISIBLE) closeDrawer();
        else if (!"home".equals(page)) show("home");
        else super.onBackPressed();
    }

    private void applyTheme() {
        boolean dark = "Dark".equals(prefs.getString("theme", "Light"));
        BG = dark ? Color.rgb(20, 22, 28) : Color.rgb(255, 248, 240);
        CARD = dark ? Color.rgb(31, 34, 43) : Color.WHITE;
        TEXT = dark ? Color.rgb(242, 242, 245) : Color.rgb(30, 30, 36);
        MUTED = dark ? Color.rgb(154, 156, 168) : Color.rgb(125, 125, 135);
        BORDER = dark ? Color.rgb(58, 61, 74) : Color.rgb(228, 221, 212);
        SOFT = dark ? Color.rgb(58, 40, 30) : Color.rgb(255, 240, 230);
        getWindow().setStatusBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(dark ? 0 : View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
    }

    // ================================================================== shell

    private void buildShell() {
        root = new FrameLayout(this);
        root.setBackgroundColor(BG);

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        toolbarHolder = new FrameLayout(this);
        column.addView(toolbarHolder, new LinearLayout.LayoutParams(-1, -2));

        scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(18), dp(4), dp(18), dp(24));
        scroll.addView(body, new FrameLayout.LayoutParams(-1, -2));
        column.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        root.addView(column, new FrameLayout.LayoutParams(-1, -1));

        scrim = new View(this);
        scrim.setBackgroundColor(0x66000000);
        scrim.setVisibility(View.GONE);
        scrim.setOnClickListener(v -> closeDrawer());
        root.addView(scrim, new FrameLayout.LayoutParams(-1, -1));

        drawer = new LinearLayout(this);
        drawer.setOrientation(LinearLayout.VERTICAL);
        drawer.setBackgroundColor(BG);
        drawer.setPadding(dp(16), dp(28), dp(16), dp(16));
        drawer.setVisibility(View.GONE);
        drawer.setClickable(true);
        root.addView(drawer, new FrameLayout.LayoutParams(dp(290), -1));
        setContentView(root);
    }

    private void openDrawer() {
        refreshDrawer();
        scrim.setAlpha(0f);
        scrim.setVisibility(View.VISIBLE);
        scrim.animate().alpha(1f).setDuration(180).start();
        drawer.setTranslationX(-dp(290));
        drawer.setVisibility(View.VISIBLE);
        drawer.animate().translationX(0).setDuration(200).start();
    }

    private void closeDrawer() {
        scrim.animate().alpha(0f).setDuration(160).withEndAction(() -> scrim.setVisibility(View.GONE)).start();
        drawer.animate().translationX(-dp(290)).setDuration(180)
                .withEndAction(() -> drawer.setVisibility(View.GONE)).start();
    }

    private void refreshDrawer() {
        drawer.removeAllViews();
        LinearLayout head = row();
        head.setGravity(Gravity.CENTER_VERTICAL);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_logo);
        head.addView(logo, new LinearLayout.LayoutParams(dp(48), dp(48)));
        LinearLayout names = new LinearLayout(this);
        names.setOrientation(LinearLayout.VERTICAL);
        names.setPadding(dp(12), 0, 0, 0);
        names.addView(text("Bug Hunter", 20, TEXT, true));
        names.addView(text("Secure \u2022 Fast \u2022 Private", 12, MUTED, false));
        head.addView(names);
        drawer.addView(head, mp(-1, -2, 0, 0, 0, 22));

        drawerItem(R.drawable.ic_home, "Home", "home");
        drawerItem(R.drawable.ic_terminal, "SSH", "ssh");
        drawerItem(R.drawable.ic_send, "VLESS", "vless");
        drawerItem(R.drawable.ic_cube, "VMess", "vmess");
        View line = new View(this);
        line.setBackgroundColor(BORDER);
        drawer.addView(line, mp(-1, 1, 6, 14, 6, 14));
        drawerItem(R.drawable.ic_gear, "Settings", "settings");
    }

    private void drawerItem(int iconRes, String label, final String target) {
        boolean sel = target.equals(page);
        LinearLayout item = row();
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(dp(14), 0, dp(14), 0);
        if (sel) item.setBackground(shape(SOFT, 0, 0, 12));
        item.addView(icon(iconRes, 22, sel ? ORANGE : TEXT));
        TextView t = text(label, 16, sel ? ORANGE : TEXT, sel);
        t.setPadding(dp(18), 0, 0, 0);
        item.addView(t);
        item.setOnClickListener(v -> {
            closeDrawer();
            if (target.equals("ssh")) selectProtocol("SSH");
            else if (target.equals("vless")) selectProtocol("VLESS");
            else if (target.equals("vmess")) selectProtocol("VMess");
            show(target);
        });
        drawer.addView(item, mp(-1, 50, 0, 2, 0, 2));
    }

    private View homeBar() {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(18), dp(6));
        ImageView menu = icon(R.drawable.ic_menu, 26, ORANGE);
        menu.setOnClickListener(v -> openDrawer());
        bar.addView(menu);
        TextView title = text("Bug Hunter", 20, TEXT, true);
        title.setPadding(dp(18), 0, 0, 0);
        bar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        FrameLayout dot = new FrameLayout(this);
        dotView = new View(this);
        FrameLayout.LayoutParams dp1 = new FrameLayout.LayoutParams(dp(12), dp(12));
        dp1.gravity = Gravity.CENTER;
        dot.addView(dotView, dp1);
        dotSpinner = icon(R.drawable.ic_spinner, 20, ORANGE);
        dot.addView(dotSpinner, new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.CENTER));
        bar.addView(dot, new LinearLayout.LayoutParams(dp(24), dp(24)));
        return bar;
    }

    private View pageBar(String title, Runnable saveAction) {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(18), dp(6));
        ImageView back = icon(R.drawable.ic_back, 24, ORANGE);
        back.setOnClickListener(v -> show("home"));
        bar.addView(back);
        TextView t = text(title, 18, TEXT, true);
        t.setPadding(dp(16), 0, 0, 0);
        bar.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        if (saveAction != null) {
            LinearLayout save = row();
            save.setGravity(Gravity.CENTER_VERTICAL);
            save.addView(icon(R.drawable.ic_save, 18, ORANGE));
            TextView s = text("SAVE", 12, ORANGE, true);
            s.setPadding(dp(5), 0, 0, 0);
            save.addView(s);
            save.setOnClickListener(v -> saveAction.run());
            bar.addView(save);
        }
        return bar;
    }

    private void show(String target) {
        page = target;
        clearHomeRefs();
        toolbarHolder.removeAllViews();
        body.removeAllViews();
        hideKeyboard();
        Runnable save = this::saveAndHome;
        if ("home".equals(target)) {
            toolbarHolder.addView(homeBar());
            buildHome();
        } else if ("ssh".equals(target)) {
            toolbarHolder.addView(pageBar("SSH Configuration", save));
            buildSsh();
        } else if ("vless".equals(target)) {
            toolbarHolder.addView(pageBar("VLESS Configuration", save));
            buildWsConfig("VLESS");
        } else if ("vmess".equals(target)) {
            toolbarHolder.addView(pageBar("VMess Configuration", save));
            buildWsConfig("VMess");
        } else {
            toolbarHolder.addView(pageBar("Settings", null));
            buildSettings();
        }
        scroll.scrollTo(0, 0);
    }

    private void clearHomeRefs() {
        ringView = null; discView = null; discIcon = null; discText = null; statusIcon = null;
        statusText = null; dotView = null; dotSpinner = null; logView = null;
    }

    private void saveAndHome() {
        Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show();
        show("home");
    }

    private boolean busy() {
        TunnelState.State s = TunnelState.state();
        return s == TunnelState.State.CONNECTED || s == TunnelState.State.CONNECTING
                || s == TunnelState.State.DISCONNECTING;
    }

    private void selectProtocol(String p) {
        if (p.equals(protocol)) return;
        if (busy()) {
            Toast.makeText(this, "Stop the VPN before changing protocol", Toast.LENGTH_SHORT).show();
            return;
        }
        protocol = p;
        prefs.edit().putString("protocol", p).apply();
    }

    // ================================================================== HOME

    private void buildHome() {
        FrameLayout hero = new FrameLayout(this);
        ringView = new View(this);
        hero.addView(ringView, new FrameLayout.LayoutParams(-1, -1));
        discView = new LinearLayout(this);
        discView.setOrientation(LinearLayout.VERTICAL);
        discView.setGravity(Gravity.CENTER);
        discIcon = icon(R.drawable.ic_power, 46, Color.WHITE);
        discText = text("CONNECT", 14, Color.WHITE, true);
        discText.setGravity(Gravity.CENTER);
        discView.addView(discIcon);
        discView.addView(discText, mp(-2, -2, 0, 6, 0, 0));
        hero.addView(discView, new FrameLayout.LayoutParams(dp(142), dp(142), Gravity.CENTER));
        hero.setOnClickListener(v -> onButton());
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(dp(180), dp(180));
        hp.gravity = Gravity.CENTER_HORIZONTAL;
        hp.topMargin = dp(14);
        body.addView(hero, hp);

        LinearLayout status = row();
        status.setGravity(Gravity.CENTER);
        statusIcon = icon(R.drawable.ic_server, 16, TEXT);
        statusText = text("", 13, TEXT, false);
        statusText.setPadding(dp(8), 0, 0, 0);
        status.addView(statusIcon);
        status.addView(statusText);
        body.addView(status, mp(-1, -2, 0, 14, 0, 22));

        body.addView(text("CHOOSE PROTOCOL", 12, ORANGE, true), mp(-2, -2, 2, 0, 0, 8));
        LinearLayout cards = row();
        int[] icons = {R.drawable.ic_terminal, R.drawable.ic_send, R.drawable.ic_cube};
        for (int i = 0; i < 3; i++) {
            final String name = PROTOCOLS[i];
            FrameLayout cell = new FrameLayout(this);
            cardBox[i] = new LinearLayout(this);
            cardBox[i].setOrientation(LinearLayout.VERTICAL);
            cardBox[i].setGravity(Gravity.CENTER);
            cardIcon[i] = icon(icons[i], 28, TEXT);
            cardLabel[i] = text(name, 13, TEXT, false);
            cardBox[i].addView(cardIcon[i]);
            cardBox[i].addView(cardLabel[i], mp(-2, -2, 0, 8, 0, 0));
            cell.addView(cardBox[i], new FrameLayout.LayoutParams(-1, -1));
            FrameLayout badge = new FrameLayout(this);
            badge.setBackground(oval(ORANGE));
            badge.addView(icon(R.drawable.ic_check, 12, Color.WHITE), new FrameLayout.LayoutParams(dp(12), dp(12), Gravity.CENTER));
            cardBadge[i] = badge;
            FrameLayout.LayoutParams bp = new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.TOP | Gravity.END);
            bp.setMargins(0, dp(6), dp(6), 0);
            cell.addView(badge, bp);
            cell.setOnClickListener(v -> { selectProtocol(name); updateCards(); refreshHome(); });
            cards.addView(cell, mp(0, 88, i == 0 ? 0 : 5, 0, i == 2 ? 0 : 5, 0, 1));
        }
        body.addView(cards);

        LinearLayout logs = new LinearLayout(this);
        logs.setOrientation(LinearLayout.VERTICAL);
        logs.setBackground(shape(CARD, ORANGE, 2, 12));
        logs.setPadding(dp(12), dp(10), dp(12), dp(12));
        LinearLayout head = row();
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.addView(text("CONNECTION LOGS", 12, ORANGE, true), new LinearLayout.LayoutParams(0, -2, 1));
        TextView clear = text("CLEAR", 11, ORANGE, true);
        clear.setPadding(dp(8), dp(6), dp(8), dp(6));
        clear.setOnClickListener(v -> { TunnelState.clearLog(); renderLog(); });
        head.addView(clear);
        ImageView copy = icon(R.drawable.ic_copy, 18, ORANGE);
        copy.setPadding(dp(4), dp(4), dp(4), dp(4));
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("log", TunnelState.logText()));
            Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show();
        });
        head.addView(copy, new LinearLayout.LayoutParams(dp(26), dp(26)));
        logs.addView(head);
        logView = text("", 11, TEXT, false);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(0, dp(8), 0, 0);
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setOnTouchListener((v, e) -> {
            if (e.getAction() == MotionEvent.ACTION_DOWN) v.getParent().requestDisallowInterceptTouchEvent(true);
            return false;
        });
        logs.addView(logView, new LinearLayout.LayoutParams(-1, dp(150)));
        body.addView(logs, mp(-1, -2, 0, 22, 0, 0));

        updateCards();
        renderLog();
        refreshHome();
    }

    private void updateCards() {
        for (int i = 0; i < 3; i++) {
            if (cardBox[i] == null) continue;
            boolean sel = PROTOCOLS[i].equals(protocol);
            cardBox[i].setBackground(sel ? shape(SOFT, ORANGE, 2, 12) : shape(CARD, BORDER, 1, 12));
            cardIcon[i].setColorFilter(sel ? ORANGE : TEXT);
            cardLabel[i].setTextColor(sel ? ORANGE : TEXT);
            cardBadge[i].setVisibility(sel ? View.VISIBLE : View.GONE);
        }
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() { refreshHome(); }
    };

    private void refreshHome() {
        if (discView == null) return;
        TunnelState.State st = TunnelState.state();
        boolean spinning = false;
        int dot = BORDER;
        switch (st) {
            case CONNECTED:
                ringView.setBackground(oval(blend(GREEN)));
                discView.setBackground(gradientOval(Color.rgb(46, 186, 116), Color.rgb(20, 138, 82)));
                discIcon.setImageResource(R.drawable.ic_check);
                discIcon.setColorFilter(Color.WHITE);
                discText.setText("CONNECTED");
                discText.setTextColor(Color.WHITE);
                dot = GREEN;
                break;
            case CONNECTING:
            case DISCONNECTING:
                ringView.setBackground(oval(blend(ORANGE)));
                discView.setBackground(shape(CARD, ORANGE, 4, 71));
                ((GradientDrawable) discView.getBackground()).setShape(GradientDrawable.OVAL);
                discIcon.setImageResource(R.drawable.ic_spinner);
                discIcon.setColorFilter(ORANGE);
                discText.setText(st == TunnelState.State.CONNECTING ? "CONNECTING..." : "STOPPING...");
                discText.setTextColor(ORANGE);
                spinning = true;
                break;
            case ERROR:
                ringView.setBackground(oval(blend(RED)));
                discView.setBackground(gradientOval(Color.rgb(250, 84, 88), Color.rgb(222, 40, 48)));
                discIcon.setImageResource(R.drawable.ic_alert);
                discIcon.setColorFilter(Color.WHITE);
                discText.setText("FAILED");
                discText.setTextColor(Color.WHITE);
                dot = RED;
                break;
            default:
                ringView.setBackground(oval(blend(Color.rgb(130, 50, 215))));
                discView.setBackground(gradientOval(Color.rgb(150, 70, 228), Color.rgb(104, 34, 196)));
                discIcon.setImageResource(R.drawable.ic_power);
                discIcon.setColorFilter(Color.WHITE);
                discText.setText("CONNECT");
                discText.setTextColor(Color.WHITE);
        }
        if (st == TunnelState.State.CONNECTED) {
            long secs = Math.max(0, (System.currentTimeMillis() - TunnelState.connectedAt()) / 1000);
            statusIcon.setImageResource(R.drawable.ic_server);
            statusIcon.setColorFilter(GREEN);
            statusText.setText(protocol + " \u2022 " + String.format(Locale.US, "%02d:%02d:%02d",
                    secs / 3600, (secs / 60) % 60, secs % 60));
            statusText.setTextColor(GREEN);
            ui.removeCallbacks(tick);
            ui.postDelayed(tick, 1000);
        } else if (st == TunnelState.State.ERROR) {
            statusIcon.setImageResource(R.drawable.ic_clock);
            statusIcon.setColorFilter(RED);
            String m = TunnelState.message();
            statusText.setText(m == null || m.isEmpty() ? "Connection timeout" : m);
            statusText.setTextColor(RED);
        } else if (spinning) {
            statusIcon.setImageResource(R.drawable.ic_server);
            statusIcon.setColorFilter(ORANGE);
            statusText.setText(protocol);
            statusText.setTextColor(ORANGE);
        } else {
            statusIcon.setImageResource(R.drawable.ic_server);
            statusIcon.setColorFilter(TEXT);
            statusText.setText("Protocol: " + protocol);
            statusText.setTextColor(TEXT);
        }

        dotView.setBackground(oval(dot));
        dotView.setVisibility(spinning ? View.GONE : View.VISIBLE);
        dotSpinner.setVisibility(spinning ? View.VISIBLE : View.GONE);
        spin(discIcon, spinning);
        spin(dotSpinner, spinning);
    }

    private void spin(View v, boolean on) {
        if (!on) { v.clearAnimation(); return; }
        if (v.getAnimation() != null) return;
        RotateAnimation a = new RotateAnimation(0, 360, Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f);
        a.setDuration(1100);
        a.setRepeatCount(Animation.INFINITE);
        a.setInterpolator(new LinearInterpolator());
        v.startAnimation(a);
    }

    private int blend(int c) {
        return Color.argb(45, Color.red(c), Color.green(c), Color.blue(c));
    }

    // ---- logs

    private boolean passesLogFilter(String line) {
        if (!"Errors only".equals(prefs.getString("logLevel", "Normal"))) return true;
        String l = line.toLowerCase(Locale.US);
        return l.contains("error") || l.contains("fail") || l.contains("stopped") || l.contains("refused")
                || l.contains("rejected") || l.contains("denied") || l.contains("lost");
    }

    private void renderLog() {
        if (logView == null) return;
        StringBuilder sb = new StringBuilder();
        for (String line : TunnelState.logText().split("\n")) {
            if (!line.isEmpty() && passesLogFilter(line)) sb.append(line).append('\n');
        }
        logView.setText(sb.toString());
        scrollLogToEnd();
    }

    private void scrollLogToEnd() {
        logView.post(() -> {
            if (logView == null || logView.getLayout() == null) return;
            int y = logView.getLayout().getLineTop(logView.getLineCount()) - logView.getHeight();
            logView.scrollTo(0, Math.max(y, 0));
        });
    }

    @Override
    public void onLog(String line) {
        if (logView == null || !passesLogFilter(line)) return;
        logView.append(line + "\n");
        scrollLogToEnd();
    }

    @Override
    public void onState(TunnelState.State state, String message) {
        if (state == TunnelState.State.CONNECTED) {
            wasConnected = true;
            autoRetrying = false;
            reconnectAttempts = 0;
        } else if (state == TunnelState.State.ERROR) {
            maybeAutoReconnect();
            wasConnected = false;
        } else if (state == TunnelState.State.DISCONNECTED) {
            wasConnected = false;
        }
        refreshHome();
    }

    private void maybeAutoReconnect() {
        if (userStopped || !prefs.getBoolean("autoReconnect", true)) return;
        if (!(wasConnected || autoRetrying) || reconnectAttempts >= 3) {
            autoRetrying = false;
            return;
        }
        reconnectAttempts++;
        autoRetrying = true;
        TunnelState.log("Auto reconnect in 3 s (attempt " + reconnectAttempts + "/3)");
        ui.postDelayed(() -> {
            TunnelState.State s = TunnelState.state();
            if (!userStopped && (s == TunnelState.State.ERROR || s == TunnelState.State.DISCONNECTED)
                    && VpnService.prepare(this) == null) {
                startConnect();
            }
        }, 3000);
    }

    // ================================================================== SSH CONFIGURATION PAGE

    private void buildSsh() {
        final String P = "SSH";
        final List<View> collapsible = new ArrayList<>();

        add(collapsible, section("SSH CREDENTIALS"));
        add(collapsible, rowField("Username", fieldSized(field(P, "user", "user123", ""))));
        final EditText pass = field(P, "pass", "password", "");
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setTypeface(Typeface.DEFAULT);
        pass.setPadding(dp(12), 0, dp(40), 0);
        final ImageView eye = icon(R.drawable.ic_eye, 20, MUTED);
        FrameLayout passBox = new FrameLayout(this);
        passBox.addView(pass, new FrameLayout.LayoutParams(-1, -1));
        FrameLayout.LayoutParams ep = new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.END | Gravity.CENTER_VERTICAL);
        ep.rightMargin = dp(12);
        passBox.addView(eye, ep);
        final boolean[] shown = {false};
        eye.setOnClickListener(v -> {
            shown[0] = !shown[0];
            pass.setTransformationMethod(shown[0] ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
            eye.setImageResource(shown[0] ? R.drawable.ic_eye_off : R.drawable.ic_eye);
            pass.setSelection(pass.getText().length());
        });
        add(collapsible, rowField("Password", passBox));

        add(collapsible, section("PROXY / SERVER"));
        add(collapsible, rowField("Proxy Host (WebSocket)", fieldSized(field(P, "proxyHost", "naruto.freessh.indevs.in", ""))));
        final boolean tls = "TLS".equals(p(P, "transport", "TLS"));
        final EditText proxyPort = field(P, "proxyPort", "443", tls ? "443" : "80");
        proxyPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        add(collapsible, rowField("Proxy Port", fieldSized(proxyPort)));

        add(collapsible, section("CONNECTION MODE"));
        final LinearLayout sniBox = stackField("SNI / Host", fieldSized(field(P, "sni", "naruto.freessh.indevs.in", "")));
        sniBox.setVisibility(tls ? View.VISIBLE : View.GONE);
        add(collapsible, segmented(new String[]{"TLS (SNI)", "Non-TLS"}, new String[]{"TLS", "Non-TLS"},
                p(P, "transport", "TLS"), value -> {
                    prefs.edit().putString(P + "_transport", value).apply();
                    boolean t = "TLS".equals(value);
                    sniBox.setVisibility(t ? View.VISIBLE : View.GONE);
                    String cur = proxyPort.getText().toString().trim();
                    if (cur.isEmpty() || cur.equals("443") || cur.equals("80")) proxyPort.setText(t ? "443" : "80");
                }));
        add(collapsible, sniBox);

        add(collapsible, section("WEBSOCKET"));
        add(collapsible, rowField("Path (optional)", fieldSized(field(P, "path", "/ws", "/ws"))));

        // PAYLOAD SECTION (Normal + Full-screen Expanded Editor)
        LinearLayout head = row();
        head.setGravity(Gravity.CENTER_VERTICAL);
        TextView ph = section("PAYLOAD");
        head.addView(ph, new LinearLayout.LayoutParams(0, -2, 1));
        final ImageView expand = icon(R.drawable.ic_expand, 18, ORANGE);
        expand.setPadding(dp(3), dp(3), dp(3), dp(3));
        head.addView(expand, new LinearLayout.LayoutParams(dp(26), dp(26)));
        body.addView(head);

        final EditText payload = payloadField();
        body.addView(payload, mp(-1, -2, 0, 0, 0, 0));

        // Clipboard toolbar for expanded payload editor (Select All, Cut, Copy, Paste)
        final LinearLayout clipboardBar = buildPayloadToolbar(payload);
        clipboardBar.setVisibility(View.GONE);
        body.addView(clipboardBar, mp(-1, -2, 0, 10, 0, 0));

        final TextView note = text("Placeholders: [crlf] [host] [host_port] [sni] [proxy] [split] ... Empty = standard WebSocket upgrade.", 11, MUTED, false);
        note.setPadding(0, dp(6), 0, dp(4));
        body.addView(note);

        final boolean[] expanded = {false};
        expand.setOnClickListener(v -> {
            expanded[0] = !expanded[0];
            expand.setImageResource(expanded[0] ? R.drawable.ic_collapse : R.drawable.ic_expand);
            for (View c : collapsible) c.setVisibility(expanded[0] ? View.GONE : View.VISIBLE);
            if (!expanded[0] && !"TLS".equals(p(P, "transport", "TLS"))) sniBox.setVisibility(View.GONE);
            clipboardBar.setVisibility(expanded[0] ? View.VISIBLE : View.GONE);
            note.setVisibility(expanded[0] ? View.GONE : View.VISIBLE);
            payload.setMinHeight(dp(expanded[0] ? 360 : 130));
            hideKeyboard();
        });

        addButtons(() -> {
            String[] keys = {"sshHost", "user", "pass", "proxyHost", "proxyPort", "sni", "path", "payload", "transport", "wsFrames"};
            SharedPreferences.Editor e = prefs.edit();
            for (String k : keys) e.remove(P + "_" + k);
            e.apply();
            Toast.makeText(this, "SSH settings reset", Toast.LENGTH_SHORT).show();
            show("ssh");
        });
    }

    private LinearLayout buildPayloadToolbar(final EditText payload) {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(0, dp(8), 0, dp(8));

        bar.addView(payloadActionButton(R.drawable.ic_select_all, "Select All", v -> payload.selectAll()),
                new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(payloadActionButton(R.drawable.ic_cut, "Cut", v -> {
            int start = payload.getSelectionStart();
            int end = payload.getSelectionEnd();
            if (start != end) {
                String sel = payload.getText().subSequence(Math.min(start, end), Math.max(start, end)).toString();
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("payload", sel));
                payload.getText().delete(Math.min(start, end), Math.max(start, end));
                Toast.makeText(this, "Cut to clipboard", Toast.LENGTH_SHORT).show();
            }
        }), new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(payloadActionButton(R.drawable.ic_copy, "Copy", v -> {
            int start = payload.getSelectionStart();
            int end = payload.getSelectionEnd();
            String sel = (start != end)
                    ? payload.getText().subSequence(Math.min(start, end), Math.max(start, end)).toString()
                    : payload.getText().toString();
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("payload", sel));
            Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show();
        }), new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(payloadActionButton(R.drawable.ic_paste, "Paste", v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence clip = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
                if (clip != null) {
                    int start = Math.max(0, payload.getSelectionStart());
                    int end = Math.max(0, payload.getSelectionEnd());
                    payload.getText().replace(Math.min(start, end), Math.max(start, end), clip);
                }
            }
        }), new LinearLayout.LayoutParams(0, -2, 1));
        return bar;
    }

    private View payloadActionButton(int iconRes, String label, View.OnClickListener action) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.VERTICAL);
        item.setGravity(Gravity.CENTER);
        item.setPadding(dp(6), dp(6), dp(6), dp(6));
        item.setBackground(shape(CARD, BORDER, 1, 8));
        item.addView(icon(iconRes, 20, TEXT));
        TextView t = text(label, 11, TEXT, false);
        t.setPadding(0, dp(4), 0, 0);
        item.addView(t);
        item.setOnClickListener(action);
        return item;
    }

    // ================================================================== VLESS / VMESS CONFIGURATION

    private void buildWsConfig(final String P) {
        body.addView(stackField("UUID", fieldSized(field(P, "uuid", "550e8400-e29b-41d4-a716-446655440000", ""))));
        body.addView(stackField("Server / Host Header", fieldSized(field(P, "server", "example.com", ""))));
        body.addView(stackField("Connect Host / IP", fieldSized(field(P, "connectIp", "1.2.3.4", ""))));
        EditText port = field(P, "port", "443", "443");
        port.setInputType(InputType.TYPE_CLASS_NUMBER);
        body.addView(stackField("Port", fieldSized(port)));

        body.addView(section("TRANSPORT"));
        final LinearLayout sniBox = stackField("SNI / Host", fieldSized(field(P, "sni", "example.com", "")));
        sniBox.setVisibility("TLS".equals(p(P, "transport", "TLS")) ? View.VISIBLE : View.GONE);
        body.addView(segmented(new String[]{"TLS", "Non-TLS"}, new String[]{"TLS", "Non-TLS"},
                p(P, "transport", "TLS"), value -> {
                    prefs.edit().putString(P + "_transport", value).apply();
                    sniBox.setVisibility("TLS".equals(value) ? View.VISIBLE : View.GONE);
                }));
        body.addView(sniBox);
        body.addView(stackField("WebSocket Path", fieldSized(field(P, "path", "/ws", "/ws"))));

        body.addView(section("ADVANCED"));
        LinearLayout ins = row();
        ins.setGravity(Gravity.CENTER_VERTICAL);
        ins.addView(text("Insecure TLS", 13, TEXT, false), new LinearLayout.LayoutParams(0, -2, 1));
        ins.addView(toggle(prefs.getBoolean(P + "_insecure", false),
                (b, on) -> prefs.edit().putBoolean(P + "_insecure", on).apply()));
        body.addView(ins, mp(-1, 40, 0, 0, 0, 0));
        body.addView(rowField("DNS", dnsDropdown()));

        addButtons(() -> {
            String[] keys = {"uuid", "server", "connectIp", "port", "sni", "path", "transport", "insecure"};
            SharedPreferences.Editor e = prefs.edit();
            for (String k : keys) e.remove(P + "_" + k);
            e.apply();
            Toast.makeText(this, P + " settings reset", Toast.LENGTH_SHORT).show();
            show(P.toLowerCase(Locale.US));
        });
    }

    // ================================================================== SETTINGS

    private void buildSettings() {
        body.addView(section("GENERAL"));
        body.addView(settingRow("Default DNS", dnsDropdown()));
        body.addView(settingRow("Log Level", dropdown(new String[]{"Normal", "Verbose", "Errors only"},
                prefs.getString("logLevel", "Normal"), v -> prefs.edit().putString("logLevel", v).apply())));

        body.addView(section("TLS"));
        final SwitchCompat verify = toggle(prefs.getBoolean("verifyCerts", true), null);
        final SwitchCompat insecure = toggle(prefs.getBoolean("allowInsecure", false), null);
        verify.setOnCheckedChangeListener((b, on) -> {
            prefs.edit().putBoolean("verifyCerts", on).apply();
            if (on && insecure.isChecked()) insecure.setChecked(false);
        });
        insecure.setOnCheckedChangeListener((b, on) -> {
            prefs.edit().putBoolean("allowInsecure", on).apply();
            if (on && verify.isChecked()) verify.setChecked(false);
        });
        body.addView(settingRow("Verify Certificates", verify));
        body.addView(settingRow("Allow Insecure TLS", insecure));

        body.addView(section("APP"));
        body.addView(settingRow("Auto Reconnect", toggle(prefs.getBoolean("autoReconnect", true),
                (b, on) -> prefs.edit().putBoolean("autoReconnect", on).apply())));
        body.addView(settingRow("Theme", dropdown(new String[]{"Light", "Dark"}, prefs.getString("theme", "Light"), v -> {
            if (v.equals(prefs.getString("theme", "Light"))) return;
            prefs.edit().putString("theme", v).apply();
            recreate();
        })));

        Button reset = outlineButton("RESET TO DEFAULTS");
        reset.setOnClickListener(v -> {
            boolean themeChanged = !"Light".equals(prefs.getString("theme", "Light"));
            prefs.edit().remove("dns").remove("logLevel").remove("verifyCerts").remove("allowInsecure")
                    .remove("autoReconnect").remove("theme").apply();
            Toast.makeText(this, "Settings reset", Toast.LENGTH_SHORT).show();
            if (themeChanged) recreate(); else show("settings");
        });
        body.addView(reset, mp(-1, 48, 0, 26, 0, 0));
    }

    private View dnsDropdown() {
        String cur = prefs.getString("dns", "8.8.8.8");
        List<String> opts = new ArrayList<>(Arrays.asList(DNS_PRESETS));
        if (!opts.contains(cur)) opts.add(0, cur);
        return dropdown(opts.toArray(new String[0]), cur, v -> prefs.edit().putString("dns", v).apply());
    }

    // ================================================================== connect / validation

    private String p(String proto, String key, String def) {
        return prefs.getString(proto + "_" + key, def);
    }

    private boolean tlsOn(String proto) { return "TLS".equals(p(proto, "transport", "TLS")); }

    private boolean insecureFor(String proto) {
        return prefs.getBoolean("allowInsecure", false) || prefs.getBoolean(proto + "_insecure", false);
    }

    private int intOr(String s, int def) {
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return def; }
    }

    private ProtocolConfig sshConfig() {
        final String P = "SSH";
        ProtocolConfig pc = new ProtocolConfig();
        pc.sshUser = p(P, "user", "").trim();
        pc.sshPassword = p(P, "pass", "");
        pc.sshHost = p(P, "sshHost", "").trim();
        pc.sshPort = 22;
        pc.proxyHost = p(P, "proxyHost", "").trim();
        pc.tls = tlsOn(P);
        pc.proxyPort = intOr(p(P, "proxyPort", pc.tls ? "443" : "80"), 0);
        pc.sni = p(P, "sni", "").trim();
        if (pc.sni.isEmpty()) pc.sni = pc.proxyHost;
        pc.path = p(P, "path", "/ws").trim();
        pc.payload = p(P, "payload", "");
        return pc;
    }

    private String validateStored() {
        try {
            if ("SSH".equals(protocol)) {
                return ProtocolRegistry.require("SSH").validate(sshConfig());
            }
            ProtocolConfig pc = new ProtocolConfig();
            pc.uuid = p(protocol, "uuid", "");
            String err = ProtocolRegistry.require(protocol).validate(pc);
            if (err != null) return err;
            int port = intOr(p(protocol, "port", "443"), -1);
            if (port < 1 || port > 65535) return "Port must be 1-65535";
            if (tlsOn(protocol) && p(protocol, "sni", "").trim().isEmpty()) return "SNI host is empty";
            if (p(protocol, "server", "").trim().isEmpty()) return "Host header is empty";
            if (p(protocol, "connectIp", "").trim().isEmpty()) return "Connect IP is empty";
            return null;
        } catch (java.io.IOException e) {
            return e.getMessage();
        }
    }

    private Intent buildIntent() {
        Intent intent = new Intent(this, TunnelVpnService.class);
        intent.setAction(TunnelVpnService.ACTION_START);
        intent.putExtra("dns", prefs.getString("dns", "8.8.8.8"));
        intent.putExtra("insecure", insecureFor(protocol));
        intent.putExtra("transport", tlsOn(protocol) ? "TLS" : "Non-TLS");
        intent.putExtra("protocol", protocol);
        if ("SSH".equals(protocol)) {
            ProtocolConfig s = sshConfig();
            intent.putExtra("bug", s.sni);
            intent.putExtra("sshUser", s.sshUser);
            intent.putExtra("sshPass", s.sshPassword);
            intent.putExtra("sshHost", s.sshHost);
            intent.putExtra("sshPort", s.sshPort);
            intent.putExtra("path", s.path);
            intent.putExtra("payload", s.payload);
            intent.putExtra("proxyHost", s.proxyHost);
            intent.putExtra("proxyPort", s.proxyPort);
            intent.putExtra("wsFrames", prefs.getBoolean("SSH_wsFrames", false));
        } else {
            intent.putExtra("uuid", p(protocol, "uuid", "").trim());
            intent.putExtra("server", p(protocol, "server", "").trim());
            intent.putExtra("connectIp", p(protocol, "connectIp", "").trim());
            intent.putExtra("port", intOr(p(protocol, "port", "443"), 443));
            intent.putExtra("bug", p(protocol, "sni", "").trim());
            intent.putExtra("path", p(protocol, "path", "").trim());
        }
        return intent;
    }

    private void onButton() {
        TunnelState.State state = TunnelState.state();
        if (state == TunnelState.State.CONNECTED || state == TunnelState.State.CONNECTING) {
            userStopped = true;
            autoRetrying = false;
            Intent stop = new Intent(this, TunnelVpnService.class);
            stop.setAction(TunnelVpnService.ACTION_STOP);
            startService(stop);
            return;
        }
        if (state == TunnelState.State.DISCONNECTING) return;
        userStopped = false;
        autoRetrying = false;
        reconnectAttempts = 0;
        startConnect();
    }

    private void startConnect() {
        String err = validateStored();
        if (err != null) {
            TunnelState.log("Input error: " + err);
            TunnelState.set(TunnelState.State.ERROR, err);
            return;
        }
        pendingStart = buildIntent();
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this,
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS);
        } else {
            askVpnPermission();
        }
    }

    private void askVpnPermission() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) vpnPermission.launch(prepare);
        else launch();
    }

    private void launch() {
        if (pendingStart == null) return;
        Intent intent = pendingStart;
        pendingStart = null;
        ContextCompat.startForegroundService(this, intent);
    }

    // ================================================================== UI HELPERS

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private LinearLayout row() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        return l;
    }

    private LinearLayout.LayoutParams mp(int w, int h, int l, int t, int r, int b) {
        return mp(w, h, l, t, r, b, 0);
    }

    private LinearLayout.LayoutParams mp(int w, int h, int l, int t, int r, int b, float weight) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w > 0 ? dp(w) : w, h > 0 ? dp(h) : h, weight);
        p.setMargins(dp(l), dp(t), dp(r), dp(b));
        return p;
    }

    private GradientDrawable shape(int fill, int stroke, int strokeDp, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(radiusDp));
        if (strokeDp > 0) g.setStroke(dp(strokeDp), stroke);
        return g;
    }

    private GradientDrawable oval(int color) {
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        g.setColor(color);
        return g;
    }

    private GradientDrawable gradientOval(int top, int bottom) {
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{top, bottom});
        g.setShape(GradientDrawable.OVAL);
        return g;
    }

    private TextView text(String t, int sp, int color, boolean bold) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(sp);
        v.setTextColor(color);
        if (bold) v.setTypeface(null, Typeface.BOLD);
        return v;
    }

    private ImageView icon(int res, int sizeDp, int color) {
        ImageView v = new ImageView(this);
        v.setImageResource(res);
        v.setColorFilter(color);
        v.setLayoutParams(new LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)));
        return v;
    }

    private TextView section(String t) {
        TextView v = text(t, 11, ORANGE, true);
        v.setLetterSpacing(0.06f);
        v.setPadding(0, dp(18), 0, dp(8));
        return v;
    }

    private void add(List<View> list, View v) {
        body.addView(v);
        list.add(v);
    }

    private EditText field(String proto, String key, String hint, String def) {
        final String k = proto + "_" + key;
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setText(prefs.getString(k, def));
        e.setSingleLine(true);
        e.setTextColor(TEXT);
        e.setHintTextColor(MUTED);
        e.setTextSize(14);
        e.setBackground(shape(CARD, BORDER, 1, 8));
        e.setPadding(dp(12), 0, dp(12), 0);
        e.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                prefs.edit().putString(k, s.toString()).apply();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
        return e;
    }

    private EditText fieldSized(EditText e) {
        e.setLayoutParams(new LinearLayout.LayoutParams(-1, dp(44)));
        return e;
    }

    private LinearLayout stackField(String label, View field) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.addView(text(label, 12, TEXT, false), mp(-2, -2, 2, 10, 0, 6));
        if (field.getLayoutParams() == null) field.setLayoutParams(new LinearLayout.LayoutParams(-1, dp(44)));
        l.addView(field);
        return l;
    }

    private LinearLayout rowField(String label, View field) {
        LinearLayout r = row();
        r.setGravity(Gravity.CENTER_VERTICAL);
        TextView t = text(label, 12, TEXT, false);
        r.addView(t, new LinearLayout.LayoutParams(dp(140), -2));
        r.addView(field, new LinearLayout.LayoutParams(0, dp(42), 1));
        r.setPadding(0, dp(4), 0, dp(4));
        return r;
    }

    private LinearLayout settingRow(String label, View control) {
        LinearLayout r = row();
        r.setGravity(Gravity.CENTER_VERTICAL);
        r.addView(text(label, 14, TEXT, false), new LinearLayout.LayoutParams(0, -2, 1));
        if (control instanceof FrameLayout) r.addView(control, new LinearLayout.LayoutParams(dp(150), dp(42)));
        else r.addView(control);
        r.setPadding(0, dp(7), 0, dp(7));
        return r;
    }

    private EditText payloadField() {
        final String k = "SSH_payload";
        EditText e = new EditText(this);
        e.setHint("GET /ws HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]");
        e.setText(prefs.getString(k, ""));
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setSingleLine(false);
        e.setHorizontallyScrolling(false);
        e.setMinHeight(dp(130));
        e.setMaxLines(Integer.MAX_VALUE);
        e.setGravity(Gravity.TOP | Gravity.START);
        e.setTypeface(Typeface.MONOSPACE);
        e.setTextColor(TEXT);
        e.setHintTextColor(MUTED);
        e.setTextSize(12);
        e.setPadding(dp(12), dp(10), dp(12), dp(10));
        e.setBackground(shape(CARD, BORDER, 1, 8));
        e.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                prefs.edit().putString(k, s.toString()).apply();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
        return e;
    }

    private View segmented(final String[] labels, final String[] values, String selected, final Pick pick) {
        LinearLayout box = row();
        box.setBackground(shape(CARD, BORDER, 1, 8));
        final TextView[] segs = new TextView[labels.length];
        final String[] cur = {selected};
        for (int i = 0; i < labels.length; i++) {
            final int idx = i;
            segs[i] = text(labels[i], 13, TEXT, true);
            segs[i].setGravity(Gravity.CENTER);
            segs[i].setOnClickListener(v -> {
                cur[0] = values[idx];
                paintSegments(segs, values, cur[0]);
                pick.on(values[idx]);
            });
            box.addView(segs[i], new LinearLayout.LayoutParams(0, dp(42), 1));
        }
        paintSegments(segs, values, cur[0]);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(2), 0, dp(6));
        box.setLayoutParams(lp);
        return box;
    }

    private void paintSegments(TextView[] segs, String[] values, String sel) {
        for (int i = 0; i < segs.length; i++) {
            boolean on = values[i].equals(sel);
            segs[i].setBackground(on ? shape(ORANGE, 0, 0, 8) : null);
            segs[i].setTextColor(on ? Color.WHITE : TEXT);
        }
    }

    private View dropdown(final String[] opts, String selected, final Pick pick) {
        FrameLayout box = new FrameLayout(this);
        box.setBackground(shape(CARD, BORDER, 1, 8));
        final Spinner sp = new Spinner(this);
        sp.setBackground(null);
        ArrayAdapter<String> ad = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, opts) {
            @Override public View getView(int pos, View cv, ViewGroup parent) {
                TextView t = (TextView) super.getView(pos, cv, parent);
                t.setTextColor(TEXT);
                t.setTextSize(13);
                t.setPadding(dp(10), 0, dp(28), 0);
                return t;
            }
            @Override public View getDropDownView(int pos, View cv, ViewGroup parent) {
                TextView t = (TextView) super.getDropDownView(pos, cv, parent);
                t.setTextColor(TEXT);
                t.setTextSize(14);
                t.setBackgroundColor(CARD);
                t.setPadding(dp(14), dp(12), dp(14), dp(12));
                return t;
            }
        };
        sp.setAdapter(ad);
        sp.setSelection(Math.max(0, Arrays.asList(opts).indexOf(selected)));
        sp.setPopupBackgroundDrawable(shape(CARD, BORDER, 1, 8));
        final boolean[] first = {true};
        sp.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                if (first[0]) { first[0] = false; return; }
                pick.on(opts[pos]);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });
        box.addView(sp, new FrameLayout.LayoutParams(-1, -1));
        FrameLayout.LayoutParams cp = new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.END | Gravity.CENTER_VERTICAL);
        cp.rightMargin = dp(8);
        box.addView(icon(R.drawable.ic_chevron, 20, MUTED), cp);
        return box;
    }

    private SwitchCompat toggle(boolean on, CompoundButton.OnCheckedChangeListener l) {
        SwitchCompat s = new SwitchCompat(this);
        s.setChecked(on);
        int[][] st = {{android.R.attr.state_checked}, {}};
        s.setThumbTintList(new ColorStateList(st, new int[]{Color.WHITE, Color.WHITE}));
        s.setTrackTintList(new ColorStateList(st, new int[]{ORANGE, Color.rgb(200, 200, 206)}));
        if (l != null) s.setOnCheckedChangeListener(l);
        return s;
    }

    private Button outlineButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(13);
        b.setTypeface(null, Typeface.BOLD);
        b.setTextColor(ORANGE);
        b.setBackground(shape(CARD, ORANGE, 1, 8));
        return b;
    }

    private void addButtons(Runnable reset) {
        LinearLayout r = row();
        Button rb = outlineButton("RESET");
        rb.setOnClickListener(v -> reset.run());
        Button sb = new Button(this);
        sb.setText("SAVE CONFIGURATION");
        sb.setAllCaps(false);
        sb.setTextSize(13);
        sb.setTypeface(null, Typeface.BOLD);
        sb.setTextColor(Color.WHITE);
        sb.setBackground(shape(ORANGE, 0, 0, 8));
        sb.setOnClickListener(v -> saveAndHome());
        r.addView(rb, mp(0, 46, 0, 0, 8, 0, 1));
        r.addView(sb, mp(0, 46, 0, 0, 0, 0, 1.6f));
        body.addView(r, mp(-1, -2, 0, 22, 0, 0));
    }

    private void hideKeyboard() {
        View f = getCurrentFocus();
        if (f == null) return;
        InputMethodManager im = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (im != null) im.hideSoftInputFromWindow(f.getWindowToken(), 0);
        f.clearFocus();
    }
}

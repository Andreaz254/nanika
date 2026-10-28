package com.example.tunnel;

import android.Manifest;
import android.animation.LayoutTransition;
import android.annotation.SuppressLint;
import android.app.DatePickerDialog;
import android.app.Dialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.provider.Settings;
import android.text.InputType;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.text.style.URLSpan;
import android.text.util.Linkify;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.LinkMovementMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.method.ScrollingMovementMethod;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.OvershootInterpolator;
import android.view.animation.RotateAnimation;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;

import androidx.core.content.FileProvider;

import com.example.tunnel.config.ConfigIO;
import com.example.tunnel.ssh.InjectPayloads;
import com.example.tunnel.update.UpdateManager;
import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.ProtocolRegistry;
import com.example.tunnel.ui.ConnectButton;
import com.example.tunnel.ui.GlyphDrawable;
import com.example.tunnel.ui.HtmlText;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Nanika UI (light/dark): Home (connect circle, protocol cards, expiry / message), Logs page, drawer, one
 * configuration page per protocol (SSH / VLESS / VMess) and Settings. Every field is saved to SharedPreferences as it is typed; the
 * service is started from those saved values.
 */
public class MainActivity extends AppCompatActivity implements TunnelState.Listener {

    private static final int ORANGE = Color.rgb(242, 107, 33);
    private static final int GREEN = Color.rgb(30, 160, 98);
    private static final int RED = Color.rgb(238, 56, 62);
    private static final String[] PROTOCOLS = {"SSH", "VLESS", "VMess"};
    private static final String[] DNS_PRESETS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"};

    private interface Pick { void on(String value); }

    // theme colours (set by applyTheme)
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

    // home widgets (null while another page is shown)
    private ConnectButton connectBtn;
    private ImageView statusIcon;
    private TextView statusText;
    private View dotView;
    private ImageView dotSpinner;
    private TextView logView;
    private LinearLayout noticeBox;
    private LinearLayout bannerCard;
    private TextView bannerText;
    private String shownBanner;
    private boolean logPlaceholder;
    private int renderedLines;
    private byte[] pendingExportData;
    private String pendingImportProto;

    // ---- forced update
    private boolean updateRequired;
    private UpdateManager.Info pendingUpdate;
    private final int[] cardGlyph = {GlyphDrawable.SSH, GlyphDrawable.VLESS, GlyphDrawable.VMESS};
    private String shownProtocol;
    private boolean payloadExpanded;
    private LayoutTransition bodyTransition;
    private float dragX0, dragY0;
    private boolean dragTracking;
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

    private final ActivityResultLauncher<Intent> exportLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                byte[] data = pendingExportData;
                pendingExportData = null;
                Intent r = result.getData();
                if (result.getResultCode() != RESULT_OK || r == null || r.getData() == null || data == null) return;
                try (OutputStream out = getContentResolver().openOutputStream(r.getData())) {
                    if (out == null) throw new java.io.IOException("cannot open the file");
                    out.write(data);
                    out.flush();
                    toast("Configuration exported");
                } catch (Exception e) {
                    toast("Export failed: " + e.getMessage());
                }
            });

    private final ActivityResultLauncher<Intent> importLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                String proto = pendingImportProto;
                pendingImportProto = null;
                Intent r = result.getData();
                if (result.getResultCode() != RESULT_OK || r == null || r.getData() == null || proto == null) return;
                importFromUri(proto, r.getData());
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

    @Override
    public boolean dispatchTouchEvent(MotionEvent e) {
        int a = e.getActionMasked();
        if (a == MotionEvent.ACTION_DOWN) {
            dragX0 = e.getRawX();
            dragY0 = e.getRawY();
            dragTracking = true;
        } else if (a == MotionEvent.ACTION_MOVE && dragTracking) {
            float dx = e.getRawX() - dragX0, dy = e.getRawY() - dragY0;
            boolean horizontal = Math.abs(dx) > Math.abs(dy) * 1.6f;
            boolean open = drawer.getVisibility() == View.VISIBLE;
            boolean openIt = !open && "home".equals(page) && dragX0 < dp(110) && dx > dp(56) && horizontal;
            boolean closeIt = open && dx < -dp(64) && horizontal;
            boolean toLogs = !open && "home".equals(page) && dx < -dp(90) && horizontal;
            boolean toHome = !open && "logs".equals(page) && dx > dp(90) && horizontal
                    && !(logView != null && logView.hasSelection());
            if (toLogs || toHome) {
                dragTracking = false;
                MotionEvent cancel = MotionEvent.obtain(e);
                cancel.setAction(MotionEvent.ACTION_CANCEL);
                super.dispatchTouchEvent(cancel);
                cancel.recycle();
                show(toLogs ? "logs" : "home");
                return true;
            }
            if (openIt || closeIt) {
                dragTracking = false;
                MotionEvent cancel = MotionEvent.obtain(e);
                cancel.setAction(MotionEvent.ACTION_CANCEL);
                super.dispatchTouchEvent(cancel);
                cancel.recycle();
                if (openIt) openDrawer(); else closeDrawer();
                return true;
            }
        } else if (a == MotionEvent.ACTION_UP || a == MotionEvent.ACTION_CANCEL) {
            dragTracking = false;
        }
        return super.dispatchTouchEvent(e);
    }

    private void applyTheme() {
        boolean dark = "Dark".equals(prefs.getString("theme", "Light"));
        BG = dark ? Color.rgb(20, 22, 28) : Color.rgb(255, 248, 240);
        CARD = dark ? Color.rgb(31, 34, 43) : Color.WHITE;
        TEXT = dark ? Color.rgb(242, 242, 245) : Color.rgb(30, 30, 36);
        MUTED = dark ? Color.rgb(154, 156, 168) : Color.rgb(125, 125, 135);
        BORDER = dark ? Color.rgb(58, 61, 74) : Color.rgb(228, 221, 212);
        SOFT = dark ? Color.rgb(58, 40, 30) : Color.rgb(255, 235, 218);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().setBackgroundDrawable(new ColorDrawable(BG));
        getWindow().getDecorView().setSystemUiVisibility(dark ? 0
                : (View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR));
    }

    // ================================================================== shell: toolbar, body, drawer

    private void buildShell() {
        root = new FrameLayout(this);
        root.setBackgroundColor(BG);

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        toolbarHolder = new FrameLayout(this);
        column.addView(toolbarHolder, new LinearLayout.LayoutParams(-1, -2));

        scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setClipChildren(false);
        body = new LinearLayout(this);
        body.setClipChildren(false);
        body.setOrientation(LinearLayout.VERTICAL);
        bodyTransition = new LayoutTransition();
        bodyTransition.enableTransitionType(LayoutTransition.CHANGING);
        bodyTransition.setDuration(220);
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
        checkForUpdate();
    }

    private void openDrawer() {
        refreshDrawer();
        scrim.setAlpha(0f);
        scrim.setVisibility(View.VISIBLE);
        scrim.animate().alpha(1f).setDuration(240).start();
        drawer.setTranslationX(-dp(290));
        drawer.setVisibility(View.VISIBLE);
        drawer.animate().translationX(0).setDuration(260).setInterpolator(new DecelerateInterpolator(1.8f)).start();
        for (int i = 0; i < drawer.getChildCount(); i++) {
            View v = drawer.getChildAt(i);
            v.setAlpha(0f);
            v.setTranslationX(-dp(22));
            v.animate().alpha(1f).translationX(0).setStartDelay(60L + i * 35L).setDuration(260)
                    .setInterpolator(new DecelerateInterpolator(1.6f)).start();
        }
    }

    private void closeDrawer() {
        scrim.animate().alpha(0f).setDuration(160).withEndAction(() -> scrim.setVisibility(View.GONE)).start();
        drawer.animate().translationX(-dp(290)).setDuration(200).setInterpolator(new DecelerateInterpolator())
                .withEndAction(() -> drawer.setVisibility(View.GONE)).start();
    }

    private void refreshDrawer() {
        drawer.removeAllViews();
        LinearLayout head = row();
        head.setGravity(Gravity.CENTER_VERTICAL);
        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.nanika_logo);
        head.addView(logo, new LinearLayout.LayoutParams(dp(40), dp(40)));
        LinearLayout names = new LinearLayout(this);
        names.setOrientation(LinearLayout.VERTICAL);
        names.setPadding(dp(12), 0, 0, 0);
        names.addView(text(getString(R.string.app_name), 20, TEXT, true));
        names.addView(text("Secure \u2022 Fast \u2022 Private", 12, MUTED, false));
        head.addView(names);
        drawer.addView(head, mp(-1, -2, 0, 0, 0, 22));

        drawerItem(R.drawable.ic_home, -1, "Home", "home");
        drawerItem(0, GlyphDrawable.SSH, "SSH", "ssh");
        drawerItem(0, GlyphDrawable.VLESS, "VLESS", "vless");
        drawerItem(0, GlyphDrawable.VMESS, "VMess", "vmess");
        drawerItem(R.drawable.ic_terminal, -1, "Logs", "logs");
        View line = new View(this);
        line.setBackgroundColor(BORDER);
        drawer.addView(line, mp(-1, 1, 6, 14, 6, 14));
        drawerItem(R.drawable.ic_gear, -1, "Settings", "settings");
    }

    private void drawerItem(int iconRes, int glyphKind, String label, final String target) {
        boolean sel = target.equals(page);
        LinearLayout item = row();
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(dp(14), 0, dp(14), 0);
        item.setBackground(rippled(sel ? shape(SOFT, 0, 0, 12) : null, 12));
        item.addView(glyphKind >= 0 ? glyph(glyphKind, 24, sel ? ORANGE : TEXT) : icon(iconRes, 24, sel ? ORANGE : TEXT));
        TextView t = text(label, 16, TEXT, sel);
        t.setPadding(dp(18), 0, 0, 0);
        item.addView(t);
        item.setOnClickListener(v -> {
            closeDrawer();
            if (target.equals("ssh")) selectProtocol("SSH");
            else if (target.equals("vless")) selectProtocol("VLESS");
            else if (target.equals("vmess")) selectProtocol("VMess");
            show(target);
        });
        drawer.addView(item, mp(-1, 52, 0, 2, 0, 2));
    }

    private View homeBar() {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(18), dp(6));
        ImageView menu = icon(R.drawable.ic_menu, 28, ORANGE);
        menu.setOnClickListener(v -> openDrawer());
        pressable(menu, 0.88f);
        bar.addView(menu);
        TextView title = text(getString(R.string.app_name), 20, TEXT, true);
        title.setPadding(dp(18), 0, 0, 0);
        bar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        FrameLayout dot = new FrameLayout(this);
        dotView = new View(this);
        FrameLayout.LayoutParams dp1 = new FrameLayout.LayoutParams(dp(14), dp(14));
        dp1.gravity = Gravity.CENTER;
        dot.addView(dotView, dp1);
        dotSpinner = icon(R.drawable.ic_spinner, 20, ORANGE);
        dot.addView(dotSpinner, new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.CENTER));
        bar.addView(dot, new LinearLayout.LayoutParams(dp(24), dp(24)));
        TextView logsBtn = text("LOGS", 12, Color.WHITE, true);
        logsBtn.setLetterSpacing(0.08f);
        logsBtn.setGravity(Gravity.CENTER);
        logsBtn.setPadding(dp(14), 0, dp(14), 0);
        logsBtn.setBackground(new RippleDrawable(ColorStateList.valueOf(0x44FFFFFF),
                shape(ORANGE, 0, 0, 4), shape(Color.WHITE, 0, 0, 4)));
        logsBtn.setOnClickListener(v -> show("logs"));
        pressable(logsBtn, 0.92f);
        bar.addView(logsBtn, mp(-2, 32, 12, 0, 0, 0));
        return bar;
    }

    private View pageBar(String title, View.OnClickListener moreAction) {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(18), dp(6));
        ImageView back = icon(R.drawable.ic_back, 26, ORANGE);
        back.setOnClickListener(v -> show("home"));
        pressable(back, 0.88f);
        bar.addView(back);
        TextView t = text(title, 18, TEXT, true);
        t.setPadding(dp(18), 0, 0, 0);
        bar.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        if (moreAction != null) {
            ImageView more = icon(R.drawable.ic_more, 26, ORANGE);
            more.setPadding(dp(2), dp(2), dp(2), dp(2));
            more.setOnClickListener(moreAction);
            pressable(more, 0.88f);
            bar.addView(more);
        }
        return bar;
    }

    private View logsBar() {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(18), dp(6));
        ImageView back = icon(R.drawable.ic_back, 26, ORANGE);
        back.setOnClickListener(v -> show("home"));
        pressable(back, 0.88f);
        bar.addView(back);
        TextView t = text("Logs", 18, TEXT, true);
        t.setPadding(dp(18), 0, 0, 0);
        bar.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        ImageView copy = icon(R.drawable.ic_copy, 20, ORANGE);
        copy.setPadding(dp(3), dp(3), dp(3), dp(3));
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            StringBuilder all = new StringBuilder();
            String b = TunnelState.banner();
            if (!b.isEmpty()) all.append("--- server banner ---\n").append(HtmlText.plain(b)).append("\n---\n");
            all.append(TunnelState.logText());
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("log", all.toString()));
            toast("Logs copied");
        });
        pressable(copy, 0.9f);
        bar.addView(copy, new LinearLayout.LayoutParams(dp(28), dp(28)));
        TextView clear = text("CLEAR", 12, ORANGE, true);
        clear.setPadding(dp(12), dp(6), dp(2), dp(6));
        clear.setOnClickListener(v -> {
            TunnelState.clearLog();
            shownBanner = null;
            renderLog();
            updateBanner();
        });
        bar.addView(clear);
        return bar;
    }

    private void show(String target) {
        page = target;
        clearHomeRefs();
        toolbarHolder.removeAllViews();
        body.removeAllViews();
        hideKeyboard();
        body.setLayoutTransition(null);
        if ("home".equals(target)) {
            toolbarHolder.addView(homeBar());
            buildHome();
        } else if ("logs".equals(target)) {
            toolbarHolder.addView(logsBar());
            buildLogs();
        } else if ("ssh".equals(target)) {
            toolbarHolder.addView(pageBar("SSH Configuration", v -> showConfigMenu(v, "SSH")));
            buildSsh();
        } else if ("vless".equals(target)) {
            toolbarHolder.addView(pageBar("VLESS Configuration", v -> showConfigMenu(v, "VLESS")));
            buildWsConfig("VLESS");
        } else if ("vmess".equals(target)) {
            toolbarHolder.addView(pageBar("VMess Configuration", v -> showConfigMenu(v, "VMess")));
            buildWsConfig("VMess");
        } else {
            toolbarHolder.addView(pageBar("Settings", null));
            buildSettings();
        }
        scroll.scrollTo(0, 0);
        animateIn();
        if (!"logs".equals(target)) body.post(() -> body.setLayoutTransition(bodyTransition));
    }

    /** Page entrance: toolbar fades in, content rises in a short stagger. */
    private void animateIn() {
        toolbarHolder.setAlpha(0f);
        toolbarHolder.animate().alpha(1f).setDuration(200).start();
        for (int i = 0; i < body.getChildCount(); i++) {
            View v = body.getChildAt(i);
            v.setAlpha(0f);
            v.setTranslationY(dp(16));
            v.animate().alpha(1f).translationY(0).setStartDelay(Math.min(i * 30L, 300L)).setDuration(280)
                    .setInterpolator(new DecelerateInterpolator(1.7f)).start();
        }
    }

    private void clearHomeRefs() {
        connectBtn = null; statusIcon = null;
        statusText = null; dotView = null; dotSpinner = null; logView = null;
        noticeBox = null; bannerCard = null; bannerText = null; shownBanner = null;
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
        connectBtn = new ConnectButton(this, CARD, SOFT);
        connectBtn.setOnClickListener(v -> onButton());
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(dp(200), dp(200));
        hp.gravity = Gravity.CENTER_HORIZONTAL;
        hp.topMargin = dp(8);
        body.addView(connectBtn, hp);

        LinearLayout status = row();
        status.setGravity(Gravity.CENTER);
        statusIcon = icon(R.drawable.ic_server, 16, TEXT);
        statusText = text("", 13, TEXT, false);
        statusText.setPadding(dp(8), 0, 0, 0);
        status.addView(statusIcon);
        status.addView(statusText);
        body.addView(status, mp(-1, -2, 0, 6, 0, 22));

        body.addView(text("CHOOSE PROTOCOL", 12, TEXT, true), mp(-2, -2, 2, 0, 0, 8));
        LinearLayout cards = row();
        cards.setClipChildren(false);
        for (int i = 0; i < 3; i++) {
            final String name = PROTOCOLS[i];
            final int idx = i;
            FrameLayout cell = new FrameLayout(this);
            cell.setClipChildren(false);
            cardBox[i] = new LinearLayout(this);
            cardBox[i].setOrientation(LinearLayout.VERTICAL);
            cardBox[i].setGravity(Gravity.CENTER);
            cardBox[i].setElevation(dp(2));
            cardIcon[i] = glyph(cardGlyph[i], 30, TEXT);
            cardLabel[i] = text(name, 13, TEXT, false);
            cardBox[i].addView(cardIcon[i]);
            cardBox[i].addView(cardLabel[i], mp(-2, -2, 0, 8, 0, 0));
            cell.addView(cardBox[i], new FrameLayout.LayoutParams(-1, -1));
            FrameLayout badge = new FrameLayout(this);
            badge.setBackground(oval(ORANGE));
            badge.setElevation(dp(3));
            badge.addView(icon(R.drawable.ic_check, 14, Color.WHITE), new FrameLayout.LayoutParams(dp(14), dp(14), Gravity.CENTER));
            cardBadge[i] = badge;
            FrameLayout.LayoutParams bp = new FrameLayout.LayoutParams(dp(22), dp(22), Gravity.TOP | Gravity.END);
            bp.setMargins(0, dp(6), dp(6), 0);
            cell.addView(badge, bp);
            cell.setOnClickListener(v -> {
                boolean changed = !name.equals(protocol);
                selectProtocol(name);
                updateCards(changed && name.equals(protocol));
                renderNotice();
                refreshHome();
            });
            pressable(cell, 0.95f);
            cards.addView(cell, mp(0, 88, i == 0 ? 0 : 5, 0, i == 2 ? 0 : 5, 0, 1));
        }
        body.addView(cards);

        noticeBox = new LinearLayout(this);
        noticeBox.setOrientation(LinearLayout.VERTICAL);
        body.addView(noticeBox, mp(-1, -2, 0, 20, 0, 0));

        shownProtocol = null;
        updateCards(false);
        renderNotice();
        refreshHome();
    }

    private void updateCards(boolean animate) {
        for (int i = 0; i < 3; i++) {
            if (cardBox[i] == null) continue;
            boolean sel = PROTOCOLS[i].equals(protocol);
            cardBox[i].setBackground(rippled(sel ? shape(SOFT, ORANGE, 2, 12) : shape(CARD, BORDER, 1, 12), 12));
            cardBox[i].setElevation(dp(sel ? 4 : 2));
            cardIcon[i].setColorFilter(sel ? ORANGE : TEXT);
            cardLabel[i].setTextColor(sel ? ORANGE : TEXT);
            cardBadge[i].setVisibility(sel ? View.VISIBLE : View.GONE);
            if (sel && animate && !PROTOCOLS[i].equals(shownProtocol)) {
                cardBox[i].setScaleX(0.9f);
                cardBox[i].setScaleY(0.9f);
                cardBox[i].animate().scaleX(1f).scaleY(1f).setDuration(320)
                        .setInterpolator(new OvershootInterpolator(2.4f)).start();
                cardBadge[i].setScaleX(0f);
                cardBadge[i].setScaleY(0f);
                cardBadge[i].animate().scaleX(1f).scaleY(1f).setStartDelay(60).setDuration(300)
                        .setInterpolator(new OvershootInterpolator(3f)).start();
            }
        }
        shownProtocol = protocol;
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            refreshHome();
        }
    };

    private void refreshHome() {
        if (connectBtn == null) return;
        TunnelState.State st = TunnelState.state();
        boolean spinning = false;
        int dot = TEXT;
        int look;
        switch (st) {
            case CONNECTED:
                look = ConnectButton.CONNECTED;
                dot = GREEN;
                break;
            case CONNECTING:
            case DISCONNECTING:
                look = ConnectButton.CONNECTING;
                spinning = true;
                break;
            case ERROR:
                look = ConnectButton.FAILED;
                dot = RED;
                break;
            default:
                look = ConnectButton.IDLE;
        }
        connectBtn.setState(look, true);
        if (st == TunnelState.State.CONNECTED) {
            long secs = Math.max(0, (System.currentTimeMillis() - TunnelState.connectedAt()) / 1000);
            statusIcon.setImageResource(R.drawable.ic_server);
            statusText.setText(protocol + " \u2022 " + String.format(Locale.US, "%02d:%02d:%02d",
                    secs / 3600, (secs / 60) % 60, secs % 60));
            ui.removeCallbacks(tick);
            ui.postDelayed(tick, 1000);
        } else if (st == TunnelState.State.ERROR) {
            statusIcon.setImageResource(R.drawable.ic_clock);
            String m = TunnelState.message();
            statusText.setText(m == null || m.isEmpty() ? "Connection failed" : m);
        } else if (spinning) {
            statusIcon.setImageResource(R.drawable.ic_server);
            statusText.setText(protocol);
        } else {
            statusIcon.setImageResource(R.drawable.ic_server);
            statusText.setText("Protocol: " + protocol);
        }
        statusIcon.setColorFilter(TEXT);
        statusText.setTextColor(TEXT);

        dotView.setBackground(oval(dot));
        dotView.setVisibility(spinning ? View.GONE : View.VISIBLE);
        dotSpinner.setVisibility(spinning ? View.VISIBLE : View.GONE);
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

    /** Soft halo colour around the big circle. */
    private int blend(int c) {
        return Color.argb(55, Color.red(c), Color.green(c), Color.blue(c));
    }

    // ---- logs

    private boolean passesLogFilter(String line) {
        if (!"Errors only".equals(prefs.getString("logLevel", "Normal"))) return true;
        String l = line.toLowerCase(Locale.US);
        return l.contains("error") || l.contains("fail") || l.contains("stopped") || l.contains("refused")
                || l.contains("rejected") || l.contains("denied") || l.contains("lost");
    }

    private void buildLogs() {
        // server banner (only shown when the SSH server sent one)
        bannerCard = new LinearLayout(this);
        bannerCard.setOrientation(LinearLayout.VERTICAL);
        bannerCard.setBackground(shape(CARD, BORDER, 1, 12));
        bannerCard.setPadding(dp(14), dp(10), dp(14), dp(12));
        bannerCard.addView(text("SERVER BANNER", 11, ORANGE, true));
        bannerText = text("", 12, TEXT, false);
        bannerText.setTypeface(Typeface.MONOSPACE);
        bannerText.setPadding(0, dp(8), 0, 0);
        bannerText.setTextIsSelectable(true);
        bannerCard.addView(bannerText);
        bannerCard.setVisibility(View.GONE);
        body.addView(bannerCard, mp(-1, -2, 0, 4, 0, 12));

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(shape(CARD, ORANGE, 2, 12));
        card.setPadding(dp(12), dp(10), dp(12), dp(12));
        logView = text("", 11, TEXT, false);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextIsSelectable(true);            // long-press to select, drag the handles, Copy
        logView.setHighlightColor(0x55F26B21);
        card.addView(logView, new LinearLayout.LayoutParams(-1, -2));
        body.addView(card, mp(-1, -2, 0, 0, 0, 0));

        shownBanner = null;
        renderLog();
        updateBanner();
        scrollLogsToBottom();
    }

    private int colorFor(String line) {
        String l = line.toLowerCase(Locale.US);
        if (line.startsWith("    ")) return MUTED;                                  // reply header lines
        int h = l.indexOf("http/");
        if (h >= 0 && l.contains("server reply")) {
            String[] t = l.substring(h).split(" ");
            if (t.length > 1) {
                char c = t[1].isEmpty() ? '0' : t[1].charAt(0);
                if (c == '1' || c == '2') return GREEN;
                if (c == '3') return ORANGE;
                return RED;
            }
        }
        if (l.contains("redirect")) return ORANGE;
        if (l.contains("error") || l.contains("failed") || l.contains("rejected") || l.contains("denied")
                || l.contains("refused") || l.contains("timed out") || l.contains("stopped:")) return RED;
        if (l.contains("tunnel check ok") || l.contains("logged in") || l.contains("vpn is up")
                || l.contains("tls up")) return GREEN;
        return TEXT;
    }

    private void appendStyled(SpannableStringBuilder sb, String line) {
        int start = sb.length();
        sb.append(line).append('\n');
        int c = colorFor(line);
        if (c != TEXT) sb.setSpan(new ForegroundColorSpan(c), start, sb.length() - 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private void renderLog() {
        if (logView == null) return;
        SpannableStringBuilder sb = new SpannableStringBuilder();
        for (String line : TunnelState.logText().split("\n")) {
            if (!line.isEmpty() && passesLogFilter(line)) appendStyled(sb, line);
        }
        logPlaceholder = sb.length() == 0;
        if (logPlaceholder) {
            sb.append("No logs yet. Connect to see what the server answers.");
            sb.setSpan(new ForegroundColorSpan(MUTED), 0, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        logView.setText(sb);
        renderedLines = 0;
    }

    private boolean nearBottom() {
        return body.getHeight() - (scroll.getScrollY() + scroll.getHeight()) <= dp(60);
    }

    /** New lines keep the view at the bottom (unless the user scrolled up to read something). */
    private void scrollLogsToBottom() {
        final Runnable r = () -> {
            if (!"logs".equals(page)) return;
            scroll.scrollTo(0, Math.max(0, body.getHeight() - scroll.getHeight()));
        };
        scroll.post(r);
        scroll.postDelayed(r, 90);
    }

    private void updateBanner() {
        if (bannerCard == null) return;
        String b = TunnelState.banner();
        if (b.equals(shownBanner)) return;
        shownBanner = b;
        if (b.trim().isEmpty()) {
            bannerCard.setVisibility(View.GONE);
            return;
        }
        CharSequence cs = HtmlText.render(b);
        bannerText.setText(cs);
        fitMono(bannerText, cs, 12);
        bannerCard.setVisibility(View.VISIBLE);
    }

    /** Monospace text shrunk (never wrapped) so the widest line fits the screen: ASCII art keeps its shape. */
    private void fitMono(TextView tv, CharSequence cs, float maxSp) {
        fitMono(tv, cs, maxSp, 2 * 18 + 2 * 14);
    }

    /** {@code paddingDp}: horizontal space (dp) taken around the text by the screen margins and the card. */
    private void fitMono(TextView tv, CharSequence cs, float maxSp, int paddingDp) {
        android.util.DisplayMetrics dm = getResources().getDisplayMetrics();
        int avail = dm.widthPixels - dp(paddingDp) - dp(4);
        Paint paint = new Paint();
        paint.setTypeface(Typeface.MONOSPACE);
        paint.setTextSize(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, maxSp, dm));
        float widest = 0;
        for (String line : cs.toString().split("\n")) widest = Math.max(widest, paint.measureText(line));
        float sp = maxSp;
        if (widest > avail && widest > 0) sp = Math.max(4.5f, maxSp * avail / widest * 0.97f);
        tv.setTextSize(sp);
    }

    @Override
    public void onLog(String line) {
        if (logView == null || !passesLogFilter(line)) return;
        boolean stick = nearBottom();
        if (logPlaceholder || ++renderedLines > 700) {
            renderLog();
        } else {
            SpannableStringBuilder one = new SpannableStringBuilder();
            appendStyled(one, line);
            logView.append(one);
        }
        updateBanner();
        if (stick) scrollLogsToBottom();
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

    /** Auto Reconnect (Settings): after an unexpected drop, retry up to 3 times, 3 s apart. */
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

    // ================================================================== SSH configuration page

    private void buildSsh() {
        final String P = "SSH";
        if (ConfigIO.flag(prefs, P, "lockAll")) { buildLocked(P); return; }
        final List<View> collapsible = new ArrayList<View>();

        add(collapsible, section("SSH CREDENTIALS"));
        add(collapsible, rowField("Username", fieldSized(field(P, "user", "username", ""))));
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
        add(collapsible, rowField("Server Address", fieldSized(field(P, "sshHost",
                ConfigIO.DEFAULT_SSH_HOST, ConfigIO.DEFAULT_SSH_HOST))));

        add(collapsible, section("PROXY / SERVER"));
        add(collapsible, rowField("Proxy Host (WebSocket)", fieldSized(field(P, "proxyHost", "your host server", ""))));
        final boolean tls = "TLS".equals(p(P, "transport", "TLS"));
        final EditText proxyPort = field(P, "proxyPort", "443 / 80", tls ? "443" : "80");
        proxyPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        add(collapsible, rowField("Proxy Port", fieldSized(proxyPort)));

        add(collapsible, section("CONNECTION MODE"));
        final LinearLayout sniBox = stackField("SNI / Host", fieldSized(field(P, "sni", "same as proxy host if empty", "")));
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


        // PAYLOAD (resizable: grows with the text, expandable to a full editor)
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
        final boolean[] expanded = {false};
        payloadExpanded = false;
        expand.setOnClickListener(v -> {
            expanded[0] = !expanded[0];
            payloadExpanded = expanded[0];
            for (View c : collapsible) c.setVisibility(expanded[0] ? View.GONE : View.VISIBLE);
            if (!expanded[0] && !"TLS".equals(p(P, "transport", "TLS"))) sniBox.setVisibility(View.GONE);
            payload.setMinHeight(dp(expanded[0] ? 400 : 130));
            if (expanded[0]) {
                payload.requestFocus();
                payload.setSelection(payload.getText().length());
                showKeyboard(payload);
            } else {
                hideKeyboard();
            }
        });

        addTextNote("Placeholders: [crlf] [host] [host_port] [sni] [proxy] [split] ...  Empty = standard WebSocket upgrade.");
        addButtons(() -> resetProto("SSH"));
    }

    // ================================================================== VLESS / VMess configuration page

    private void buildWsConfig(final String P) {
        if (ConfigIO.flag(prefs, P, "lockAll")) { buildLocked(P); return; }
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
        body.addView(stackField("WebSocket Path", fieldSized(field(P, "path", "/ws", ""))));

        body.addView(section("ADVANCED"));
        LinearLayout ins = row();
        ins.setGravity(Gravity.CENTER_VERTICAL);
        ins.addView(text("Insecure TLS", 13, TEXT, false), new LinearLayout.LayoutParams(0, -2, 1));
        ins.addView(toggle(prefs.getBoolean(P + "_insecure", false),
                (b, on) -> prefs.edit().putBoolean(P + "_insecure", on).apply()));
        body.addView(ins, mp(-1, 40, 0, 0, 0, 0));
        body.addView(rowField("DNS", dnsDropdown()));

        addButtons(() -> resetProto(P));
    }

    // ================================================================== Settings page

    private void buildSettings() {
        body.addView(section("DEVICE"));
        LinearLayout hwidRow = row();
        hwidRow.setGravity(Gravity.CENTER_VERTICAL);
        hwidRow.setBackground(rippled(null, 8));
        hwidRow.setPadding(dp(2), dp(7), dp(2), dp(7));
        LinearLayout hwidCol = new LinearLayout(this);
        hwidCol.setOrientation(LinearLayout.VERTICAL);
        hwidCol.addView(text("HWID", 14, TEXT, false));
        TextView hwidVal = text(HwId.get(this), 12, MUTED, false);
        hwidVal.setTypeface(Typeface.MONOSPACE);
        hwidVal.setPadding(0, dp(2), 0, 0);
        hwidCol.addView(hwidVal);
        hwidRow.addView(hwidCol, new LinearLayout.LayoutParams(0, -2, 1));
        ImageView hwidCopy = icon(R.drawable.ic_copy, 18, ORANGE);
        hwidCopy.setPadding(dp(4), dp(4), dp(4), dp(4));
        hwidRow.addView(hwidCopy, new LinearLayout.LayoutParams(dp(30), dp(30)));
        View.OnClickListener copyHwid = v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("HWID", HwId.get(this)));
            toast("HWID copied");
        };
        hwidCopy.setOnClickListener(copyHwid);
        hwidRow.setOnClickListener(copyHwid);          // tapping anywhere on the row copies it too
        pressable(hwidRow, 0.97f);
        body.addView(hwidRow, mp(-1, -2, 0, 8, 0, 4));
        TextView hwidNote = text("Used to lock an exported configuration to this device.", 11, MUTED, false);
        hwidNote.setPadding(0, 0, 0, 4);
        body.addView(hwidNote);

        body.addView(section("GENERAL"));
        body.addView(settingRow("Default DNS", dnsDropdown()));
        body.addView(settingRow("Log Level", dropdown(new String[]{"Normal", "Verbose", "Errors only"},
                prefs.getString("logLevel", "Normal"), v -> prefs.edit().putString("logLevel", v).apply())));

        body.addView(settingRow("Hide Server Address in Logs", toggle(prefs.getBoolean("hideHosts", true),
                (b, on) -> prefs.edit().putBoolean("hideHosts", on).apply())));

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
                    .remove("autoReconnect").remove("theme").remove("hideHosts").apply();
            Toast.makeText(this, "Settings reset", Toast.LENGTH_SHORT).show();
            if (themeChanged) recreate(); else show("settings");
        });
        body.addView(reset, mp(-1, 48, 0, 26, 0, 0));
    }

    private View dnsDropdown() {
        String cur = prefs.getString("dns", "8.8.8.8");
        List<String> opts = new ArrayList<String>(Arrays.asList(DNS_PRESETS));
        if (!opts.contains(cur)) opts.add(0, cur);
        return dropdown(opts.toArray(new String[0]), cur, v -> prefs.edit().putString("dns", v).apply());
    }

    // ================================================================== connect / validate / start

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
        pc.sshHost = p(P, "sshHost", ConfigIO.DEFAULT_SSH_HOST).trim();   // "Server Address": [host] in the payload
        pc.sshPort = 22;
        pc.proxyHost = p(P, "proxyHost", "").trim();
        pc.tls = tlsOn(P);
        pc.proxyPort = intOr(p(P, "proxyPort", pc.tls ? "443" : "80"), 0);
        pc.sni = p(P, "sni", "").trim();
        if (pc.sni.isEmpty()) pc.sni = pc.proxyHost;           // SNI defaults to the proxy host
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
        intent.putExtra("hideHosts", prefs.getBoolean("hideHosts", true) || ConfigIO.anyLock(prefs, protocol));
        if ("SSH".equals(protocol)) {
            ProtocolConfig s = sshConfig();
            intent.putExtra("bug", s.sni);
            intent.putExtra("sshUser", s.sshUser);
            intent.putExtra("sshPass", s.sshPassword);
            intent.putExtra("sshHost", s.sshHost);
            intent.putExtra("sshPort", s.sshPort);
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
        if (updateRequired) {
            if (pendingUpdate != null) showUpdateDialog(pendingUpdate);
            return;
        }
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

    // ================================================================== home: expiry + message

    /** Shows the selected configuration's expiry and message (HTML like the SSH banner) under the protocol cards. */
    private void renderNotice() {
        if (noticeBox == null) return;
        noticeBox.removeAllViews();
        String msg = p(protocol, "message", "").trim();
        String exp = p(protocol, "expiry", "").trim();
        if (msg.isEmpty() && exp.isEmpty()) {
            noticeBox.setVisibility(View.GONE);
            return;
        }
        noticeBox.setVisibility(View.VISIBLE);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(shape(CARD, ORANGE, 2, 12));
        card.setElevation(dp(2));
        card.setPadding(dp(14), dp(10), dp(14), dp(12));
        card.addView(text(protocol.toUpperCase(Locale.US) + " MESSAGE", 11, ORANGE, true));
        if (!exp.isEmpty()) {
            int[] color = {TEXT};
            String label = expiryLabel(exp, color);
            TextView e = text(label, 13, color[0], true);
            e.setPadding(0, dp(8), 0, 0);
            card.addView(e);
        }
        if (!msg.isEmpty()) {
            CharSequence cs = HtmlText.render(msg);
            TextView m = text("", 12, TEXT, false);
            m.setTypeface(Typeface.MONOSPACE);
            m.setPadding(0, dp(8), 0, 0);
            richText(m, cs);
            fitMono(m, cs, 12);
            card.addView(m);
        }
        noticeBox.addView(card);
    }

    /** "Expires 2026-12-01 (26 days left)" / "Expired on ..." and its colour. */
    private String expiryLabel(String exp, int[] colorOut) {
        try {
            SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            f.setLenient(false);
            Date d = f.parse(exp);
            Calendar end = Calendar.getInstance();
            end.setTime(d);
            end.set(Calendar.HOUR_OF_DAY, 23);
            end.set(Calendar.MINUTE, 59);
            end.set(Calendar.SECOND, 59);
            long left = end.getTimeInMillis() - System.currentTimeMillis();
            if (left < 0) {
                colorOut[0] = RED;
                return "Expired on " + exp;
            }
            long days = (left + 86399999L) / 86400000L;
            colorOut[0] = days <= 3 ? ORANGE : GREEN;
            return "Expires " + exp + "  (" + (days <= 1 ? "today" : days + " days left") + ")";
        } catch (Exception e) {
            colorOut[0] = MUTED;
            return "Expiry: " + exp;
        }
    }

    // ================================================================== forced update

    private void checkForUpdate() {
        String current;
        try {
            current = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            current = "0";
        }
        final String cur = current == null ? "0" : current;
        new Thread(() -> UpdateManager.check(cur, new UpdateManager.CheckListener() {
            @Override public void onUpdateAvailable(UpdateManager.Info info) {
                ui.post(() -> showUpdateDialog(info));
            }
            @Override public void onNoUpdate() { /* offline / already current / bad reply: say nothing */ }
        }), "update-check").start();
    }

    /** A non-cancelable dialog: there is no way to dismiss it other than finishing the update. */
    private void showUpdateDialog(final UpdateManager.Info info) {
        updateRequired = true;
        pendingUpdate = info;

        final Dialog d = new Dialog(this);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        d.setCancelable(false);
        d.setCanceledOnTouchOutside(false);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(shape(CARD, ORANGE, 2, 14));
        box.setPadding(dp(22), dp(20), dp(22), dp(18));
        box.addView(text("Update required", 18, TEXT, true));
        final TextView msg = text("A new version (" + info.version + ") is available. Nanika must be updated "
                + "before it can be used.", 13, MUTED, false);
        msg.setPadding(0, dp(10), 0, dp(4));
        box.addView(msg);

        final ProgressBar spinner = new ProgressBar(this);
        spinner.setVisibility(View.GONE);
        box.addView(spinner, mp(-2, -2, 0, 14, 0, 0));

        final Button go = new Button(this);
        go.setText("UPDATE NOW");
        go.setAllCaps(false);
        go.setTextSize(13);
        go.setTypeface(null, Typeface.BOLD);
        go.setTextColor(Color.WHITE);
        go.setBackground(new RippleDrawable(ColorStateList.valueOf(0x44FFFFFF), shape(ORANGE, 0, 0, 8), shape(Color.WHITE, 0, 0, 8)));
        go.setStateListAnimator(null);
        go.setOnClickListener(v -> {
            go.setEnabled(false);
            go.setText("DOWNLOADING... 0%");
            msg.setTextColor(MUTED);
            msg.setText("Please keep Nanika open until this finishes.");
            spinner.setVisibility(View.VISIBLE);
            startUpdateDownload(info, go, msg, spinner);
        });
        box.addView(go, mp(-1, 46, 0, 16, 0, 0));

        d.setContentView(box);
        if (d.getWindow() != null) {
            d.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            d.getWindow().setLayout((int) (getResources().getDisplayMetrics().widthPixels * 0.88f),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        d.show();
    }

    private void startUpdateDownload(final UpdateManager.Info info, final Button go, final TextView msg,
            final ProgressBar spinner) {
        final File dest = new File(new File(getCacheDir(), "updates"), info.file);
        new Thread(() -> UpdateManager.download(info, dest, new UpdateManager.DownloadListener() {
            @Override public void onProgress(int percent) {
                ui.post(() -> go.setText("DOWNLOADING... " + percent + "%"));
            }
            @Override public void onDone(File file) {
                ui.post(() -> installUpdate(file, info));
            }
            @Override public void onError(String message) {
                ui.post(() -> {
                    go.setEnabled(true);
                    go.setText("RETRY");
                    spinner.setVisibility(View.GONE);
                    msg.setText("Download failed: " + message);
                    msg.setTextColor(RED);
                });
            }
        }), "update-download").start();
    }

    private void installUpdate(File file, UpdateManager.Info info) {
        if (Build.VERSION.SDK_INT >= 26 && !getPackageManager().canRequestPackageInstalls()) {
            toast("Allow Nanika to install updates, then tap UPDATE NOW again");
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception ignored) { }
            if (updateDialogStillNeeded()) showUpdateDialog(info);
            return;
        }
        try {
            Uri apkUri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", file);
            Intent install = new Intent(Intent.ACTION_VIEW);
            install.setDataAndType(apkUri, "application/vnd.android.package-archive");
            install.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(install);
        } catch (Exception e) {
            toast("Could not start the installer: " + e.getMessage());
            return;
        }
        ui.postDelayed(this::finishAffinity, 300);     // give the installer a moment to take over, then close
    }

    private boolean updateDialogStillNeeded() { return updateRequired; }

    // ================================================================== three-dots menu, import / export

    private void toast(String m) { Toast.makeText(this, m, Toast.LENGTH_LONG).show(); }

    private void showConfigMenu(View anchor, final String proto) {
        boolean locked = ConfigIO.anyLock(prefs, proto);      // protected by its creator: cannot be exported again
        if ("SSH".equals(proto)) {
            if (locked) {
                // a creator-protected import: no export, and no payload injection over a hidden/locked payload
                showMenu(anchor, new String[]{"Import file", "Reset"}, new Runnable[]{
                        () -> pickImportFile("SSH"), () -> resetProto("SSH")});
            } else {
                showMenu(anchor, new String[]{"Import file", "Export file", "Inject payload", "Reset"}, new Runnable[]{
                        () -> pickImportFile("SSH"),
                        () -> showExportDialog("SSH", false),
                        this::showInjectDialog,
                        () -> resetProto("SSH")});
            }
        } else if (locked) {
            showMenu(anchor, new String[]{"Import", "Reset"}, new Runnable[]{
                    () -> importDialog(proto), () -> resetProto(proto)});
        } else {
            showMenu(anchor, new String[]{"Import", "Export", "Reset"}, new Runnable[]{
                    () -> importDialog(proto),
                    () -> exportDialog(proto),
                    () -> resetProto(proto)});
        }
    }

    /** Clears every stored setting of one protocol (including any protection / HWID lock) and refreshes the page. */
    private void resetProto(String proto) {
        String P = "SSH".equalsIgnoreCase(proto) ? "SSH" : ("VLESS".equalsIgnoreCase(proto) ? "VLESS" : "VMess");
        SharedPreferences.Editor e = prefs.edit();
        for (String k : ConfigIO.keys(P)) e.remove(P + "_" + k);
        e.apply();
        toast(P + " configuration reset");
        if (page.equals(P.toLowerCase(Locale.US))) show(P.toLowerCase(Locale.US));
    }

    private void showMenu(View anchor, String[] labels, final Runnable[] actions) {
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setBackground(shape(CARD, BORDER, 1, 10));
        list.setPadding(0, dp(6), 0, dp(6));
        final PopupWindow pw = new PopupWindow(list, dp(210), ViewGroup.LayoutParams.WRAP_CONTENT, true);
        for (int i = 0; i < labels.length; i++) {
            final int idx = i;
            TextView t = text(labels[i], 14, TEXT, false);
            t.setPadding(dp(18), dp(13), dp(18), dp(13));
            t.setBackground(rippled(null, 0));
            t.setOnClickListener(v -> {
                pw.dismiss();
                actions[idx].run();
            });
            list.addView(t, new LinearLayout.LayoutParams(-1, -2));
        }
        pw.setElevation(dp(10));
        pw.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        pw.setOutsideTouchable(true);
        pw.showAsDropDown(anchor, anchor.getWidth() - dp(210), 0);
    }

    private void choose(String title, String[] labels, final Runnable[] actions) {
        final Dialog d = new Dialog(this);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(shape(CARD, BORDER, 1, 14));
        box.setPadding(dp(8), dp(16), dp(8), dp(10));
        TextView t = text(title, 16, TEXT, true);
        t.setPadding(dp(14), 0, dp(14), dp(10));
        box.addView(t);
        for (int i = 0; i < labels.length; i++) {
            final int idx = i;
            TextView item = text(labels[i], 14, TEXT, false);
            item.setPadding(dp(14), dp(13), dp(14), dp(13));
            item.setBackground(rippled(null, 8));
            item.setOnClickListener(v -> {
                d.dismiss();
                actions[idx].run();
            });
            box.addView(item, new LinearLayout.LayoutParams(-1, -2));
        }
        TextView cancel = text("CANCEL", 12, ORANGE, true);
        cancel.setGravity(Gravity.END);
        cancel.setPadding(dp(14), dp(12), dp(14), dp(4));
        cancel.setOnClickListener(v -> d.dismiss());
        box.addView(cancel);
        d.setContentView(box);
        if (d.getWindow() != null) {
            d.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            d.getWindow().setLayout((int) (getResources().getDisplayMetrics().widthPixels * 0.86f),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        d.show();
    }

    private void showInjectDialog() {
        choose("Inject payload", new String[]{"Cloudflare", "Enhanced", "Direct"}, new Runnable[]{
                () -> applyInjectPayload("Cloudflare", InjectPayloads.CLOUDFLARE),
                () -> applyInjectPayload("Enhanced", InjectPayloads.ENHANCED),
                () -> applyInjectPayload("Direct", InjectPayloads.DIRECT)});
    }

    private void applyInjectPayload(String label, String template) {
        prefs.edit().putString("SSH_payload", template).apply();
        toast(label + " payload injected");
        if ("ssh".equals(page)) show("ssh");
    }

    private void importDialog(final String proto) {
        choose("Import " + proto, new String[]{"From clipboard (" + proto.toLowerCase(Locale.US) + ":// link)",
                "From file (.anika or .json)"}, new Runnable[]{
                () -> importFromClipboard(proto),
                () -> pickImportFile(proto)});
    }

    private void exportDialog(final String proto) {
        choose("Export " + proto, new String[]{"Copy link to clipboard", "Save as .anika (encrypted)",
                "Save as JSON file"}, new Runnable[]{
                () -> exportLink(proto),
                () -> showExportDialog(proto, false),
                () -> showExportDialog(proto, true)});
    }

    private void importFromClipboard(String proto) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        CharSequence cs = null;
        if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip() != null && cm.getPrimaryClip().getItemCount() > 0) {
            cs = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
        }
        String err = ConfigIO.importLink(prefs, proto, cs == null ? "" : cs.toString());
        if (err != null) {
            toast("Import failed: " + err);
            return;
        }
        toast(proto + " configuration imported");
        show(proto.toLowerCase(Locale.US));
    }

    private void exportLink(String proto) {
        if (ConfigIO.anyLock(prefs, proto)) {
            toast("This configuration is locked by its creator and can't be exported");
            return;
        }
        if (p(proto, "uuid", "").trim().isEmpty()) {
            toast("Fill in the configuration first");
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText(proto + " link", ConfigIO.exportLink(prefs, proto)));
        toast(proto + " link copied");
    }

    /**
     * The export dialog: file name (top), expiry, protection boxes (hide server / hide host / lock all) and,
     * at the very bottom, the message shown on the home page (HTML, links work).
     */
    private void showExportDialog(final String proto, final boolean json) {
        if (ConfigIO.anyLock(prefs, proto)) {
            toast("This configuration is locked by its creator and can't be exported");
            return;
        }
        final String ext = json ? ".json" : ".anika";
        final Dialog d = new Dialog(this);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(shape(CARD, BORDER, 1, 14));
        box.setPadding(dp(18), dp(16), dp(18), dp(12));
        box.addView(text("Export " + proto + " configuration", 17, TEXT, true));

        // ---- file name (top)
        box.addView(text("File name", 12, TEXT, false), mp(-2, -2, 2, 14, 0, 6));
        LinearLayout nameRow = row();
        nameRow.setGravity(Gravity.CENTER_VERTICAL);
        final EditText name = new EditText(this);
        name.setText("nanika-" + proto.toLowerCase(Locale.US));
        name.setSingleLine(true);
        name.setTextColor(TEXT);
        name.setTextSize(14);
        name.setBackground(shape(CARD, BORDER, 1, 8));
        name.setPadding(dp(12), 0, dp(12), 0);
        name.setHighlightColor(0x55F26B21);
        name.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        focusRing(name);
        nameRow.addView(name, new LinearLayout.LayoutParams(0, dp(44), 1));
        TextView extView = text(ext, 14, MUTED, false);
        extView.setPadding(dp(8), 0, 0, 0);
        nameRow.addView(extView);
        box.addView(nameRow);

        // ---- expiry
        box.addView(section("EXPIRY"));
        final String[] expiry = {p(proto, "expiry", "")};
        final TextView expView = text("", 14, TEXT, false);
        expView.setGravity(Gravity.CENTER_VERTICAL);
        expView.setPadding(dp(12), 0, dp(12), 0);
        expView.setBackground(shape(CARD, BORDER, 1, 8));
        final Runnable paintExpiry = () -> {
            expView.setText(expiry[0].isEmpty() ? "No expiry (tap to pick a date)" : expiry[0]);
            expView.setTextColor(expiry[0].isEmpty() ? MUTED : TEXT);
        };
        paintExpiry.run();
        expView.setOnClickListener(v -> {
            Calendar c = Calendar.getInstance();
            String cur = expiry[0];
            if (cur.matches("\\d{4}-\\d{2}-\\d{2}")) {
                c.set(Integer.parseInt(cur.substring(0, 4)), Integer.parseInt(cur.substring(5, 7)) - 1,
                        Integer.parseInt(cur.substring(8, 10)));
            }
            new DatePickerDialog(this, (view, y, m, day) -> {
                expiry[0] = String.format(Locale.US, "%04d-%02d-%02d", y, m + 1, day);
                paintExpiry.run();
            }, c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH)).show();
        });
        TextView clearExp = text("CLEAR", 11, ORANGE, true);
        clearExp.setPadding(dp(12), dp(8), dp(2), dp(8));
        clearExp.setOnClickListener(v -> { expiry[0] = ""; paintExpiry.run(); });
        LinearLayout expRow = row();
        expRow.setGravity(Gravity.CENTER_VERTICAL);
        expRow.addView(expView, new LinearLayout.LayoutParams(0, dp(44), 1));
        expRow.addView(clearExp);
        box.addView(expRow);

        // ---- protection boxes
        box.addView(section("PROTECTION"));
        final CheckBox cbServer = protectBox(box, "Hide server",
                "Server address / Host header are not shown to the person who imports the file");
        final CheckBox cbHost = protectBox(box, "Hide host only",
                "Proxy host, connect host, SNI" + ("SSH".equals(proto) ? " and payload" : "") + " are not shown");
        final CheckBox cbLock = protectBox(box, "Lock all",
                "Nothing is shown: the settings page says \"Config locked by creator\"");
        cbLock.setOnCheckedChangeListener((b, on) -> {
            if (on) { cbServer.setChecked(true); cbHost.setChecked(true); }
            cbServer.setEnabled(!on);
            cbHost.setEnabled(!on);
        });
        if (json) {
            cbServer.setEnabled(false);
            cbHost.setEnabled(false);
            cbLock.setEnabled(false);
            TextView n = text("JSON files are readable by anyone, so protection is only available for .anika files.",
                    11, MUTED, false);
            n.setPadding(0, dp(4), 0, 0);
            box.addView(n);
        } else {
            TextView n = text("A protected file cannot be exported again after it is imported. Logs of a protected "
                    + "configuration always hide the server addresses.", 11, MUTED, false);
            n.setPadding(0, dp(4), 0, 0);
            box.addView(n);
        }

        // ---- device lock (HWID)
        box.addView(section("DEVICE LOCK"));
        final CheckBox cbHwid = new CheckBox(this);
        cbHwid.setText("Restrict to one device (HWID)");
        cbHwid.setTextColor(TEXT);
        cbHwid.setTextSize(14);
        cbHwid.setButtonTintList(new ColorStateList(new int[][]{{android.R.attr.state_checked}, {}},
                new int[]{ORANGE, MUTED}));
        box.addView(cbHwid);
        final EditText hwidField = new EditText(this);
        hwidField.setHint("HWID, e.g. " + HwId.get(this));
        hwidField.setSingleLine(true);
        hwidField.setTextColor(TEXT);
        hwidField.setHintTextColor(MUTED);
        hwidField.setTextSize(13);
        hwidField.setTypeface(Typeface.MONOSPACE);
        hwidField.setBackground(shape(CARD, BORDER, 1, 8));
        hwidField.setPadding(dp(12), 0, dp(12), 0);
        hwidField.setEnabled(false);
        hwidField.setHighlightColor(0x55F26B21);
        focusRing(hwidField);
        LinearLayout hwidRow2 = row();
        hwidRow2.setGravity(Gravity.CENTER_VERTICAL);
        hwidRow2.addView(hwidField, new LinearLayout.LayoutParams(0, dp(42), 1));
        final TextView useThis = text("USE THIS DEVICE", 11, ORANGE, true);
        useThis.setPadding(dp(10), dp(8), dp(2), dp(8));
        useThis.setAlpha(0.4f);
        useThis.setClickable(false);
        useThis.setOnClickListener(v -> hwidField.setText(HwId.get(this)));
        hwidRow2.addView(useThis);
        box.addView(hwidRow2, mp(-1, -2, 0, 8, 0, 4));
        cbHwid.setOnCheckedChangeListener((b, on) -> {
            hwidField.setEnabled(on);
            useThis.setAlpha(on ? 1f : 0.4f);
            useThis.setClickable(on);
        });
        TextView hwidNote2 = text("Only the device with this HWID (see Settings) will be able to import the file.",
                11, MUTED, false);
        hwidNote2.setPadding(0, dp(4), 0, 0);
        box.addView(hwidNote2);

        // ---- message (very bottom)
        box.addView(section("MESSAGE ON THE HOME PAGE"));
        box.addView(text("Text or HTML. Links (WhatsApp, Telegram, any web link) can be tapped.", 11, MUTED, false));
        final EditText msg = new EditText(this);
        msg.setHint("<b>Welcome!</b> Join us: <a href=\"https://t.me/yourchannel\">Telegram</a>");
        msg.setText(prefs.getString(proto + "_message", ""));
        msg.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        msg.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI | EditorInfo.IME_FLAG_NO_FULLSCREEN);
        msg.setSingleLine(false);
        msg.setMinHeight(dp(100));
        msg.setMaxLines(Integer.MAX_VALUE);
        msg.setGravity(Gravity.TOP | Gravity.START);
        msg.setTypeface(Typeface.MONOSPACE);
        msg.setTextColor(TEXT);
        msg.setHintTextColor(MUTED);
        msg.setHighlightColor(0x55F26B21);
        msg.setTextSize(12);
        msg.setPadding(dp(12), dp(10), dp(12), dp(10));
        msg.setBackground(shape(CARD, BORDER, 1, 8));
        focusRing(msg);
        box.addView(msg, mp(-1, -2, 0, 8, 0, 0));
        box.addView(text("PREVIEW", 10, MUTED, true), mp(-2, -2, 2, 10, 0, 4));
        final TextView preview = text("", 12, TEXT, false);
        preview.setTypeface(Typeface.MONOSPACE);
        box.addView(preview);
        final Runnable paintPreview = () -> {
            CharSequence r = HtmlText.render(msg.getText().toString());
            if (r.length() == 0) { preview.setText(""); return; }
            richText(preview, r);
            fitMono(preview, r, 12, 2 * 18 + 2 * 18);
        };
        paintPreview.run();
        msg.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { paintPreview.run(); }
            @Override public void afterTextChanged(Editable s) {}
        });

        // ---- buttons
        LinearLayout buttons = row();
        buttons.setGravity(Gravity.END);
        TextView cancel = text("CANCEL", 13, ORANGE, true);
        cancel.setPadding(dp(16), dp(12), dp(16), dp(12));
        cancel.setOnClickListener(v -> d.dismiss());
        buttons.addView(cancel);
        Button go = new Button(this);
        go.setText("EXPORT");
        go.setAllCaps(false);
        go.setTextSize(13);
        go.setTypeface(null, Typeface.BOLD);
        go.setTextColor(Color.WHITE);
        go.setBackground(new RippleDrawable(ColorStateList.valueOf(0x44FFFFFF), shape(ORANGE, 0, 0, 8), shape(Color.WHITE, 0, 0, 8)));
        go.setStateListAnimator(null);
        go.setOnClickListener(v -> {
            String fname = fileName(name.getText().toString(), proto, ext);
            String message = msg.getText().toString().trim();
            SharedPreferences.Editor e = prefs.edit();
            if (expiry[0].isEmpty()) e.remove(proto + "_expiry"); else e.putString(proto + "_expiry", expiry[0]);
            if (message.isEmpty()) e.remove(proto + "_message"); else e.putString(proto + "_message", message);
            e.apply();
            boolean lock = !json && cbLock.isChecked();
            boolean hideServer = !json && (lock || cbServer.isChecked());
            boolean hideHost = !json && (lock || cbHost.isChecked());
            String hwidValue = cbHwid.isChecked() ? hwidField.getText().toString().trim() : "";
            if (cbHwid.isChecked() && hwidValue.isEmpty()) {
                toast("Enter a HWID, or tap USE THIS DEVICE");
                return;
            }
            if (startExport(proto, json, fname + ext, lock, hideServer, hideHost, hwidValue)) d.dismiss();
        });
        buttons.addView(go, new LinearLayout.LayoutParams(dp(110), dp(42)));
        box.addView(buttons, mp(-1, -2, 0, 14, 0, 0));

        ScrollView sv = new ScrollView(this);
        sv.setFillViewport(false);
        sv.addView(box);
        d.setContentView(sv);
        if (d.getWindow() != null) {
            d.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            d.getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
            d.getWindow().setLayout((int) (getResources().getDisplayMetrics().widthPixels * 0.92f),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        d.show();
    }

    private CheckBox protectBox(LinearLayout parent, String label, String sub) {
        CheckBox cb = new CheckBox(this);
        cb.setText(label);
        cb.setTextColor(TEXT);
        cb.setTextSize(14);
        cb.setButtonTintList(new ColorStateList(new int[][]{{android.R.attr.state_checked}, {}},
                new int[]{ORANGE, MUTED}));
        parent.addView(cb);
        TextView t = text(sub, 11, MUTED, false);
        t.setPadding(dp(34), 0, 0, dp(6));
        parent.addView(t);
        return cb;
    }

    private String fileName(String typed, String proto, String ext) {
        String n = typed == null ? "" : typed.trim();
        if (n.toLowerCase(Locale.US).endsWith(ext)) n = n.substring(0, n.length() - ext.length());
        n = n.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_").trim();
        if (n.length() > 60) n = n.substring(0, 60);
        return n.isEmpty() ? "nanika-" + proto.toLowerCase(Locale.US) : n;
    }

    /** Builds the file and opens the system "save as" screen. Returns false if it could not be built. */
    private boolean startExport(String proto, boolean json, String fileName, boolean lock, boolean hideServer,
                                boolean hideHost, String hwid) {
        try {
            JSONObject root = ConfigIO.toJson(prefs, proto);
            JSONObject cfg = root.optJSONObject("config");
            if (cfg != null) {
                if (lock) cfg.put("lockAll", true);
                if (hideServer) cfg.put("hideServer", true);
                if (hideHost) cfg.put("hideHost", true);
                if (hwid != null && !hwid.isEmpty()) cfg.put("hwid", hwid);
            }
            pendingExportData = json ? ConfigIO.toJsonFile(root) : ConfigIO.toAnika(root);
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType(json ? "application/json" : "application/octet-stream");
            i.putExtra(Intent.EXTRA_TITLE, fileName);
            exportLauncher.launch(i);
            return true;
        } catch (Exception e) {
            pendingExportData = null;
            toast("Export failed: " + e.getMessage());
            return false;
        }
    }

    // ================================================================== links inside messages

    private static final java.util.List<String> LINK_SCHEMES = Arrays.asList(
            "http", "https", "tg", "whatsapp", "mailto", "tel", "sms", "signal", "viber");

    /** Shows text whose links (author's <a href> and plain URLs such as wa.me / t.me) can be tapped. */
    private void richText(TextView tv, CharSequence cs) {
        SpannableString sp = new SpannableString(cs);
        URLSpan[] orig = sp.getSpans(0, sp.length(), URLSpan.class);
        int[][] ranges = new int[orig.length][2];
        String[] urls = new String[orig.length];
        for (int i = 0; i < orig.length; i++) {
            ranges[i][0] = sp.getSpanStart(orig[i]);
            ranges[i][1] = sp.getSpanEnd(orig[i]);
            urls[i] = orig[i].getURL();
        }
        Linkify.addLinks(sp, Linkify.WEB_URLS);                 // this drops the author's own links ...
        for (int i = 0; i < orig.length; i++) {                  // ... so they are put back
            for (URLSpan o : sp.getSpans(ranges[i][0], ranges[i][1], URLSpan.class)) sp.removeSpan(o);
            sp.setSpan(new URLSpan(urls[i]), ranges[i][0], ranges[i][1], Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        for (URLSpan u : sp.getSpans(0, sp.length(), URLSpan.class)) {
            int a = sp.getSpanStart(u), b = sp.getSpanEnd(u);
            String url = u.getURL();
            sp.removeSpan(u);
            sp.setSpan(new SafeLink(url), a, b, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        tv.setText(sp);
        tv.setMovementMethod(LinkMovementMethod.getInstance());
        tv.setHighlightColor(Color.TRANSPARENT);
    }

    private final class SafeLink extends android.text.style.ClickableSpan {
        private final String url;
        SafeLink(String url) { this.url = url; }
        @Override public void onClick(View widget) { openLink(url); }
        @Override public void updateDrawState(android.text.TextPaint ds) {
            ds.setColor(ORANGE);
            ds.setUnderlineText(true);
        }
    }

    /** Asks before opening, and only opens web, WhatsApp, Telegram, mail, phone and similar links. */
    private void openLink(String raw) {
        String url = raw == null ? "" : raw.trim();
        if (!url.contains(":") && url.contains(".")) url = "https://" + url;
        final Uri uri;
        try { uri = Uri.parse(url); } catch (Exception e) { return; }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.US);
        if (!LINK_SCHEMES.contains(scheme)) {
            toast("This kind of link is not allowed");
            return;
        }
        final Dialog d = new Dialog(this);
        d.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(shape(CARD, BORDER, 1, 14));
        box.setPadding(dp(20), dp(18), dp(20), dp(10));
        box.addView(text("Open this link?", 16, TEXT, true));
        TextView u = text(url, 12, MUTED, false);
        u.setTypeface(Typeface.MONOSPACE);
        u.setPadding(0, dp(10), 0, dp(6));
        box.addView(u);
        TextView note = text("It comes from the message in the configuration.", 11, MUTED, false);
        box.addView(note);
        LinearLayout buttons = row();
        buttons.setGravity(Gravity.END);
        TextView cancel = text("CANCEL", 13, ORANGE, true);
        cancel.setPadding(dp(14), dp(12), dp(14), dp(12));
        cancel.setOnClickListener(v -> d.dismiss());
        TextView open = text("OPEN", 13, ORANGE, true);
        open.setPadding(dp(14), dp(12), dp(6), dp(12));
        open.setOnClickListener(v -> {
            d.dismiss();
            try {
                Intent i = new Intent(Intent.ACTION_VIEW, uri);
                i.addCategory(Intent.CATEGORY_BROWSABLE);
                startActivity(i);
            } catch (ActivityNotFoundException e) {
                toast("No app can open this link");
            }
        });
        buttons.addView(cancel);
        buttons.addView(open);
        box.addView(buttons, mp(-1, -2, 0, 8, 0, 0));
        d.setContentView(box);
        if (d.getWindow() != null) {
            d.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            d.getWindow().setLayout((int) (getResources().getDisplayMetrics().widthPixels * 0.88f),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        d.show();
    }

    // ================================================================== config page shown when the creator locked it

    private void buildLocked(String P) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setBackground(shape(CARD, ORANGE, 2, 14));
        card.setElevation(dp(2));
        card.setPadding(dp(22), dp(28), dp(22), dp(28));
        FrameLayout badge = new FrameLayout(this);
        badge.setBackground(oval(ORANGE));
        badge.addView(icon(R.drawable.ic_lock, 30, Color.WHITE), new FrameLayout.LayoutParams(dp(30), dp(30), Gravity.CENTER));
        card.addView(badge, new LinearLayout.LayoutParams(dp(64), dp(64)));
        TextView t = text("Config locked by creator", 18, TEXT, true);
        t.setGravity(Gravity.CENTER);
        t.setPadding(0, dp(16), 0, dp(6));
        card.addView(t);
        TextView sub = text("The settings of this " + P + " configuration are hidden by whoever made it. "
                + "You can still connect from the home page, or import a different file from the menu.", 13, MUTED, false);
        sub.setGravity(Gravity.CENTER);
        card.addView(sub);
        String exp = p(P, "expiry", "").trim();
        if (!exp.isEmpty()) {
            int[] color = {TEXT};
            TextView e = text(expiryLabel(exp, color), 13, color[0], true);
            e.setPadding(0, dp(14), 0, 0);
            card.addView(e);
        }
        body.addView(card, mp(-1, -2, 0, 24, 0, 0));
    }

    private void pickImportFile(String proto) {
        pendingImportProto = proto;
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        importLauncher.launch(i);
    }

    private void importFromUri(String proto, Uri uri) {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new java.io.IOException("cannot open the file");
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
                if (bo.size() > 1024 * 1024) throw new java.io.IOException("the file is too large");
            }
            JSONObject root = ConfigIO.parseFile(bo.toByteArray());
            String err = ConfigIO.fromJson(prefs, proto, root, HwId.get(this));
            if (err != null) {
                toast("Import failed: " + err);
                return;
            }
            toast(proto + " configuration imported");
            show(proto.toLowerCase(Locale.US));
        } catch (Exception e) {
            toast("Import failed: " + e.getMessage());
        }
    }

    // ================================================================== view helpers

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
        if (bold) v.setTypeface(sp >= 18 ? Typeface.DEFAULT_BOLD : Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return v;
    }

    private ImageView glyph(int kind, int sizeDp, int color) {
        ImageView v = new ImageView(this);
        v.setImageDrawable(new GlyphDrawable(kind));
        v.setColorFilter(color);
        v.setLayoutParams(new LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)));
        return v;
    }

    /** Wraps a background in an orange touch ripple clipped to the same rounded shape. */
    private Drawable rippled(Drawable content, int radiusDp) {
        return new RippleDrawable(ColorStateList.valueOf(0x33F26B21), content, shape(Color.WHITE, 0, 0, radiusDp));
    }

    /** Little "squish" on touch (does not consume the touch, so clicks still work). */
    @SuppressLint("ClickableViewAccessibility")
    private void pressable(View v, final float to) {
        v.setOnTouchListener((view, e) -> {
            int a = e.getActionMasked();
            if (a == MotionEvent.ACTION_DOWN) {
                view.animate().scaleX(to).scaleY(to).setDuration(90).setInterpolator(new DecelerateInterpolator()).start();
            } else if (a == MotionEvent.ACTION_UP || a == MotionEvent.ACTION_CANCEL) {
                view.animate().scaleX(1f).scaleY(1f).setDuration(220).setInterpolator(new OvershootInterpolator(2.4f)).start();
            }
            return false;
        });
    }

    private void showKeyboard(final View v) {
        v.post(() -> {
            InputMethodManager im = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (im != null) im.showSoftInput(v, InputMethodManager.SHOW_IMPLICIT);
        });
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

    private void addTextNote(String t) {
        TextView n = text(t, 11, MUTED, false);
        n.setPadding(0, dp(6), 0, dp(4));
        body.addView(n);
    }

    /** A value the creator hid: shown as dots, cannot be edited or copied, but is still used to connect. */
    private EditText hiddenField() {
        EditText e = new EditText(this);
        e.setText("\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022");
        e.setEnabled(false);
        e.setSingleLine(true);
        e.setTextColor(MUTED);
        e.setTextSize(14);
        e.setBackground(shape(CARD, BORDER, 1, 8));
        e.setPadding(dp(12), 0, dp(12), 0);
        return e;
    }

    private EditText field(String proto, String key, String hint, String def) {
        if (ConfigIO.isHidden(prefs, proto, key)) return hiddenField();
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
        e.setHighlightColor(0x55F26B21);
        e.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        focusRing(e);
        e.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                prefs.edit().putString(k, s.toString()).apply();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
        return e;
    }

    /** Orange 2dp outline while the field has focus. */
    private void focusRing(final EditText e) {
        e.setOnFocusChangeListener((v, focused) ->
                e.setBackground(focused ? shape(CARD, ORANGE, 2, 8) : shape(CARD, BORDER, 1, 8)));
    }

    private EditText fieldSized(EditText e) {
        e.setLayoutParams(new LinearLayout.LayoutParams(-1, dp(44)));
        return e;
    }

    private View fieldSized(View v) { return v; }

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
        r.addView(t, new LinearLayout.LayoutParams(dp(112), -2));
        r.addView(field, new LinearLayout.LayoutParams(0, dp(42), 1));
        r.setPadding(0, dp(3), 0, dp(3));
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

    @SuppressLint("ClickableViewAccessibility")
    private EditText payloadField() {
        if (ConfigIO.isHidden(prefs, "SSH", "payload")) {
            EditText h = hiddenField();
            h.setMinHeight(dp(130));
            h.setGravity(Gravity.TOP | Gravity.START);
            h.setPadding(dp(12), dp(10), dp(12), dp(10));
            return h;
        }
        final String k = "SSH_payload";
        final EditText e = new EditText(this);
        e.setHint("GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]");
        e.setText(prefs.getString(k, ""));
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI | EditorInfo.IME_FLAG_NO_FULLSCREEN);
        e.setSingleLine(false);
        e.setHorizontallyScrolling(false);
        e.setMinHeight(dp(130));
        e.setMaxLines(Integer.MAX_VALUE);
        e.setGravity(Gravity.TOP | Gravity.START);
        e.setTypeface(Typeface.MONOSPACE);
        e.setTextColor(TEXT);
        e.setHintTextColor(MUTED);
        e.setHighlightColor(0x55F26B21);
        e.setTextSize(12);
        e.setPadding(dp(12), dp(10), dp(12), dp(10));
        e.setBackground(shape(CARD, BORDER, 1, 8));
        // real, fully editable field: taps focus it and raise the keyboard, long-press gives the system
        // Select all / Cut / Copy / Paste bar, and the selection handles can be dragged
        e.setFocusable(true);
        e.setFocusableInTouchMode(true);
        e.setClickable(true);
        e.setLongClickable(true);
        e.setCursorVisible(true);
        e.setShowSoftInputOnFocus(true);
        e.setOnFocusChangeListener((v, focused) -> {
            e.setBackground(focused ? shape(CARD, ORANGE, 2, 8) : shape(CARD, BORDER, 1, 8));
            if (focused) showKeyboard(e);
        });
        e.setOnClickListener(v -> {
            if (!e.hasFocus()) e.requestFocus();
            showKeyboard(e);
        });
        e.setOnTouchListener((v, ev) -> {
            // keep the page from scrolling away while the user is selecting / dragging inside the field
            if (ev.getActionMasked() == MotionEvent.ACTION_DOWN && e.hasFocus() && (e.hasSelection() || payloadExpanded)) {
                v.getParent().requestDisallowInterceptTouchEvent(true);
            }
            return false;
        });
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
        final int n = labels.length;
        final FrameLayout box = new FrameLayout(this);
        box.setBackground(shape(CARD, BORDER, 1, 8));
        final View thumb = new View(this);
        thumb.setBackground(shape(ORANGE, 0, 0, 8));
        thumb.setElevation(dp(1));
        box.addView(thumb, new FrameLayout.LayoutParams(0, dp(42)));
        LinearLayout labelRow = row();
        final TextView[] segs = new TextView[n];
        final int[] sel = {Math.max(0, Arrays.asList(values).indexOf(selected))};
        for (int i = 0; i < n; i++) {
            final int idx = i;
            segs[i] = text(labels[i], 13, TEXT, true);
            segs[i].setGravity(Gravity.CENTER);
            segs[i].setOnClickListener(v -> {
                if (sel[0] == idx) return;
                sel[0] = idx;
                thumb.animate().translationX(thumb.getWidth() * idx).setDuration(240)
                        .setInterpolator(new DecelerateInterpolator(1.8f)).start();
                paintSegments(segs, sel[0]);
                pick.on(values[idx]);
            });
            labelRow.addView(segs[i], new LinearLayout.LayoutParams(0, dp(42), 1));
        }
        box.addView(labelRow, new FrameLayout.LayoutParams(-1, dp(42)));
        box.addOnLayoutChangeListener((v, l, t, r, bt, ol, ot, orr, ob) -> {
            int w = (r - l) / n;
            FrameLayout.LayoutParams tlp = (FrameLayout.LayoutParams) thumb.getLayoutParams();
            if (tlp.width != w) {
                tlp.width = w;
                thumb.setLayoutParams(tlp);
            }
            thumb.setTranslationX(w * sel[0]);
        });
        paintSegments(segs, sel[0]);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(2), 0, dp(6));
        box.setLayoutParams(lp);
        return box;
    }

    private void paintSegments(TextView[] segs, int sel) {
        for (int i = 0; i < segs.length; i++) segs[i].setTextColor(i == sel ? Color.WHITE : TEXT);
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
        b.setBackground(rippled(shape(CARD, ORANGE, 1, 8), 8));
        b.setStateListAnimator(null);
        b.setElevation(dp(1));
        pressable(b, 0.97f);
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
        sb.setBackground(new RippleDrawable(ColorStateList.valueOf(0x44FFFFFF), shape(ORANGE, 0, 0, 8), shape(Color.WHITE, 0, 0, 8)));
        sb.setStateListAnimator(null);
        sb.setElevation(dp(3));
        pressable(sb, 0.97f);
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

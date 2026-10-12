package com.example.tunnel;

import android.Manifest;
import android.animation.LayoutTransition;
import android.annotation.SuppressLint;
import android.app.DatePickerDialog;
import android.graphics.Outline;
import android.graphics.Paint;
import android.text.style.AbsoluteSizeSpan;
import android.util.TypedValue;
import android.view.ViewOutlineProvider;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.Html;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.InputType;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.text.style.ForegroundColorSpan;
import android.util.Base64;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
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
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
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
import com.example.tunnel.ui.ConnectButton;
import com.example.tunnel.ui.GlyphDrawable;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Bug Hunter UI (light/dark): Home (connect circle, protocol cards, logs), drawer, one configuration page per
 * protocol (SSH / VLESS / VMess) and Settings. Every field is saved to SharedPreferences as it is typed; the
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
    private final int[] cardGlyph = {GlyphDrawable.SSH, GlyphDrawable.VLESS, GlyphDrawable.VMESS};
    private String shownProtocol;
    private boolean payloadExpanded;
    private HorizontalScrollView logsHsv;      // unused now (logs wrap to the screen), kept so the swipe code stays simple
    private LinearLayout infoCard;
    private TextView infoExpiry, infoMsg;
    private boolean followLogs = true;
    private android.view.ViewTreeObserver.OnScrollChangedListener logScrollListener;
    private PopupWindow menuPopup;
    private String pendingFile;          // "import:SSH" / "export:VLESS" while the file picker is open
    private static final String DEFAULT_SERVER = "naruto.freessh.indevs.in";
    private static final String[] SSH_KEYS = {"sshHost", "user", "pass", "proxyHost", "proxyPort", "sni", "payload", "transport", "wsFrames"};
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

    private final ActivityResultLauncher<Intent> fileResult = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                String job = pendingFile;
                pendingFile = null;
                Intent data = result.getData();
                if (job == null || result.getResultCode() != RESULT_OK || data == null || data.getData() == null) return;
                String[] t = job.split(":");
                final Uri uri = data.getData();
                guarded(() -> {
                    if ("import".equals(t[0])) {
                        importBytes(t[1], readBytes(uri));
                    } else {
                        writeBytes(uri, "anika".equals(t[0]) ? exportAnika(t[1])
                                : exportJson(t[1]).getBytes(Charset.forName("UTF-8")));
                        Toast.makeText(this, "Exported", Toast.LENGTH_SHORT).show();
                    }
                });
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
        refreshInfo();
    }

    @Override
    protected void onDestroy() {
        TunnelState.setListener(null);
        dismissMenu();
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
            boolean logsIt = !open && "home".equals(page) && dx < -dp(72) && horizontal;
            boolean backIt = !open && "logs".equals(page) && dx > dp(72) && horizontal
                    && (logsHsv == null || logsHsv.getScrollX() == 0);
            if (openIt || closeIt || logsIt || backIt) {
                dragTracking = false;
                MotionEvent cancel = MotionEvent.obtain(e);
                cancel.setAction(MotionEvent.ACTION_CANCEL);
                super.dispatchTouchEvent(cancel);
                cancel.recycle();
                if (openIt) openDrawer();
                else if (closeIt) closeDrawer();
                else if (logsIt) show("logs");
                else show("home");
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
        logo.setImageResource(R.drawable.nanika_avatar);
        logo.setScaleType(ImageView.ScaleType.CENTER_CROP);
        logo.setOutlineProvider(new ViewOutlineProvider() {
            @Override public void getOutline(View v, Outline o) { o.setOval(0, 0, v.getWidth(), v.getHeight()); }
        });
        logo.setClipToOutline(true);
        logo.setElevation(dp(2));
        head.addView(logo, new LinearLayout.LayoutParams(dp(50), dp(50)));
        LinearLayout names = new LinearLayout(this);
        names.setOrientation(LinearLayout.VERTICAL);
        names.setPadding(dp(12), 0, 0, 0);
        names.addView(text("Nanika", 20, TEXT, true));
        names.addView(text("Secure \u2022 Fast \u2022 Private", 12, MUTED, false));
        head.addView(names);
        drawer.addView(head, mp(-1, -2, 0, 0, 0, 22));

        drawerItem(R.drawable.ic_home, -1, "Home", "home");
        drawerItem(0, GlyphDrawable.SSH, "SSH", "ssh");
        drawerItem(0, GlyphDrawable.VLESS, "VLESS", "vless");
        drawerItem(0, GlyphDrawable.VMESS, "VMess", "vmess");
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
        TextView title = text("Nanika", 20, TEXT, true);
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
        LinearLayout logsBtn = row();
        logsBtn.setGravity(Gravity.CENTER_VERTICAL);
        logsBtn.setPadding(dp(12), 0, dp(14), 0);
        logsBtn.setBackground(new RippleDrawable(ColorStateList.valueOf(0x55FFFFFF),
                shape(ORANGE, 0, 0, 8), shape(Color.WHITE, 0, 0, 8)));
        logsBtn.setElevation(dp(2));
        logsBtn.addView(icon(R.drawable.ic_terminal, 16, Color.WHITE));
        TextView lt = text("LOGS", 12, Color.WHITE, true);
        lt.setLetterSpacing(0.08f);
        lt.setPadding(dp(7), 0, 0, 0);
        logsBtn.addView(lt);
        logsBtn.setContentDescription("Open logs");
        logsBtn.setOnClickListener(v -> show("logs"));
        pressable(logsBtn, 0.94f);
        bar.addView(logsBtn, mp(-2, 34, 12, 0, 0, 0));
        return bar;
    }

    private View pageBar(String title, final List<MenuItem> menu) {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(10), dp(6));
        ImageView back = icon(R.drawable.ic_back, 26, ORANGE);
        back.setOnClickListener(v -> show("home"));
        pressable(back, 0.88f);
        bar.addView(back);
        TextView t = text(title, 18, TEXT, true);
        t.setPadding(dp(18), 0, 0, 0);
        bar.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        if (menu != null) {
            final ImageView more = icon(R.drawable.ic_more, 26, ORANGE);
            more.setPadding(dp(5), dp(5), dp(5), dp(5));
            more.setContentDescription("More options");
            more.setOnClickListener(v -> showMenu(more, menu));
            pressable(more, 0.85f);
            bar.addView(more, new LinearLayout.LayoutParams(dp(38), dp(38)));
        }
        return bar;
    }

    private View logsBar() {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(14), dp(10), dp(14), dp(6));
        ImageView back = icon(R.drawable.ic_back, 26, ORANGE);
        back.setOnClickListener(v -> show("home"));
        pressable(back, 0.88f);
        bar.addView(back);
        TextView t = text("Logs", 18, TEXT, true);
        t.setPadding(dp(18), 0, 0, 0);
        bar.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        TextView clear = text("CLEAR", 12, ORANGE, true);
        clear.setPadding(dp(10), dp(8), dp(10), dp(8));
        clear.setOnClickListener(v -> { TunnelState.clearLog(); renderLog(); });
        pressable(clear, 0.92f);
        bar.addView(clear);
        ImageView copy = icon(R.drawable.ic_copy, 22, ORANGE);
        copy.setPadding(dp(3), dp(3), dp(3), dp(3));
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("log", TunnelState.logText()));
            Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show();
        });
        pressable(copy, 0.88f);
        bar.addView(copy, new LinearLayout.LayoutParams(dp(30), dp(30)));
        return bar;
    }

    private void show(String target) {
        page = target;
        clearHomeRefs();
        toolbarHolder.removeAllViews();
        body.removeAllViews();
        hideKeyboard();
        body.setLayoutTransition(null);
        dismissMenu();
        if ("home".equals(target)) {
            toolbarHolder.addView(homeBar());
            buildHome();
        } else if ("logs".equals(target)) {
            toolbarHolder.addView(logsBar());
            buildLogs();
        } else if ("ssh".equals(target)) {
            toolbarHolder.addView(pageBar("SSH Configuration", menuFor("SSH")));
            buildSsh();
        } else if ("vless".equals(target)) {
            toolbarHolder.addView(pageBar("VLESS Configuration", menuFor("VLESS")));
            buildWsConfig("VLESS");
        } else if ("vmess".equals(target)) {
            toolbarHolder.addView(pageBar("VMess Configuration", menuFor("VMess")));
            buildWsConfig("VMess");
        } else {
            toolbarHolder.addView(pageBar("Settings", null));
            buildSettings();
        }
        scroll.scrollTo(0, 0);
        animateIn();
        body.post(() -> body.setLayoutTransition(bodyTransition));
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
        if (logScrollListener != null && scroll != null) {
            scroll.getViewTreeObserver().removeOnScrollChangedListener(logScrollListener);
            logScrollListener = null;
        }
        infoCard = null; infoExpiry = null; infoMsg = null;
        connectBtn = null; statusIcon = null;
        statusText = null; dotView = null; dotSpinner = null; logView = null; logsHsv = null;
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
                refreshHome();
                refreshInfo();
            });
            pressable(cell, 0.95f);
            cards.addView(cell, mp(0, 88, i == 0 ? 0 : 5, 0, i == 2 ? 0 : 5, 0, 1));
        }
        body.addView(cards);

        infoCard = new LinearLayout(this);
        infoCard.setOrientation(LinearLayout.VERTICAL);
        infoCard.setBackground(shape(CARD, BORDER, 1, 12));
        infoCard.setElevation(dp(2));
        infoCard.setPadding(dp(14), dp(12), dp(14), dp(12));
        infoExpiry = text("", 13, TEXT, true);
        infoMsg = text("", 12, TEXT, false);
        infoMsg.setTypeface(Typeface.MONOSPACE);
        infoCard.addView(infoExpiry);
        infoCard.addView(infoMsg, mp(-1, -2, 0, 8, 0, 0));
        body.addView(infoCard, mp(-1, -2, 0, 18, 0, 0));

        shownProtocol = null;
        updateCards(false);
        refreshHome();
        refreshInfo();
    }

    private float spPx(float sp) {
        return TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, sp, getResources().getDisplayMetrics());
    }

    /** Largest monospace size (<= maxPx) at which the widest line of the text still fits in availPx. */
    private float fitSize(CharSequence text, float availPx, float maxPx, float minPx) {
        Paint pt = new Paint();
        pt.setTypeface(Typeface.MONOSPACE);
        pt.setTextSize(100f);
        float widest = 0f;
        for (String line : text.toString().split("\n")) widest = Math.max(widest, pt.measureText(line));
        if (widest <= 0f) return maxPx;
        return Math.max(minPx, Math.min(maxPx, 100f * availPx / widest));
    }

    /** Expiry line + HTML message of the selected protocol's configuration, shown under the protocol cards. */
    private void refreshInfo() {
        if (infoCard == null) return;
        String exp = nz(p(protocol, "expiry", ""));
        String msg = p(protocol, "message", "");
        boolean hasExp = !exp.isEmpty(), hasMsg = !msg.trim().isEmpty();
        infoCard.setVisibility(hasExp || hasMsg ? View.VISIBLE : View.GONE);
        if (hasExp) {
            int color = TEXT;
            String label = "Expiry: " + exp;
            try {
                Date d = new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(exp);
                Calendar today = Calendar.getInstance();
                today.set(Calendar.HOUR_OF_DAY, 0); today.set(Calendar.MINUTE, 0);
                today.set(Calendar.SECOND, 0); today.set(Calendar.MILLISECOND, 0);
                long days = Math.round((d.getTime() - today.getTimeInMillis()) / 86400000.0);
                if (days > 3) { label = "Expires " + exp + "  \u2022  " + days + " days left"; color = GREEN; }
                else if (days > 0) { label = "Expires " + exp + "  \u2022  " + days + (days == 1 ? " day left" : " days left"); color = ORANGE; }
                else if (days == 0) { label = "Expires today"; color = ORANGE; }
                else { label = "Expired " + exp + "  \u2022  " + (-days) + (days == -1 ? " day ago" : " days ago"); color = RED; }
            } catch (java.text.ParseException ignored) { }
            infoExpiry.setText(label);
            infoExpiry.setTextColor(color);
            infoExpiry.setVisibility(View.VISIBLE);
        } else {
            infoExpiry.setVisibility(View.GONE);
        }
        if (hasMsg) {
            CharSequence sp = bannerToSpanned(msg);
            float avail = getResources().getDisplayMetrics().widthPixels - dp(36) - dp(28) - dp(4);
            infoMsg.setTextSize(TypedValue.COMPLEX_UNIT_PX, fitSize(sp, avail, spPx(12), spPx(5)));
            infoMsg.setText(sp);
            infoMsg.setVisibility(View.VISIBLE);
        } else {
            infoMsg.setVisibility(View.GONE);
        }
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
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(shape(CARD, ORANGE, 2, 12));
        card.setElevation(dp(2));
        card.setPadding(dp(12), dp(12), dp(12), dp(12));
        logView = text("", 11, TEXT, false);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextIsSelectable(true);
        logView.setHighlightColor(0x55F26B21);
        card.addView(logView, new LinearLayout.LayoutParams(-1, -2));
        body.addView(card, mp(-1, -2, 0, 0, 0, 0));
        followLogs = true;
        // whenever the text grows and the reader is at the bottom, stay at the bottom
        logView.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, orr, ob) -> {
            if (followLogs && (b - t) != (ob - ot)) pinLogsToBottom();
        });
        logScrollListener = () -> { if (logView != null) followLogs = nearLogBottom(); };
        scroll.getViewTreeObserver().addOnScrollChangedListener(logScrollListener);
        renderLog();
        pinLogsToBottom();
    }

    private void pinLogsToBottom() {
        Runnable down = () -> {
            View c = scroll.getChildAt(0);
            if (c != null) scroll.scrollTo(0, c.getHeight());
        };
        scroll.post(down);
        scroll.postDelayed(down, 90);
    }

    private float logAvailPx() {
        return getResources().getDisplayMetrics().widthPixels - dp(36) - dp(24) - dp(4);
    }

    private void renderLog() {
        if (logView == null) return;
        SpannableStringBuilder sb = new SpannableStringBuilder();
        for (String e : TunnelState.logEntries()) appendEntry(sb, e);
        if (sb.length() == 0) {
            sb.append("No logs yet. Connect and the server responses (101 Switching Protocols, SSH banner) show up here.");
            sb.setSpan(new ForegroundColorSpan(MUTED), 0, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        logView.setText(sb);
    }

    /** Adds one stored log entry (a normal line, or a multi-line SSH banner) to the builder. */
    private void appendEntry(SpannableStringBuilder sb, String entry) {
        if (entry == null || entry.isEmpty()) return;
        if (entry.charAt(0) == TunnelState.BANNER) {
            int i = entry.indexOf(TunnelState.BANNER, 1);
            if (i < 0) return;
            int start = sb.length();
            sb.append("[").append(entry.substring(1, i)).append("] SSH banner:\n");
            sb.setSpan(new ForegroundColorSpan(ORANGE), start, sb.length() - 1, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            CharSequence banner = bannerToSpanned(entry.substring(i + 1));
            int bs = sb.length();
            sb.append(banner);
            float px = fitSize(banner, logAvailPx(), spPx(11), spPx(5));     // shrink wide ASCII art to fit, never scroll sideways
            if (px < spPx(11) - 0.5f) sb.setSpan(new AbsoluteSizeSpan((int) px, false), bs, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            if (sb.length() == 0 || sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
            return;
        }
        if (!passesLogFilter(entry)) return;
        int start = sb.length();
        sb.append(entry).append('\n');
        String l = entry.toLowerCase(Locale.US);
        int color = 0;
        if (l.contains(" 101 ") || l.contains("logged in") || l.contains("established")) color = GREEN;
        else if (l.contains("error") || l.contains("fail") || l.contains("rejected") || l.contains("denied")
                || l.contains("refused") || l.contains("lost")) color = RED;
        if (color != 0) sb.setSpan(new ForegroundColorSpan(color), start, sb.length() - 1, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    /**
     * Turns an SSH banner into styled text. Plain banners stay as they are. HTML banners (font colours, h1-h6,
     * br, b, i ...) are rendered; line breaks and runs of spaces in the source are kept so ASCII art stays aligned.
     */
    private CharSequence bannerToSpanned(String raw) {
        String text = raw.replace("\r\n", "\n").replace('\r', '\n');
        if (!text.matches("(?s).*<\\s*/?\\s*[a-zA-Z][^>]*>.*")) return text;
        StringBuilder out = new StringBuilder(text.length() * 2);
        boolean inTag = false, skipNl = false;
        StringBuilder tag = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inTag) {
                out.append(ch);
                tag.append(ch);
                if (ch == '>') {
                    inTag = false;
                    skipNl = tag.length() > 1 && tag.charAt(1) != '/';     // newline right after an opening tag is layout only
                }
            } else if (ch == '<') {
                inTag = true;
                tag.setLength(0);
                tag.append(ch);
                out.append(ch);
            } else if (ch == '\n') {
                if (skipNl) skipNl = false; else out.append("<br>");
            } else {
                skipNl = false;
                if (ch == ' ') out.append("&nbsp;");
                else if (ch == '\t') out.append("&nbsp;&nbsp;&nbsp;&nbsp;");
                else out.append(ch);
            }
        }
        if (Build.VERSION.SDK_INT >= 24) return Html.fromHtml(out.toString(), Html.FROM_HTML_MODE_LEGACY);
        return Html.fromHtml(out.toString());
    }

    private boolean nearLogBottom() {
        View c = scroll.getChildAt(0);
        return c == null || c.getBottom() - (scroll.getHeight() + scroll.getScrollY()) < dp(160);
    }

    @Override
    public void onLog(String line) {
        if (logView == null) return;
        SpannableStringBuilder sb = new SpannableStringBuilder();
        appendEntry(sb, line);
        if (sb.length() == 0) return;
        followLogs = nearLogBottom();
        if (logView.getText().toString().startsWith("No logs yet")) logView.setText(sb); else logView.append(sb);
        if (followLogs) pinLogsToBottom();
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
        add(collapsible, rowField("Server Address", fieldSized(field(P, "sshHost", "server address", DEFAULT_SERVER))));

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
        addInfoSection(P, collapsible);
        addButtons(() -> {
            String[] keys = {"sshHost", "user", "pass", "proxyHost", "proxyPort", "sni", "payload", "transport", "wsFrames", "expiry", "message"};
            SharedPreferences.Editor e = prefs.edit();
            for (String k : keys) e.remove(P + "_" + k);
            e.apply();
            Toast.makeText(this, "SSH settings reset", Toast.LENGTH_SHORT).show();
            show("ssh");
        });
    }

    /** Expiry date + HTML message that travel with a configuration and are shown on the home page. */
    private void addInfoSection(String P, List<View> into) {
        List<View> parts = new ArrayList<View>();
        parts.add(section("EXPIRY & MESSAGE"));
        final EditText exp = field(P, "expiry", "YYYY-MM-DD (optional)", "");
        exp.setFocusable(false);
        exp.setCursorVisible(false);
        exp.setClickable(true);
        exp.setOnClickListener(v -> pickDate(exp));
        parts.add(rowField("Expiry", fieldSized(exp)));
        LinearLayout lab = row();
        lab.addView(text("Message (HTML)", 13, TEXT, false));
        parts.add(lab);
        parts.add(multilineField(P, "message", "<font color=\"#ff3333\">Welcome!</font><br>Valid until the expiry date", 90));
        for (View v : parts) {
            if (v instanceof EditText) body.addView(v, mp(-1, -2, 0, 4, 0, 0)); else body.addView(v);
            if (into != null) into.add(v);
        }
    }

    private void pickDate(final EditText target) {
        Calendar c = Calendar.getInstance();
        try {
            Date d = new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(target.getText().toString().trim());
            if (d != null) c.setTime(d);
        } catch (java.text.ParseException ignored) { }
        DatePickerDialog dlg = new DatePickerDialog(this, (view, y, mo, d) ->
                target.setText(String.format(Locale.US, "%04d-%02d-%02d", y, mo + 1, d)),
                c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH));
        dlg.setButton(DatePickerDialog.BUTTON_NEUTRAL, "Clear", (d2, w) -> target.setText(""));
        dlg.show();
    }

    // ================================================================== three-dots menus

    private static final class MenuItem {
        final String label;
        final Runnable action;
        final List<MenuItem> children;
        MenuItem(String label, Runnable action, List<MenuItem> children) {
            this.label = label;
            this.action = action;
            this.children = children;
        }
    }

    private static MenuItem item(String label, Runnable action) { return new MenuItem(label, action, null); }

    private static MenuItem group(String label, MenuItem... kids) {
        return new MenuItem(label, null, new ArrayList<MenuItem>(Arrays.asList(kids)));
    }

    private List<MenuItem> menuFor(final String P) {
        List<MenuItem> m = new ArrayList<MenuItem>();
        if ("SSH".equals(P)) {
            m.add(item("Import file", () -> pickFile("import", P)));
            m.add(item("Export file (.anika)", () -> pickFile("anika", P)));
            m.add(group("Inject payload",
                    item("Cloudflare", () -> comingSoon("Cloudflare")),
                    item("Enhanced", () -> comingSoon("Enhanced")),
                    item("Direct", () -> comingSoon("Direct"))));
        } else {
            m.add(group("Import",
                    item("From clipboard", () -> guarded(() -> importClipboard(P))),
                    item("From file (.anika / JSON)", () -> pickFile("import", P))));
            m.add(group("Export",
                    item("To clipboard (link)", () -> guarded(() -> exportClipboard(P))),
                    item("To file (.anika)", () -> pickFile("anika", P)),
                    item("To JSON file", () -> pickFile("json", P))));
        }
        return m;
    }

    private void comingSoon(String name) {
        Toast.makeText(this, name + " payload injection is not available yet", Toast.LENGTH_SHORT).show();
    }

    private void dismissMenu() {
        if (menuPopup != null) {
            try { menuPopup.dismiss(); } catch (RuntimeException ignored) { }
            menuPopup = null;
        }
    }

    private void showMenu(View anchor, List<MenuItem> items) {
        dismissMenu();
        final int cardW = dp(226);
        final int pad = dp(12);
        FrameLayout frame = new FrameLayout(this);
        frame.setPadding(pad, pad, pad, pad);
        final LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(6), dp(6), dp(6), dp(6));
        card.setBackground(shape(CARD, BORDER, 1, 14));
        card.setElevation(dp(8));
        frame.addView(card, new FrameLayout.LayoutParams(cardW, -2));
        final PopupWindow pw = new PopupWindow(frame, cardW + 2 * pad, ViewGroup.LayoutParams.WRAP_CONTENT, true);
        pw.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        pw.setAnimationStyle(0);
        pw.setOutsideTouchable(true);
        fillMenu(card, pw, null, items, items);
        menuPopup = pw;
        pw.showAsDropDown(anchor, anchor.getWidth() - (cardW + 2 * pad) + dp(6), -dp(10));
        card.setPivotX(cardW);
        card.setPivotY(0);
        card.setScaleX(0.82f);
        card.setScaleY(0.82f);
        card.setAlpha(0f);
        card.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(200)
                .setInterpolator(new DecelerateInterpolator(1.6f)).start();
    }

    private void fillMenu(final LinearLayout card, final PopupWindow pw, String header,
                          List<MenuItem> items, final List<MenuItem> root) {
        card.removeAllViews();
        if (header != null) {
            TextView back = text("\u2039   " + header, 14, ORANGE, true);
            back.setGravity(Gravity.CENTER_VERTICAL);
            back.setPadding(dp(14), 0, dp(14), 0);
            back.setBackground(rippled(null, 10));
            back.setOnClickListener(v -> swapMenu(card, pw, null, root, root));
            card.addView(back, new LinearLayout.LayoutParams(-1, dp(44)));
        }
        for (final MenuItem it : items) {
            LinearLayout row = row();
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(14), 0, dp(12), 0);
            row.setBackground(rippled(null, 10));
            row.addView(text(it.label, 15, TEXT, false), new LinearLayout.LayoutParams(0, -2, 1));
            if (it.children != null) row.addView(text("\u203A", 20, ORANGE, true));
            row.setOnClickListener(v -> {
                if (it.children != null) {
                    swapMenu(card, pw, it.label, it.children, root);
                } else {
                    pw.dismiss();
                    if (it.action != null) it.action.run();
                }
            });
            card.addView(row, new LinearLayout.LayoutParams(-1, dp(46)));
        }
    }

    private void swapMenu(final LinearLayout card, final PopupWindow pw, final String header,
                          final List<MenuItem> items, final List<MenuItem> root) {
        card.animate().alpha(0f).setDuration(90).withEndAction(() -> {
            fillMenu(card, pw, header, items, root);
            card.animate().alpha(1f).setDuration(140).start();
        }).start();
    }

    // ================================================================== import / export

    private void guarded(Runnable r) {
        try {
            r.run();
        } catch (IllegalArgumentException | IllegalStateException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void pickFile(String kind, String P) {
        Intent i;
        if ("import".equals(kind)) {
            i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
        } else {
            boolean anika = "anika".equals(kind);
            i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType(anika ? "application/octet-stream" : "application/json");
            i.putExtra(Intent.EXTRA_TITLE, "nanika-" + P.toLowerCase(Locale.US) + (anika ? ".anika" : ".json"));
        }
        pendingFile = kind + ":" + P;
        try {
            fileResult.launch(i);
        } catch (RuntimeException e) {
            pendingFile = null;
            Toast.makeText(this, "No file picker available on this device", Toast.LENGTH_LONG).show();
        }
    }

    private void importClipboard(String P) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        String text = "";
        if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip() != null && cm.getPrimaryClip().getItemCount() > 0) {
            CharSequence cs = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
            if (cs != null) text = cs.toString();
        }
        if (text.trim().isEmpty()) throw new IllegalArgumentException("The clipboard is empty");
        importText(P, text);
    }

    private void exportClipboard(String P) {
        String text = exportText(P);
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("config", text));
        Toast.makeText(this, P + " link copied to the clipboard", Toast.LENGTH_SHORT).show();
    }

    private byte[] readBytes(Uri uri) {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("Cannot open that file");
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n, total = 0;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > 512 * 1024) throw new IllegalArgumentException("That file is too large to be a configuration");
                bo.write(buf, 0, n);
            }
            return bo.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Could not read the file: " + e.getMessage());
        }
    }

    private void writeBytes(Uri uri, byte[] data) {
        try (OutputStream os = getContentResolver().openOutputStream(uri, "wt")) {
            if (os == null) throw new IllegalStateException("Cannot write that file");
            os.write(data);
        } catch (IOException e) {
            throw new IllegalStateException("Could not write the file: " + e.getMessage());
        }
    }

    private static String enc(String v) {
        try {
            return URLEncoder.encode(v, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return v;
        }
    }

    private static String nz(String v) { return v == null ? "" : v.trim(); }

    private static final String[] WS_KEYS = {"uuid", "server", "connectIp", "port", "transport", "sni", "path", "insecure"};

    private static String[] keysFor(String P) {
        String[] base = "SSH".equals(P) ? SSH_KEYS : WS_KEYS;
        String[] all = Arrays.copyOf(base, base.length + 2);
        all[base.length] = "expiry";
        all[base.length + 1] = "message";
        return all;
    }

    private static String niceName(String type) {
        return "vless".equals(type) ? "VLESS" : "vmess".equals(type) ? "VMess" : "ssh".equals(type) ? "SSH" : type;
    }

    /** Everything on the page (including expiry and message) as one JSON object. */
    private JSONObject configJson(String P) {
        try {
            JSONObject o = new JSONObject();
            o.put("app", "nanika");
            o.put("version", 1);
            o.put("type", P.toLowerCase(Locale.US));
            java.util.Map<String, ?> all = prefs.getAll();
            for (String k : keysFor(P)) {
                Object v = all.get(P + "_" + k);
                if (v instanceof String || v instanceof Boolean) o.put(k, v);
            }
            if ("SSH".equals(P) && !o.has("sshHost")) o.put("sshHost", DEFAULT_SERVER);
            return o;
        } catch (JSONException e) {
            throw new IllegalStateException("Could not build the export: " + e.getMessage());
        }
    }

    private String exportJson(String P) {
        try {
            return configJson(P).toString(2);
        } catch (JSONException e) {
            throw new IllegalStateException("Could not build the export: " + e.getMessage());
        }
    }

    /** Encrypted .anika file contents. */
    private byte[] exportAnika(String P) {
        try {
            return AnikaCrypto.encrypt(configJson(P).toString());
        } catch (Exception e) {
            throw new IllegalStateException("Could not encrypt the export: " + e.getMessage());
        }
    }

    /** vless:// or vmess:// link for the clipboard. */
    private String exportText(String P) {
        try {
            String uuid = p(P, "uuid", "").trim();
            String server = p(P, "server", "").trim();
            String ip = p(P, "connectIp", "").trim();
            if (uuid.isEmpty()) throw new IllegalStateException("The UUID is empty - fill in the " + P + " page first");
            String host = ip.isEmpty() ? server : ip;
            if (host.isEmpty()) throw new IllegalStateException("Connect host / server is empty - fill in the " + P + " page first");
            int port = intOr(p(P, "port", "443"), 443);
            boolean tls = tlsOn(P);
            String sni = p(P, "sni", "").trim();
            if (sni.isEmpty()) sni = server.isEmpty() ? host : server;
            String path = p(P, "path", "").trim();
            if (path.isEmpty()) path = "/";
            if (!path.startsWith("/")) path = "/" + path;
            boolean insecure = prefs.getBoolean(P + "_insecure", false);

            if ("VLESS".equals(P)) {
                StringBuilder u = new StringBuilder("vless://").append(uuid).append('@')
                        .append(host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host)
                        .append(':').append(port)
                        .append("?encryption=none&security=").append(tls ? "tls" : "none");
                if (tls) u.append("&sni=").append(enc(sni)).append("&fp=chrome");
                u.append("&type=ws");
                if (!server.isEmpty()) u.append("&host=").append(enc(server));
                u.append("&path=").append(enc(path));
                if (insecure) u.append("&allowInsecure=1");
                u.append("#Nanika-VLESS");
                return u.toString();
            }
            JSONObject o = new JSONObject();
            o.put("v", "2");
            o.put("ps", "Nanika-VMess");
            o.put("add", host);
            o.put("port", String.valueOf(port));
            o.put("id", uuid);
            o.put("aid", "0");
            o.put("scy", "auto");
            o.put("net", "ws");
            o.put("type", "none");
            o.put("host", server);
            o.put("path", path);
            o.put("tls", tls ? "tls" : "");
            o.put("sni", tls ? sni : "");
            return "vmess://" + Base64.encodeToString(o.toString().getBytes(Charset.forName("UTF-8")), Base64.NO_WRAP);
        } catch (JSONException e) {
            throw new IllegalStateException("Could not build the export: " + e.getMessage());
        }
    }

    /** .anika (encrypted) or plain text/JSON/link read from a file. */
    private void importBytes(String P, byte[] data) {
        String text = AnikaCrypto.looksEncrypted(data) ? AnikaCrypto.decrypt(data)
                : new String(data, Charset.forName("UTF-8"));
        importText(P, text);
    }

    private void importText(String P, String raw) {
        if (raw == null || raw.trim().isEmpty()) throw new IllegalArgumentException("Nothing to import - the text is empty");
        String text = raw.trim();
        if (text.startsWith("\uFEFF")) text = text.substring(1).trim();
        if (text.startsWith("{")) {
            importConfigJson(P, text);
        } else if ("SSH".equals(P)) {
            throw new IllegalArgumentException("That is not a Nanika SSH file");
        } else {
            String scheme = P.toLowerCase(Locale.US) + "://";
            String link = null;
            for (String tok : text.split("\\s+")) {
                if (tok.toLowerCase(Locale.US).startsWith(scheme)) { link = tok; break; }
            }
            if (link == null) {
                String other = "vless".equals(P.toLowerCase(Locale.US)) ? "vmess://" : "vless://";
                if (text.toLowerCase(Locale.US).contains(other)) {
                    throw new IllegalArgumentException("That is a " + other + " link - import it on the "
                            + ("vless://".equals(other) ? "VLESS" : "VMess") + " page");
                }
                throw new IllegalArgumentException("No " + scheme + " link found");
            }
            // a link carries no expiry / message, so keep whatever this page already has
            if ("VLESS".equals(P)) importVless(link); else importVmess(link);
        }
        Toast.makeText(this, P + " configuration imported", Toast.LENGTH_SHORT).show();
        show(P.toLowerCase(Locale.US));
    }

    private void importConfigJson(String P, String text) {
        JSONObject o;
        try {
            o = new JSONObject(text);
        } catch (JSONException e) {
            throw new IllegalArgumentException("That is not a valid configuration file");
        }
        String type = o.optString("type", "").toLowerCase(Locale.US);
        if (type.equals("bughunter-ssh")) type = "ssh";
        if (!type.isEmpty() && !type.equals(P.toLowerCase(Locale.US))) {
            throw new IllegalArgumentException("That file is a " + niceName(type) + " configuration - import it on the "
                    + niceName(type) + " page");
        }
        String uuid = o.optString("uuid", "");
        if (!"SSH".equals(P) && !uuid.isEmpty() && !validUuid(uuid.trim())) {
            throw new IllegalArgumentException("The file has an invalid UUID");
        }
        SharedPreferences.Editor e = prefs.edit();
        int n = 0;
        for (String k : keysFor(P)) {
            Object v = o.opt(k);
            if (v instanceof String) { e.putString(P + "_" + k, (String) v); n++; }
            else if (v instanceof Boolean) { e.putBoolean(P + "_" + k, (Boolean) v); n++; }
            else if ((k.equals("expiry") || k.equals("message"))) e.remove(P + "_" + k);   // no stale expiry from before
        }
        if (n == 0) throw new IllegalArgumentException("That file has no settings in it");
        e.apply();
    }

    private static boolean validUuid(String u) {
        return u != null && u.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }

    private void storeWsConfig(String P, String uuid, String connect, int port, boolean tls, String sni,
                               String server, String path, boolean insecure) {
        prefs.edit()
                .putString(P + "_uuid", uuid)
                .putString(P + "_connectIp", connect)
                .putString(P + "_port", String.valueOf(port))
                .putString(P + "_transport", tls ? "TLS" : "Non-TLS")
                .putString(P + "_sni", sni)
                .putString(P + "_server", server)
                .putString(P + "_path", path.isEmpty() ? "/" : path)
                .putBoolean(P + "_insecure", insecure)
                .apply();
    }

    private void importVless(String link) {
        Uri u = Uri.parse(link);
        String uuid = nz(u.getUserInfo());
        if (!validUuid(uuid)) throw new IllegalArgumentException("The vless:// link has no valid UUID");
        String host = nz(u.getHost());
        if (host.isEmpty()) throw new IllegalArgumentException("The vless:// link has no server address");
        int port = u.getPort() > 0 ? u.getPort() : 443;
        String type = nz(u.getQueryParameter("type")).toLowerCase(Locale.US);
        if (!type.isEmpty() && !type.equals("ws")) {
            throw new IllegalArgumentException("Only WebSocket links are supported (this one is type=" + type + ")");
        }
        String sec = nz(u.getQueryParameter("security")).toLowerCase(Locale.US);
        if (sec.equals("reality")) throw new IllegalArgumentException("REALITY links are not supported");
        boolean tls = sec.equals("tls");
        String hostParam = nz(u.getQueryParameter("host"));
        String sniParam = nz(u.getQueryParameter("sni"));
        String sni = !sniParam.isEmpty() ? sniParam : !hostParam.isEmpty() ? hostParam : host;
        String server = !hostParam.isEmpty() ? hostParam : sni;
        String path = nz(u.getQueryParameter("path"));
        String ins = nz(u.getQueryParameter("allowInsecure")) + nz(u.getQueryParameter("insecure"));
        storeWsConfig("VLESS", uuid, host, port, tls, sni, server, path, ins.startsWith("1") || ins.startsWith("true"));
    }

    private void importVmess(String link) {
        String b64 = link.substring("vmess://".length());
        int hash = b64.indexOf('#');
        if (hash >= 0) b64 = b64.substring(0, hash);
        b64 = b64.replaceAll("\\s", "");
        byte[] raw;
        try {
            raw = Base64.decode(b64, Base64.DEFAULT);
        } catch (IllegalArgumentException e1) {
            try {
                raw = Base64.decode(b64, Base64.URL_SAFE);
            } catch (IllegalArgumentException e2) {
                throw new IllegalArgumentException("The vmess:// link is not valid base64");
            }
        }
        JSONObject o;
        try {
            o = new JSONObject(new String(raw, Charset.forName("UTF-8")));
        } catch (JSONException e) {
            throw new IllegalArgumentException("The vmess:// link does not contain a valid configuration");
        }
        String uuid = nz(o.optString("id", ""));
        if (!validUuid(uuid)) throw new IllegalArgumentException("The vmess:// link has no valid UUID");
        String add = nz(o.optString("add", ""));
        if (add.isEmpty()) throw new IllegalArgumentException("The vmess:// link has no server address");
        String net = nz(o.optString("net", "")).toLowerCase(Locale.US);
        if (!net.isEmpty() && !net.equals("ws")) {
            throw new IllegalArgumentException("Only WebSocket links are supported (this one is net=" + net + ")");
        }
        int port = intOr(nz(o.optString("port", "443")), 443);
        boolean tls = nz(o.optString("tls", "")).equalsIgnoreCase("tls");
        String hostParam = nz(o.optString("host", ""));
        String sniParam = nz(o.optString("sni", ""));
        String sni = !sniParam.isEmpty() ? sniParam : !hostParam.isEmpty() ? hostParam : add;
        String server = !hostParam.isEmpty() ? hostParam : sni;
        storeWsConfig("VMess", uuid, add, port, tls, sni, server, nz(o.optString("path", "")), false);
    }

    // ================================================================== VLESS / VMess configuration page

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
        body.addView(stackField("WebSocket Path", fieldSized(field(P, "path", "/ws", ""))));

        body.addView(section("ADVANCED"));
        LinearLayout ins = row();
        ins.setGravity(Gravity.CENTER_VERTICAL);
        ins.addView(text("Insecure TLS", 13, TEXT, false), new LinearLayout.LayoutParams(0, -2, 1));
        ins.addView(toggle(prefs.getBoolean(P + "_insecure", false),
                (b, on) -> prefs.edit().putBoolean(P + "_insecure", on).apply()));
        body.addView(ins, mp(-1, 40, 0, 0, 0, 0));
        body.addView(rowField("DNS", dnsDropdown()));
        addInfoSection(P, null);

        addButtons(() -> {
            String[] keys = {"uuid", "server", "connectIp", "port", "sni", "path", "transport", "insecure", "expiry", "message"};
            SharedPreferences.Editor e = prefs.edit();
            for (String k : keys) e.remove(P + "_" + k);
            e.apply();
            Toast.makeText(this, P + " settings reset", Toast.LENGTH_SHORT).show();
            show(P.toLowerCase(Locale.US));
        });
    }

    // ================================================================== Settings page

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
        body.addView(settingRow("Hide server in logs", toggle(prefs.getBoolean("hideHosts", true),
                (b, on) -> prefs.edit().putBoolean("hideHosts", on).apply())));
        body.addView(settingRow("Theme", dropdown(new String[]{"Light", "Dark"}, prefs.getString("theme", "Light"), v -> {
            if (v.equals(prefs.getString("theme", "Light"))) return;
            prefs.edit().putString("theme", v).apply();
            recreate();
        })));

        Button reset = outlineButton("RESET TO DEFAULTS");
        reset.setOnClickListener(v -> {
            boolean themeChanged = !"Light".equals(prefs.getString("theme", "Light"));
            prefs.edit().remove("dns").remove("logLevel").remove("verifyCerts").remove("allowInsecure")
                    .remove("autoReconnect").remove("hideHosts").remove("theme").apply();
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
        pc.sshHost = p(P, "sshHost", DEFAULT_SERVER).trim();
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

    /** Tells the log layer which server names to blank out (Settings > Hide server in logs). */
    private void applyLogMask() {
        List<String> hosts = new ArrayList<String>();
        if ("SSH".equals(protocol)) {
            hosts.add(p("SSH", "proxyHost", "").trim());
            hosts.add(p("SSH", "sshHost", DEFAULT_SERVER).trim());
            hosts.add(p("SSH", "sni", "").trim());
        } else {
            hosts.add(p(protocol, "server", "").trim());
            hosts.add(p(protocol, "connectIp", "").trim());
            hosts.add(p(protocol, "sni", "").trim());
        }
        TunnelState.setMask(prefs.getBoolean("hideHosts", true), hosts);
    }

    private Intent buildIntent() {
        applyLogMask();
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
        return multilineField("SSH", "payload",
                "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]", 130);
    }

    @SuppressLint("ClickableViewAccessibility")
    private EditText multilineField(String P, String key, String hint, int minDp) {
        final String k = P + "_" + key;
        final EditText e = new EditText(this);
        e.setHint(hint);
        e.setText(prefs.getString(k, ""));
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI | EditorInfo.IME_FLAG_NO_FULLSCREEN);
        e.setSingleLine(false);
        e.setHorizontallyScrolling(false);
        e.setMinHeight(dp(minDp));
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

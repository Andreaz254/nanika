package com.example.tunnel;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.text.TextWatcher;
import android.text.Editable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.example.tunnel.protocol.ProtocolConfig;
import com.example.tunnel.protocol.ProtocolRegistry;
import com.example.tunnel.protocol.Uuids;

import java.io.File;
import java.util.List;

public class MainActivity extends AppCompatActivity
        implements TunnelState.Listener {

    private static final int BG = Color.rgb(7, 11, 9);
    private static final int PANEL = Color.rgb(16, 22, 19);
    private static final int CARD = Color.rgb(21, 29, 25);
    private static final int SOFT = Color.rgb(26, 36, 31);
    private static final int ORANGE = Color.rgb(34, 197, 94);
    private static final int ORANGE_DARK = Color.rgb(21, 128, 61);
    private static final int GREEN = Color.rgb(34, 197, 94);
    private static final int RED = Color.rgb(239, 68, 68);
    private static final int PURPLE = Color.rgb(20, 108, 62);
    private static final int WHITE = Color.rgb(255, 255, 255);
    private static final int TEXT = Color.rgb(226, 240, 232);
    private static final int MUTED = Color.rgb(138, 158, 147);
    private static final int DIVIDER = Color.rgb(34, 46, 40);

    private static final String DEFAULT_ENDPOINT =
            "https://scanner.makeli.indevs.in/upload.php";
    private static final String DEFAULT_TOKEN =
            "huX4W8zNYFhW5z1nuXLVFI65rUwMoYxyRSQOOAb9OPA";

    private FrameLayout root;
    private LinearLayout drawer;
    private LinearLayout screen;
    private TextView statusLabel;
    private TextView logView;
    private Button btnConnect;
    private Button menuButton;
    private float drawerSwipeStartX;

    private EditText editUuid;
    private EditText editServer;
    private EditText editConnectIp;
    private EditText editPort;
    private EditText editBug;
    private EditText editPath;
    private EditText editDns;
    private EditText editPayload;
    private EditText editSshPassword;

    private CheckBox checkInsecure;

    private Button tlsButton;
    private Button nonTlsButton;
    private Button sshButton;
    private Button vlessButton;
    private Button vmessButton;

    private String selectedTransport = "TLS";
    private String selectedProtocol = "VLESS";
    private String currentPage = "home";

    private Intent pendingStart;

    private SharedPreferences preferences;

    private TextView hotspotOutput;
    private TextView hotspotStatus;
    private Button scanButton;
    private Button huntButton;
    private Button uploadButton;
    private Button pingButton;
    private Button stopHuntButton;
    private EditText editScanEndpoint;
    private EditText editScanToken;
    private CheckBox checkAutoUpload;
    private HotspotScanner hotspotScanner;
    private boolean huntRunning;
    private File lastArchive;

    private final ActivityResultLauncher<String> locationPermission =
            registerForActivityResult(
                    new ActivityResultContracts.RequestPermission(),
                    granted -> {
                        if (granted) {
                            runHotspotScan();
                        } else if (hotspotOutput != null) {
                            hotspotOutput.setText("Location permission denied. It is required to scan Wi-Fi.");
                        }
                    });

    /* ============================ HOTSPOT PAGE ============================ */

    private void buildHotspotPage() {
        addHeading("Hotspot Scanner");
        addText("Hunt Cloudflare / CloudFront bug hosts behind a captive portal. "
                + "Mirrors the portal, extracts every domain, probes for WebSocket 101 + open proxies, "
                + "zips the evidence and uploads it.");

        addSectionLabel("UPLOAD ENDPOINT");
        editScanEndpoint = createInput(DEFAULT_ENDPOINT,
                preferences.getString("scan_endpoint", DEFAULT_ENDPOINT));
        editScanEndpoint.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                preferences.edit().putString("scan_endpoint", s.toString().trim()).apply();
            }
            @Override public void afterTextChanged(Editable e) {}
        });
        screen.addView(editScanEndpoint);

        editScanToken = createInput("Upload token",
                preferences.getString("scan_token", DEFAULT_TOKEN));
        editScanToken.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                preferences.edit().putString("scan_token", s.toString().trim()).apply();
            }
            @Override public void afterTextChanged(Editable e) {}
        });
        screen.addView(editScanToken);

        checkAutoUpload = new CheckBox(this);
        checkAutoUpload.setText("Upload report when the network is back (Wi-Fi or VPN)");
        checkAutoUpload.setTextColor(TEXT);
        checkAutoUpload.setButtonTintList(android.content.res.ColorStateList.valueOf(ORANGE));
        checkAutoUpload.setChecked(preferences.getBoolean("scan_auto_upload", true));
        checkAutoUpload.setOnCheckedChangeListener((b, v) ->
                preferences.edit().putBoolean("scan_auto_upload", v).apply());
        screen.addView(checkAutoUpload);

        addSectionLabel("ACTIONS");

        LinearLayout row1 = horizontalRow();
        scanButton = modeButton("SCAN WI-FI", ORANGE);
        scanButton.setTextColor(WHITE);
        scanButton.setBackground(roundDrawable(ORANGE, 12));
        huntButton = modeButton("FULL HUNT", ORANGE);
        huntButton.setTextColor(WHITE);
        huntButton.setBackground(roundDrawable(ORANGE, 12));
        row1.addView(scanButton, weightedParams());
        row1.addView(huntButton, weightedParams());
        screen.addView(row1);

        LinearLayout row2 = horizontalRow();
        uploadButton = modeButton("UPLOAD", GREEN);
        uploadButton.setTextColor(WHITE);
        uploadButton.setBackground(roundDrawable(GREEN, 12));
        pingButton = modeButton("TEST LINK", SOFT);
        stopHuntButton = modeButton("STOP", RED);
        stopHuntButton.setTextColor(WHITE);
        stopHuntButton.setBackground(roundDrawable(RED, 12));
        row2.addView(uploadButton, weightedParams());
        row2.addView(pingButton, weightedParams());
        row2.addView(stopHuntButton, weightedParams());
        screen.addView(row2);

        LinearLayout row3 = horizontalRow();
        Button savedButton = modeButton("SAVED HOSTS", SOFT);
        Button copyButton = modeButton("COPY", SOFT);
        row3.addView(savedButton, weightedParams());
        row3.addView(copyButton, weightedParams());
        screen.addView(row3);

        scanButton.setOnClickListener(v -> onScanClicked());
        huntButton.setOnClickListener(v -> runFullHunt());
        uploadButton.setOnClickListener(v -> runManualUpload());
        pingButton.setOnClickListener(v -> runPing());
        stopHuntButton.setOnClickListener(v -> {
            if (hotspotScanner != null) hotspotScanner.cancel();
            huntRunning = false;
            setHuntButtons(true);
            if (hotspotStatus != null) hotspotStatus.setText("Stopped.");
        });
        savedButton.setOnClickListener(v -> showSaved());
        copyButton.setOnClickListener(v -> copyOutput());

        hotspotStatus = new TextView(this);
        hotspotStatus.setTextColor(MUTED);
        hotspotStatus.setTextSize(12);
        hotspotStatus.setPadding(dp(4), dp(14), 0, dp(4));
        hotspotStatus.setText("Idle");
        screen.addView(hotspotStatus);

        addSectionLabel("OUTPUT");

        hotspotOutput = new TextView(this);
        hotspotOutput.setTextColor(TEXT);
        hotspotOutput.setTextSize(11);
        hotspotOutput.setTypeface(Typeface.MONOSPACE);
        hotspotOutput.setPadding(dp(10), dp(10), dp(10), dp(10));
        hotspotOutput.setBackground(roundDrawable(PANEL, 12));
        hotspotOutput.setMinHeight(dp(240));
        hotspotOutput.setTextIsSelectable(true);
        hotspotOutput.setMovementMethod(new ScrollingMovementMethod());
        screen.addView(hotspotOutput, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void setHuntButtons(boolean idle) {
        if (huntButton != null) huntButton.setEnabled(idle);
        if (scanButton != null) scanButton.setEnabled(idle);
        if (uploadButton != null) uploadButton.setEnabled(idle);
        if (pingButton != null) pingButton.setEnabled(idle);
        if (stopHuntButton != null) stopHuntButton.setEnabled(!idle);
    }

    private void onScanClicked() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            locationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION);
        } else {
            runHotspotScan();
        }
    }

    private void runHotspotScan() {
        if (hotspotScanner == null) hotspotScanner = new HotspotScanner(this);
        hotspotOutput.setText("");
        setHuntButtons(false);
        hotspotScanner.scan(new HotspotScanner.Callback() {
            @Override public void onMessage(String line) {
                runOnUiThread(() -> {
                    if (hotspotOutput != null) hotspotOutput.append(line + "\n");
                });
            }
            @Override public void onFinished() {
                runOnUiThread(() -> setHuntButtons(true));
            }
        });
    }

    private void runFullHunt() {
        if (huntRunning) return;

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            locationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION);
            return;
        }

        String endpoint = editScanEndpoint.getText().toString().trim();
        String token = editScanToken.getText().toString().trim();
        if (endpoint.isEmpty()) {
            Toast.makeText(this, "Upload endpoint is empty", Toast.LENGTH_SHORT).show();
            return;
        }

        HotspotScanner.Config cfg = new HotspotScanner.Config();
        cfg.endpoint = endpoint;
        cfg.token = token;
        cfg.upload = checkAutoUpload.isChecked();

        hotspotScanner = new HotspotScanner(this);
        hotspotOutput.setText("");
        huntRunning = true;
        setHuntButtons(false);
        if (hotspotStatus != null) hotspotStatus.setText("Hunting...");

        hotspotScanner.fullHunt(cfg, new HotspotScanner.HuntListener() {
            @Override public void onMessage(String line) {
                runOnUiThread(() -> {
                    if (hotspotOutput != null) hotspotOutput.append(line + "\n");
                });
            }
            @Override public void onProgress(int done, int total) {
                runOnUiThread(() -> {
                    if (hotspotStatus != null) hotspotStatus.setText("Probing " + done + " / " + total);
                });
            }
            @Override public void onFinished(HotspotScanner.Report report) {
                runOnUiThread(() -> {
                    lastArchive = report.zipFile;
                    huntRunning = false;
                    setHuntButtons(true);
                    if (hotspotStatus != null) {
                        hotspotStatus.setText(report.summary()
                                + (report.uploaded ? "  - uploaded" : ""));
                    }
                    if (hotspotOutput != null) {
                        hotspotOutput.append("\n" + report.summary() + "\n");
                        if (report.zipFile != null)
                            hotspotOutput.append("archive: " + report.zipFile.getName() + "\n");
                    }
                    if (report.proxyHits > 0) {
                        Toast.makeText(MainActivity.this,
                                report.proxyHits + " open proxy(ies) saved", Toast.LENGTH_LONG).show();
                    }
                });
            }
        });
    }

    private void runManualUpload() {
        File zip = (lastArchive != null && lastArchive.isFile())
                ? lastArchive : HotspotScanner.newestArchive(this);
        if (zip == null) {
            hotspotOutput.setText("No archive yet - run a FULL HUNT first.\n");
            return;
        }
        if (hotspotStatus != null) hotspotStatus.setText("Uploading " + zip.getName() + "...");
        hotspotOutput.append("\n[up] manual upload of " + zip.getName()
                + " (" + (zip.length() / 1024) + " KB)\n");

        HotspotScanner.Config cfg = new HotspotScanner.Config();
        cfg.endpoint = editScanEndpoint.getText().toString().trim();
        cfg.token = editScanToken.getText().toString().trim();

        HotspotScanner.uploadArchive(this, zip, cfg, new HotspotScanner.HuntListener() {
            @Override public void onMessage(String line) {
                runOnUiThread(() -> {
                    if (hotspotOutput != null) hotspotOutput.append(line + "\n");
                    if (hotspotStatus != null) hotspotStatus.setText(line);
                });
            }
        });
    }

    private void runPing() {
        hotspotOutput.append("\n[ping] testing endpoint...\n");
        HotspotScanner.ping(this, editScanEndpoint.getText().toString().trim(),
                new HotspotScanner.HuntListener() {
                    @Override public void onMessage(String line) {
                        runOnUiThread(() -> {
                            if (hotspotOutput != null) hotspotOutput.append(line + "\n");
                            if (hotspotStatus != null) hotspotStatus.setText(line);
                        });
                    }
                });
    }

    private void showSaved() {
        List<HotspotScanner.FoundHost> hosts = HotspotScanner.Store.hosts(this);
        List<HotspotScanner.FoundHost> proxies = HotspotScanner.Store.proxies(this);

        StringBuilder sb = new StringBuilder();
        sb.append("=== SAVED OPEN PROXIES (").append(proxies.size()).append(") ===\n");
        for (HotspotScanner.FoundHost h : proxies) sb.append(h.line()).append('\n');
        sb.append("\n=== ALL SAVED HOSTS (").append(hosts.size()).append(") ===\n");
        for (HotspotScanner.FoundHost h : hosts) sb.append(h.line()).append('\n');
        if (hosts.isEmpty()) sb.append("(nothing yet - run a full hunt)\n");

        hotspotOutput.setText(sb.toString());
        if (hotspotStatus != null) {
            hotspotStatus.setText(proxies.size() + " proxies / " + hosts.size() + " hosts saved");
        }
    }

    private void copyOutput() {
        if (hotspotOutput == null) return;
        ((ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE))
                .setPrimaryClip(ClipData.newPlainText("scan", hotspotOutput.getText().toString()));
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
    }

    /* ============================ VPN FLOW ============================ */

    private final ActivityResultLauncher<Intent> vpnPermission =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) {
                            launch();
                        } else {
                            pendingStart = null;
                            TunnelState.log("VPN permission denied - cannot start");
                        }
                    });

    private final ActivityResultLauncher<String> notificationPermission =
            registerForActivityResult(
                    new ActivityResultContracts.RequestPermission(),
                    granted -> askVpnPermission());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            getWindow().setStatusBarColor(PANEL);
            getWindow().setNavigationBarColor(BG);
            getWindow().getDecorView().setSystemUiVisibility(0);
        }

        preferences = getSharedPreferences("dark_custom_settings", MODE_PRIVATE);
        selectedProtocol = preferences.getString("protocol", "SSH");
        selectedTransport = preferences.getString(selectedProtocol + "_transport", "TLS");

        editUuid = createInput("UUID / User ID", saved(selectedProtocol, "uuid", ""));
        editServer = createInput("Server / Host Header", saved(selectedProtocol, "server", ""));
        editConnectIp = createInput("Connect IP", saved(selectedProtocol, "connectIp", ""));
        editPort = createInput("Port", saved(selectedProtocol, "port", ""));
        editBug = createInput("SNI / TLS Host", saved(selectedProtocol, "sni", ""));
        editPath = createInput("WebSocket Path", saved(selectedProtocol, "path", ""));
        editDns = createInput("Default DNS server", preferences.getString("dns", "8.8.8.8"));

        editPayload = createInput("Payload", saved(selectedProtocol, "payload", ""));
        editPayload.setSingleLine(false);
        editPayload.setGravity(Gravity.TOP | Gravity.START);
        editPayload.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        editPayload.setMinLines(6);
        editPayload.setMaxLines(16);
        editPayload.setTextIsSelectable(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            editPayload.setShowSoftInputOnFocus(false);
        }
        editPayload.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(180)));
        editPayload.setVerticalScrollBarEnabled(true);
        editPayload.setMovementMethod(new ScrollingMovementMethod());
        editPayload.setOnTouchListener((v, event) -> {
            v.getParent().requestDisallowInterceptTouchEvent(true);
            return false;
        });

        editSshPassword = createInput("SSH Password", preferences.getString("SSH_password", ""));
        editSshPassword.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);

        editPayload.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                preferences.edit().putString(protocolKey("payload"), s.toString()).apply();
                int lines = Math.max(3, Math.min(12, editPayload.getLineCount() + 1));
                ViewGroup.LayoutParams lp = editPayload.getLayoutParams();
                lp.height = dp(Math.max(96, Math.min(280, lines * 24 + 24)));
                editPayload.setLayoutParams(lp);
            }
            @Override public void afterTextChanged(Editable e) {}
        });
        editSshPassword.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                preferences.edit().putString("SSH_password", s.toString()).apply();
            }
            @Override public void afterTextChanged(Editable e) {}
        });

        checkInsecure = new CheckBox(this);
        checkInsecure.setText("Skip TLS certificate verification (insecure)");
        checkInsecure.setTextColor(TEXT);
        checkInsecure.setButtonTintList(android.content.res.ColorStateList.valueOf(ORANGE));
        checkInsecure.setChecked(preferences.getBoolean(selectedProtocol + "_insecure", false));

        attachInputPersistence(editUuid, "uuid");
        attachInputPersistence(editServer, "server");
        attachInputPersistence(editConnectIp, "connectIp");
        attachInputPersistence(editPort, "port");
        attachInputPersistence(editBug, "sni");
        attachInputPersistence(editPath, "path");
        checkInsecure.setOnCheckedChangeListener((button, checked) ->
                preferences.edit().putBoolean(protocolKey("insecure"), checked).apply());

        buildApplication();
        showPage("home");
    }

    private void buildApplication() {
        root = new FrameLayout(this);
        root.setBackgroundColor(BG);

        LinearLayout toolbar = new LinearLayout(this);
        toolbar.setGravity(Gravity.CENTER_VERTICAL);
        toolbar.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        toolbar.setPadding(dp(10), dp(10), dp(10), dp(10));
        toolbar.setBackgroundColor(PANEL);
        toolbar.setElevation(dp(2));

        menuButton = new Button(this);
        menuButton.setText("☰");
        menuButton.setTextSize(22);
        menuButton.setTextColor(TEXT);
        menuButton.setBackgroundColor(Color.TRANSPARENT);
        menuButton.setTranslationY(-dp(4));
        menuButton.setElevation(dp(12));
        menuButton.bringToFront();
        toolbar.addView(menuButton, new LinearLayout.LayoutParams(dp(42), dp(42)));

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.HORIZONTAL);
        brand.setGravity(Gravity.CENTER_VERTICAL);
        brand.setPadding(dp(8), 0, 0, 0);

        View logo = new View(this);
        logo.setBackground(roundDrawable(ORANGE, 14));
        LinearLayout.LayoutParams logoParams = new LinearLayout.LayoutParams(dp(28), dp(28));
        logoParams.setMargins(0, 0, dp(8), 0);
        brand.addView(logo, logoParams);

        TextView title = new TextView(this);
        title.setText("Bug Hunter");
        title.setTextColor(TEXT);
        title.setTextSize(18);
        title.setTypeface(null, Typeface.BOLD);
        brand.addView(title);

        toolbar.addView(brand, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        TextView indicator = new TextView(this);
        indicator.setText("●");
        indicator.setTextSize(16);
        indicator.setTextColor(GREEN);
        toolbar.addView(indicator);

        FrameLayout.LayoutParams toolbarParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.START);
        root.addView(toolbar, toolbarParams);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);

        screen = new LinearLayout(this);
        screen.setOrientation(LinearLayout.VERTICAL);
        screen.setPadding(dp(16), dp(20), dp(16), dp(24));
        scroll.addView(screen);

        FrameLayout.LayoutParams scrollParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
                Gravity.TOP | Gravity.START);
        scrollParams.topMargin = dp(56);
        root.addView(scroll, scrollParams);

        drawer = new LinearLayout(this);
        drawer.setOrientation(LinearLayout.VERTICAL);
        drawer.setPadding(dp(12), dp(12), dp(12), dp(12));
        drawer.setBackgroundColor(PANEL);
        drawer.setElevation(dp(10));
        drawer.setVisibility(View.GONE);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(4), dp(4), dp(4), dp(12));

        View shield = new View(this);
        shield.setBackground(roundDrawable(ORANGE, 16));
        LinearLayout.LayoutParams shieldParams = new LinearLayout.LayoutParams(dp(30), dp(30));
        shieldParams.setMargins(0, 0, dp(10), 0);
        header.addView(shield, shieldParams);

        LinearLayout brandStack = new LinearLayout(this);
        brandStack.setOrientation(LinearLayout.HORIZONTAL);
        brandStack.setGravity(Gravity.CENTER_VERTICAL);
        TextView brandTitle = new TextView(this);
        brandTitle.setText("Bug Hunter");
        brandTitle.setTextColor(TEXT);
        brandTitle.setTextSize(20);
        brandTitle.setTypeface(null, Typeface.BOLD);
        TextView brandSub = new TextView(this);
        brandSub.setText("VPN");
        brandSub.setTextColor(MUTED);
        brandSub.setTextSize(10);
        brandSub.setPadding(dp(8), 0, 0, 0);
        brandStack.addView(brandTitle);
        brandStack.addView(brandSub);
        header.addView(brandStack);
        drawer.addView(header);
        drawer.addView(new View(this), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(1)));

        addNavItem("SSH", "ssh", "⌁");
        addNavItem("VLESS", "vless", "✦");
        addNavItem("VMess", "vmess", "◫");
        addNavItem("HOTSPOT SCANNER", "hotspot", "📡");
        addNavItem("Settings", "settings", "⚙");

        FrameLayout.LayoutParams drawerParams = new FrameLayout.LayoutParams(
                dp(260), ViewGroup.LayoutParams.MATCH_PARENT, Gravity.LEFT);
        drawerParams.topMargin = dp(56);
        root.addView(drawer, drawerParams);

        menuButton.setOnClickListener(v -> {
            boolean visible = drawer.getVisibility() == View.VISIBLE;
            drawer.setVisibility(visible ? View.GONE : View.VISIBLE);
            menuButton.setVisibility(View.VISIBLE);
            menuButton.bringToFront();
        });
        installDrawerSwipeClose(drawer);

        setContentView(root);
    }

    private void addNavItem(String label, String page, String glyph) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(dp(14), dp(10), dp(14), dp(10));
        item.setTag(page);
        item.setBackground(roundDrawable(SOFT, 10));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        params.setMargins(0, dp(6), 0, dp(6));
        item.setLayoutParams(params);

        TextView icon = new TextView(this);
        icon.setText(glyph);
        icon.setTextSize(16);
        icon.setTextColor(ORANGE);
        icon.setTypeface(null, Typeface.BOLD);
        icon.setPadding(0, 0, dp(12), 0);
        item.addView(icon, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText(label);
        title.setTextColor(TEXT);
        title.setTextSize(15);
        title.setTypeface(null, Typeface.BOLD);
        item.addView(title);

        if (page.equals(currentPage)) {
            item.setBackground(roundDrawable(ORANGE_DARK, 10));
            title.setTextColor(WHITE);
            icon.setTextColor(WHITE);
        }

        item.setOnClickListener(v -> {
            drawer.setVisibility(View.GONE);
            menuButton.setVisibility(View.VISIBLE);
            showPage(String.valueOf(v.getTag()));
        });
        installDrawerSwipeClose(item);
        drawer.addView(item);
    }

    private void installDrawerSwipeClose(View view) {
        view.setOnTouchListener((touchedView, event) -> {
            switch (event.getAction()) {
                case android.view.MotionEvent.ACTION_DOWN:
                    drawerSwipeStartX = event.getRawX();
                    return false;
                case android.view.MotionEvent.ACTION_UP:
                    float deltaX = event.getRawX() - drawerSwipeStartX;
                    if (Math.abs(deltaX) > dp(48)) {
                        drawer.setVisibility(View.GONE);
                        menuButton.setVisibility(View.VISIBLE);
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        });
    }

    private void showPage(String page) {
        currentPage = page;
        drawer.setVisibility(View.GONE);
        menuButton.setVisibility(View.VISIBLE);
        screen.removeAllViews();

        if ("home".equals(page)) {
            buildHomePage();
        } else if ("payload".equals(page)) {
            buildPayloadPage();
        } else if ("settings".equals(page)) {
            buildSettingsPage();
        } else if ("ssh".equals(page)) {
            buildSshPage();
        } else if ("vless".equals(page)) {
            buildVlessPage();
        } else if ("vmess".equals(page)) {
            buildVmessPage();
        } else if ("hotspot".equals(page)) {
            buildHotspotPage();
        }
    }

    @Override
    public void onBackPressed() {
        if (drawer != null && drawer.getVisibility() == View.VISIBLE) {
            saveFormBeforeLeaving();
            showPage("home");
            return;
        }
        if (!"home".equals(currentPage)) {
            saveFormBeforeLeaving();
            showPage("home");
            return;
        }
        super.onBackPressed();
    }

    private void saveFormBeforeLeaving() {
        if ("ssh".equals(currentPage)) {
            saveCurrentProtocolForm();
            preferences.edit().putString("SSH_password",
                    editSshPassword.getText().toString()).apply();
        } else if ("vless".equals(currentPage) || "vmess".equals(currentPage)) {
            saveCurrentProtocolForm();
        }
    }

    private String protocolKey(String field) { return selectedProtocol + "_" + field; }

    private String saved(String protocol, String field, String fallback) {
        return preferences.getString(protocol + "_" + field, fallback);
    }

    private void attachInputPersistence(EditText input, String field) {
        input.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {
                preferences.edit().putString(protocolKey(field), s.toString()).apply();
            }
            @Override public void afterTextChanged(Editable e) {}
        });
    }

    private void switchProtocol(String protocol) {
        if (protocol.equals(selectedProtocol)) return;
        saveCurrentProtocolForm();
        selectedProtocol = protocol;
        preferences.edit().putString("protocol", protocol).apply();
        loadProtocolForm(protocol);
        updateModeButtons();
        updateTransportFields();
        showPage(currentPage);
    }

    private void saveCurrentProtocolForm() {
        preferences.edit()
                .putString(protocolKey("uuid"), editUuid.getText().toString())
                .putString(protocolKey("server"), editServer.getText().toString())
                .putString(protocolKey("connectIp"), editConnectIp.getText().toString())
                .putString(protocolKey("port"), editPort.getText().toString())
                .putString(protocolKey("sni"), editBug.getText().toString())
                .putString(protocolKey("path"), editPath.getText().toString())
                .putString(protocolKey("payload"), editPayload.getText().toString())
                .putBoolean(protocolKey("insecure"), checkInsecure.isChecked())
                .putString(protocolKey("transport"), selectedTransport)
                .apply();
    }

    private void loadProtocolForm(String protocol) {
        String uuid = saved(protocol, "uuid", "");
        String sshUsername = saved("SSH", "uuid", "").trim();
        if (!"SSH".equals(protocol) && !sshUsername.isEmpty()
                && uuid.trim().equals(sshUsername) && !isValidUuid(uuid)) {
            preferences.edit().remove(protocol + "_uuid").apply();
            uuid = "";
            TunnelState.log(protocol + " UUID cleared because it matched the SSH username; enter the protocol UUID.");
        }
        editUuid.setText(uuid);
        editServer.setText(saved(protocol, "server", ""));
        editConnectIp.setText(saved(protocol, "connectIp", ""));
        editPort.setText(saved(protocol, "port", ""));
        editBug.setText(saved(protocol, "sni", ""));
        editPath.setText(saved(protocol, "path", ""));
        editPayload.setText(saved(protocol, "payload", ""));
        checkInsecure.setChecked(preferences.getBoolean(protocol + "_insecure", false));
        selectedTransport = preferences.getString(protocol + "_transport", "TLS");
        if ("SSH".equals(protocol)) {
            if (editServer.getText().toString().trim().isEmpty()) editServer.setText("naruto.freessh.indevs.in");
            if (editConnectIp.getText().toString().trim().isEmpty()) editConnectIp.setText("naruto.freessh.indevs.in");
            if (editPort.getText().toString().trim().isEmpty()) editPort.setText("TLS".equals(selectedTransport) ? "443" : "80");
            if (editBug.getText().toString().trim().isEmpty()) editBug.setText("naruto.freessh.indevs.in");
        }
        updateProtocolFieldHints();
    }

    private boolean isValidUuid(String value) {
        try { Uuids.parse(value); return true; }
        catch (IllegalArgumentException e) { return false; }
    }

    private void updateProtocolFieldHints() {
        boolean vmess = "VMess".equals(selectedProtocol);
        boolean ssh = "SSH".equals(selectedProtocol);
        editUuid.setHint(ssh ? "SSH Username (configure password in menu)"
                : (vmess ? "VMess User ID (UUID)" : "VLESS UUID"));
        editServer.setHint(ssh ? "TARGET: your SSH/WS server (goes in Host: via [host])"
                : (vmess ? "VMess Server / Host Header" : "VLESS Server / Host Header"));
        editConnectIp.setHint(ssh ? "PROXY: host/IP the TCP socket connects to (e.g. betika.com)"
                : (vmess ? "VMess Connect IP" : "VLESS Connect IP"));
        editPort.setHint(ssh ? "Proxy Port (443 TLS/SNI, 80 without TLS)"
                : (vmess ? "VMess Port" : "VLESS Port"));
        editBug.setHint(ssh ? "TLS SNI (e.g. naruto.freessh.indevs.in)"
                : (vmess ? "VMess TLS SNI / Host" : "VLESS TLS SNI / Host"));
        editPath.setHint(vmess ? "VMess WebSocket Path"
                : (ssh ? "SSH WebSocket Path (optional)" : "VLESS WebSocket Path"));
    }

    private void updateTransportFields() {
        boolean tls = "TLS".equals(selectedTransport);
        if (editBug != null) editBug.setVisibility(tls ? View.VISIBLE : View.GONE);
        if (checkInsecure != null) checkInsecure.setVisibility(View.VISIBLE);
    }

    private void buildHomePage() {
        screen.setBackgroundColor(BG);

        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setGravity(Gravity.CENTER_HORIZONTAL);
        hero.setPadding(0, dp(10), 0, dp(12));

        btnConnect = new Button(this);
        btnConnect.setText("CONNECT");
        btnConnect.setTextColor(WHITE);
        btnConnect.setTextSize(18);
        btnConnect.setAllCaps(false);
        btnConnect.setTypeface(null, Typeface.BOLD);
        btnConnect.setBackground(roundDrawable(PURPLE, 1000));
        btnConnect.setGravity(Gravity.CENTER);
        btnConnect.setMinWidth(dp(150));
        btnConnect.setMinHeight(dp(150));
        btnConnect.setLayoutParams(new LinearLayout.LayoutParams(dp(150), dp(150)));
        btnConnect.setOnClickListener(v -> onButton());
        hero.addView(btnConnect);

        TextView protocolBadge = new TextView(this);
        protocolBadge.setText(selectedProtocol.toUpperCase());
        protocolBadge.setTextColor(TEXT);
        protocolBadge.setTextSize(12);
        protocolBadge.setTypeface(null, Typeface.BOLD);
        protocolBadge.setPadding(0, dp(10), 0, dp(6));
        hero.addView(protocolBadge);
        screen.addView(hero);

        addSectionLabel("CHOOSE PROTOCOL");

        LinearLayout protocols = horizontalRow();
        sshButton = modeButton("SSH", ORANGE);
        vlessButton = modeButton("VLESS", ORANGE);
        vmessButton = modeButton("VMess", ORANGE);
        protocols.addView(sshButton, weightedParams());
        protocols.addView(vlessButton, weightedParams());
        protocols.addView(vmessButton, weightedParams());
        screen.addView(protocols);

        sshButton.setOnClickListener(v -> switchProtocol("SSH"));
        vlessButton.setOnClickListener(v -> switchProtocol("VLESS"));
        vmessButton.setOnClickListener(v -> switchProtocol("VMess"));
        updateModeButtons();

        statusLabel = new TextView(this);
        statusLabel.setTextSize(12);
        statusLabel.setTextColor(MUTED);
        statusLabel.setPadding(dp(8), dp(14), 0, dp(4));
        statusLabel.setText("Disconnected");
        screen.addView(statusLabel);

        addSectionLabel("CONNECTION LOGS");

        LinearLayout logToolbar = new LinearLayout(this);
        logToolbar.setOrientation(LinearLayout.HORIZONTAL);
        logToolbar.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        logToolbar.setPadding(0, 0, 0, dp(4));
        TextView logTitle = new TextView(this);
        logTitle.setTextColor(MUTED);
        logTitle.setTextSize(11);
        logTitle.setTypeface(null, Typeface.BOLD);
        logToolbar.addView(logTitle);
        Button clearLog = new Button(this);
        clearLog.setText("CLEAR");
        clearLog.setTextColor(TEXT);
        clearLog.setAllCaps(false);
        clearLog.setBackground(roundDrawable(SOFT, 10));
        clearLog.setTextSize(11);
        clearLog.setOnClickListener(v -> {
            TunnelState.log("Connection log cleared");
            if (logView != null) logView.setText("");
        });
        logToolbar.addView(clearLog);
        screen.addView(logToolbar);

        logView = new TextView(this);
        logView.setTextColor(TEXT);
        logView.setTextSize(11);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(dp(10), dp(10), dp(10), dp(10));
        logView.setBackground(roundDrawable(PANEL, 12));
        logView.setMinHeight(dp(150));
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setText(TunnelState.logText());
        logView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(190)));
        screen.addView(logView);

        onState(TunnelState.state(), TunnelState.message());
        updateTransportFields();
    }

    private void buildPayloadPage() {
        addHeading("Payload");
        addText("Payload configuration");

        addSectionLabel("CUSTOM PAYLOAD");
        screen.addView(editPayload);

        addText("Payload is saved per protocol and passed to the SSH transport. "
                + "Use [host], [port], [path] or [crlf] placeholders if needed.");
        if ("SSH".equals(selectedProtocol)) {
            addSectionLabel("PROXY SERVER");
            addText("Field 1 = TARGET (your SSH server, becomes [host]). "
                    + "Field 3 = PROXY (where the TCP connection really goes). "
                    + "TLS/SNI normally uses port 443, Non-TLS port 80.");
            screen.addView(editServer);
            screen.addView(editPort);
            screen.addView(editConnectIp);
        }

        Button back = modeButton("BACK TO CONNECTION", GREEN);
        back.setTextColor(WHITE);
        back.setBackground(roundDrawable(GREEN, 12));
        screen.addView(back, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(50)));
        back.setOnClickListener(v -> showPage("home"));
    }

    private void buildProtocolPage(String title, String protocol) {
        addHeading(title);
        addSectionLabel("CONFIGURATION");
        screen.addView(editUuid);
        screen.addView(editServer);
        screen.addView(editConnectIp);
        screen.addView(editPort);

        addSectionLabel("WEBSOCKET PATH");
        screen.addView(editPath);

        addSectionLabel("TRANSPORT");
        LinearLayout transportRow = horizontalRow();
        tlsButton = modeButton("TLS", ORANGE);
        nonTlsButton = modeButton("Non-TLS", ORANGE);
        transportRow.addView(tlsButton, weightedParams());
        nonTlsButton.setLayoutParams(weightedParams());
        transportRow.addView(nonTlsButton);
        screen.addView(transportRow);
        tlsButton.setOnClickListener(v -> {
            selectedTransport = "TLS";
            preferences.edit().putString(protocolKey("transport"), selectedTransport).apply();
            updateModeButtons();
            updateTransportFields();
        });
        nonTlsButton.setOnClickListener(v -> {
            selectedTransport = "Non-TLS";
            preferences.edit().putString(protocolKey("transport"), selectedTransport).apply();
            updateModeButtons();
            updateTransportFields();
        });
        updateModeButtons();

        addSectionLabel("SNI");
        screen.addView(editBug);
        screen.addView(checkInsecure);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.CENTER_VERTICAL);
        actions.setPadding(0, dp(18), 0, 0);

        Button reset = new Button(this);
        reset.setText("RESET");
        reset.setTextColor(WHITE);
        reset.setTextSize(13);
        reset.setTypeface(null, Typeface.BOLD);
        reset.setAllCaps(false);
        reset.setBackground(roundDrawable(RED, 12));
        LinearLayout.LayoutParams actionParams = new LinearLayout.LayoutParams(0, dp(46), 1);
        actionParams.setMargins(0, 0, dp(8), 0);
        reset.setLayoutParams(actionParams);
        reset.setOnClickListener(v -> {
            preferences.edit()
                    .remove(protocol + "_uuid").remove(protocol + "_server")
                    .remove(protocol + "_connectIp").remove(protocol + "_port")
                    .remove(protocol + "_sni").remove(protocol + "_path")
                    .remove(protocol + "_payload").remove(protocol + "_transport")
                    .remove(protocol + "_insecure").apply();
            loadProtocolForm(protocol);
            updateModeButtons();
            updateTransportFields();
            TunnelState.log(protocol + " configuration reset");
        });

        Button save = new Button(this);
        save.setText("SAVE");
        save.setTextColor(WHITE);
        save.setTextSize(13);
        save.setTypeface(null, Typeface.BOLD);
        save.setAllCaps(false);
        save.setBackground(roundDrawable(GREEN, 12));
        save.setLayoutParams(new LinearLayout.LayoutParams(0, dp(46), 1));
        save.setOnClickListener(v -> {
            saveCurrentProtocolForm();
            TunnelState.log(title + " saved");
            showPage("home");
        });
        actions.addView(reset);
        actions.addView(save);
        screen.addView(actions);
    }

    private void buildSshPage() {
        selectedProtocol = "SSH";
        preferences.edit().putString("protocol", selectedProtocol).apply();
        loadProtocolForm(selectedProtocol);
        addHeading("SSH Configuration");

        addSectionLabel("SSH CREDENTIALS");
        editUuid.setHint("Username");
        screen.addView(editUuid);

        editSshPassword.setHint("Password");
        editSshPassword.setText(preferences.getString("SSH_password", ""));
        screen.addView(editSshPassword);

        editServer.setHint("Host / server");
        editServer.setSelection(editServer.getText().length());
        screen.addView(editServer);

        addSectionLabel("PROXY / SERVER");
        editConnectIp.setHint("Proxy host / IP");
        screen.addView(editConnectIp);

        editPort.setHint("Proxy port");
        screen.addView(editPort);

        LinearLayout sniRow = new LinearLayout(this);
        sniRow.setOrientation(LinearLayout.HORIZONTAL);
        sniRow.setGravity(Gravity.CENTER_VERTICAL);
        sniRow.setPadding(0, dp(10), 0, dp(6));

        CheckBox sniCheck = new CheckBox(this);
        sniCheck.setText("SNI");
        sniCheck.setTextColor(TEXT);
        sniCheck.setButtonTintList(android.content.res.ColorStateList.valueOf(ORANGE));
        sniCheck.setChecked(!"Non-TLS".equals(selectedTransport));
        sniRow.addView(sniCheck);
        screen.addView(sniRow);

        editBug.setHint("SNI host");
        editBug.setVisibility(sniCheck.isChecked() ? View.VISIBLE : View.GONE);
        sniCheck.setOnCheckedChangeListener((button, checked) -> {
            selectedTransport = checked ? "TLS" : "Non-TLS";
            preferences.edit().putString(protocolKey("transport"), selectedTransport).apply();
            editBug.setVisibility(checked ? View.VISIBLE : View.GONE);
        });
        screen.addView(editBug);

        addSectionLabel("PAYLOAD");
        editPayload.setHint("GET /...\nHost: ...\nUpgrade: websocket");
        editPayload.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(180)));
        editPayload.setMinLines(6);
        editPayload.setMaxLines(20);
        screen.addView(editPayload);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.CENTER_VERTICAL);
        actions.setPadding(0, dp(18), 0, 0);

        Button reset = new Button(this);
        reset.setText("RESET");
        reset.setTextColor(WHITE);
        reset.setTextSize(13);
        reset.setTypeface(null, Typeface.BOLD);
        reset.setAllCaps(false);
        reset.setBackground(roundDrawable(RED, 12));
        reset.setLayoutParams(new LinearLayout.LayoutParams(0, dp(46), 1));
        reset.setOnClickListener(v -> {
            preferences.edit().remove("SSH_uuid").remove("SSH_server").remove("SSH_connectIp")
                    .remove("SSH_port").remove("SSH_sni").remove("SSH_payload")
                    .remove("SSH_password").remove("SSH_transport").remove("SSH_insecure").apply();
            selectedTransport = "TLS";
            loadProtocolForm("SSH");
            editSshPassword.setText("");
            TunnelState.log("SSH configuration reset");
        });

        Button save = new Button(this);
        save.setText("SAVE");
        save.setTextColor(WHITE);
        save.setTextSize(13);
        save.setTypeface(null, Typeface.BOLD);
        save.setAllCaps(false);
        save.setBackground(roundDrawable(GREEN, 12));
        save.setLayoutParams(new LinearLayout.LayoutParams(0, dp(46), 1));
        save.setOnClickListener(v -> {
            saveCurrentProtocolForm();
            preferences.edit().putString("SSH_password", editSshPassword.getText().toString()).apply();
            TunnelState.log("SSH configuration saved");
            showPage("home");
        });

        actions.addView(reset);
        actions.addView(save);
        screen.addView(actions);
    }

    private void buildVlessPage() {
        selectedProtocol = "VLESS";
        preferences.edit().putString("protocol", "VLESS").apply();
        loadProtocolForm("VLESS");
        buildProtocolPage("VLESS Configuration", "VLESS");
    }

    private void buildVmessPage() {
        selectedProtocol = "VMess";
        preferences.edit().putString("protocol", "VMess").apply();
        loadProtocolForm("VMess");
        buildProtocolPage("VMess Configuration", "VMess");
    }

    private void buildSettingsPage() {
        addHeading("Settings");
        addSectionLabel("GENERAL");
        addText("Default DNS server");
        screen.addView(editDns);

        Button save = modeButton("RESET TO DEFAULTS", ORANGE);
        save.setTextColor(WHITE);
        save.setBackground(roundDrawable(ORANGE, 12));
        screen.addView(save, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52)));

        save.setOnClickListener(v -> {
            String dns = editDns.getText().toString().trim();
            if (!dns.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                editDns.setError("Enter a valid IPv4 address");
                return;
            }
            for (String part : dns.split("\\.")) {
                if (Integer.parseInt(part) > 255) {
                    editDns.setError("Invalid IPv4 address");
                    return;
                }
            }
            preferences.edit().putString("dns", dns).apply();
            TunnelState.log("Default DNS setting saved");
            showPage("home");
        });
    }

    private void updateModeButtons() {
        if (vlessButton == null || vmessButton == null || sshButton == null
                || tlsButton == null || nonTlsButton == null) {
            return;
        }
        styleMode(sshButton, "SSH".equals(selectedProtocol), ORANGE);
        styleMode(vlessButton, "VLESS".equals(selectedProtocol), ORANGE);
        styleMode(vmessButton, "VMess".equals(selectedProtocol), ORANGE);
        styleMode(tlsButton, "TLS".equals(selectedTransport), ORANGE);
        styleMode(nonTlsButton, "Non-TLS".equals(selectedTransport), ORANGE);
    }

    private void styleMode(Button button, boolean selected, int accent) {
        button.setTextColor(selected ? WHITE : TEXT);
        button.setBackground(roundDrawable(selected ? accent : SOFT, 12));
        button.setTypeface(null, Typeface.BOLD);
    }

    private Button modeButton(String text, int accent) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(13);
        button.setAllCaps(false);
        button.setTextColor(TEXT);
        button.setBackground(roundDrawable(SOFT, 12));
        button.setTypeface(null, Typeface.BOLD);
        return button;
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        return row;
    }

    private LinearLayout.LayoutParams weightedParams() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, dp(48), 1);
        params.setMargins(0, dp(4), dp(8), dp(4));
        return params;
    }

    private void addHeading(String text) {
        TextView heading = new TextView(this);
        heading.setText(text);
        heading.setTextColor(TEXT);
        heading.setTextSize(25);
        heading.setTypeface(null, Typeface.BOLD);
        heading.setPadding(0, dp(4), 0, dp(4));
        screen.addView(heading);
    }

    private void addSectionLabel(String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextColor(ORANGE);
        label.setTextSize(12);
        label.setTypeface(null, Typeface.BOLD);
        label.setPadding(0, dp(16), 0, dp(6));
        screen.addView(label);
    }

    private void addText(String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextColor(MUTED);
        label.setTextSize(13);
        label.setPadding(0, dp(5), 0, dp(8));
        screen.addView(label);
    }

    private EditText createInput(String hint, String value) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setText(value);
        input.setSingleLine(true);
        input.setTextColor(TEXT);
        input.setHintTextColor(MUTED);
        input.setTextSize(14);
        input.setPadding(dp(12), dp(8), dp(12), dp(8));
        input.setBackground(roundDrawable(PANEL, 10));

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        params.setMargins(0, dp(5), 0, dp(5));
        input.setLayoutParams(params);
        return input;
    }

    private GradientDrawable roundDrawable(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radius));
        return drawable;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onStart() {
        super.onStart();
        TunnelState.setListener(this);
        if ("home".equals(currentPage) && logView != null) {
            logView.setText(TunnelState.logText());
            scrollLogToEnd();
            onState(TunnelState.state(), TunnelState.message());
        }
    }

    @Override
    protected void onDestroy() {
        if (hotspotScanner != null) hotspotScanner.stop();
        super.onDestroy();
    }

    @Override
    protected void onStop() {
        if (editUuid != null) saveCurrentProtocolForm();
        if (editDns != null) {
            preferences.edit().putString("dns", editDns.getText().toString().trim()).apply();
        }
        TunnelState.setListener(null);
        super.onStop();
    }

    @Override
    public void onState(TunnelState.State state, String message) {
        if (statusLabel == null || btnConnect == null) return;

        switch (state) {
            case CONNECTED:
                statusLabel.setText("CONNECTED");
                statusLabel.setTextColor(GREEN);
                btnConnect.setText("CONNECTED");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(roundDrawable(GREEN, 1000));
                break;
            case CONNECTING:
                statusLabel.setText("CONNECTING...");
                statusLabel.setTextColor(ORANGE);
                btnConnect.setText("CONNECTING...");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(roundDrawable(ORANGE, 1000));
                break;
            case DISCONNECTING:
                statusLabel.setText("DISCONNECTING...");
                statusLabel.setTextColor(ORANGE);
                btnConnect.setText("DISCONNECTING");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(roundDrawable(ORANGE, 1000));
                break;
            case ERROR:
                statusLabel.setText("FAILED");
                statusLabel.setTextColor(RED);
                btnConnect.setText("RETRY");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(roundDrawable(RED, 1000));
                break;
            default:
                statusLabel.setText("DISCONNECTED");
                statusLabel.setTextColor(MUTED);
                setIdleButton();
                break;
        }
    }

    private void setIdleButton() {
        btnConnect.setText("CONNECT");
        btnConnect.setTextColor(WHITE);
        btnConnect.setBackground(roundDrawable(PURPLE, 1000));
    }

    @Override
    public void onLog(String line) {
        if (logView == null || !"home".equals(currentPage)) return;
        logView.append(line + "\n");
        scrollLogToEnd();
    }

    private void scrollLogToEnd() {
        if (logView == null) return;
        logView.post(() -> {
            if (logView.getLayout() == null) return;
            int y = logView.getLayout().getLineTop(logView.getLineCount()) - logView.getHeight();
            logView.scrollTo(0, Math.max(y, 0));
        });
    }

    private void onButton() {
        TunnelState.State state = TunnelState.state();

        if (state == TunnelState.State.CONNECTED || state == TunnelState.State.CONNECTING) {
            Intent stop = new Intent(this, TunnelVpnService.class);
            stop.setAction(TunnelVpnService.ACTION_STOP);
            startService(stop);
            return;
        }
        if (state == TunnelState.State.DISCONNECTING) return;

        String err = validate();
        if (err != null) {
            TunnelState.log("Input error: " + err);
            statusLabel.setText("INPUT ERROR: " + err);
            statusLabel.setTextColor(RED);
            return;
        }

        Intent intent = new Intent(this, TunnelVpnService.class);
        intent.setAction(TunnelVpnService.ACTION_START);
        intent.putExtra("uuid", editUuid.getText().toString().trim());
        intent.putExtra("server", editServer.getText().toString().trim());
        intent.putExtra("connectIp", editConnectIp.getText().toString().trim());
        intent.putExtra("port", Integer.parseInt(editPort.getText().toString().trim()));
        intent.putExtra("bug", editBug.getText().toString().trim());
        intent.putExtra("path", editPath.getText().toString().trim());
        intent.putExtra("dns", editDns.getText().toString().trim());
        intent.putExtra("insecure", checkInsecure.isChecked());
        intent.putExtra("transport", selectedTransport);
        intent.putExtra("protocol", selectedProtocol);
        intent.putExtra("payload", editPayload.getText().toString());
        intent.putExtra("sshUsername", "SSH".equals(selectedProtocol)
                ? editUuid.getText().toString().trim() : "");
        intent.putExtra("sshPassword", preferences.getString("SSH_password", ""));
        intent.putExtra("sshHost", editServer.getText().toString().trim());

        pendingStart = intent;

        if (Build.VERSION.SDK_INT >= 33
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS);
        } else {
            askVpnPermission();
        }
    }

    private String validate() {
        ProtocolConfig pc = new ProtocolConfig();
        pc.uuid = editUuid.getText().toString();
        pc.sshUsername = editUuid.getText().toString().trim();
        pc.sshPassword = preferences.getString("SSH_password", "");
        pc.hostHeader = editServer.getText().toString().trim();
        pc.port = parsePort(editPort.getText().toString(), 443);
        pc.sni = editBug.getText().toString().trim();
        pc.tls = "TLS".equals(selectedTransport);
        try {
            String protoErr = ProtocolRegistry.require(selectedProtocol).validate(pc);
            if (protoErr != null) return protoErr;
        } catch (java.io.IOException e) {
            return e.getMessage();
        }

        try {
            int port = Integer.parseInt(editPort.getText().toString().trim());
            if (port < 1 || port > 65535) return "Port must be 1-65535";
        } catch (NumberFormatException e) {
            return "Port must be a number";
        }

        if (!"SSH".equals(selectedProtocol) && "TLS".equals(selectedTransport)
                && editBug.getText().toString().trim().isEmpty()) {
            return "SNI host is empty";
        }
        if (editServer.getText().toString().trim().isEmpty()) return "Host header is empty";
        if (editConnectIp.getText().toString().trim().isEmpty()) return "Connect IP is empty";

        String dns = editDns.getText().toString().trim();
        if (!dns.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return "DNS must be an IPv4 address";
        for (String part : dns.split("\\.")) {
            if (Integer.parseInt(part) > 255) return "DNS must be a valid IPv4 address";
        }
        return null;
    }

    private int parsePort(String value, int fallback) {
        try { return Integer.parseInt(value.trim()); } catch (Exception e) { return fallback; }
    }

    private void askVpnPermission() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            vpnPermission.launch(prepare);
        } else {
            launch();
        }
    }

    private void launch() {
        if (pendingStart == null) return;
        Intent intent = pendingStart;
        pendingStart = null;
        ContextCompat.startForegroundService(this, intent);
    }
}

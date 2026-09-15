
package com.example.tunnel;

import android.Manifest;
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
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.example.tunnel.vless.VlessCodec;

public class MainActivity extends AppCompatActivity
        implements TunnelState.Listener {

    // Dark Custom theme
    private static final int BG = Color.rgb(15, 17, 25);
    private static final int PANEL = Color.rgb(25, 28, 40);
    private static final int GREEN = Color.rgb(0, 230, 118);
    private static final int PURPLE = Color.rgb(171, 71, 255);
    private static final int WHITE = Color.rgb(244, 245, 250);
    private static final int MUTED = Color.rgb(160, 165, 185);

    private LinearLayout root;
    private LinearLayout drawer;
    private LinearLayout screen;
    private TextView statusLabel;
    private TextView logView;
    private Button btnConnect;

    private EditText editUuid;
    private EditText editServer;
    private EditText editConnectIp;
    private EditText editPort;
    private EditText editBug;
    private EditText editPath;
    private EditText editDns;
    private EditText editPayload;

    private CheckBox checkInsecure;

    private Button tlsButton;
    private Button nonTlsButton;
    private Button vlessButton;
    private Button vmessButton;

    private String selectedTransport = "TLS";
    private String selectedProtocol = "VLESS";
    private String currentPage = "home";

    private Intent pendingStart;

    private SharedPreferences preferences;

    private final ActivityResultLauncher<Intent> vpnPermission =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) {
                            launch();
                        } else {
                            pendingStart = null;
                            TunnelState.log(
                                    "VPN permission denied - cannot start");
                        }
                    });


    private final ActivityResultLauncher<String> notificationPermission =
            registerForActivityResult(
                    new ActivityResultContracts.RequestPermission(),
                    granted -> askVpnPermission());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        preferences = getSharedPreferences(
                "dark_custom_settings", MODE_PRIVATE);
        selectedProtocol = preferences.getString("protocol", "VLESS");
        selectedTransport = preferences.getString(selectedProtocol + "_transport", "TLS");

        editUuid = createInput("UUID / User ID",
                saved(selectedProtocol, "uuid", ""));
        editServer = createInput("Server / Host Header",
                saved(selectedProtocol, "server", ""));
        editConnectIp = createInput("Connect IP",
                saved(selectedProtocol, "connectIp", ""));
        editPort = createInput("Port",
                saved(selectedProtocol, "port", ""));
        editBug = createInput("SNI / TLS Host",
                saved(selectedProtocol, "sni", ""));
        editPath = createInput("WebSocket Path",
                saved(selectedProtocol, "path", ""));
        editDns = createInput("Default DNS server",
                preferences.getString("dns", "8.8.8.8"));

        editPayload = createInput(
                "Payload", "Enter your payload");

        checkInsecure = new CheckBox(this);
        checkInsecure.setText(
                "Skip TLS certificate verification (insecure)");
        checkInsecure.setTextColor(WHITE);
        checkInsecure.setButtonTintList(
                android.content.res.ColorStateList.valueOf(GREEN));
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
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        // Top app bar
        LinearLayout toolbar = new LinearLayout(this);
        toolbar.setGravity(Gravity.CENTER_VERTICAL);
        toolbar.setPadding(dp(10), dp(8), dp(16), dp(8));
        toolbar.setBackgroundColor(PANEL);

        Button menuButton = new Button(this);
        menuButton.setText("☰");
        menuButton.setTextSize(25);
        menuButton.setTextColor(GREEN);
        menuButton.setBackgroundColor(Color.TRANSPARENT);
        toolbar.addView(menuButton, new LinearLayout.LayoutParams(
                dp(54), dp(52)));

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.VERTICAL);

        TextView title = new TextView(this);
        title.setText("DARK CUSTOM");
        title.setTextColor(GREEN);
        title.setTextSize(20);
        title.setTypeface(null, Typeface.BOLD);

        TextView subtitle = new TextView(this);
        subtitle.setText("SECURE TUNNEL CLIENT");
        subtitle.setTextColor(MUTED);
        subtitle.setTextSize(10);

        brand.addView(title);
        brand.addView(subtitle);

        toolbar.addView(brand, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        TextView indicator = new TextView(this);
        indicator.setText("●");
        indicator.setTextSize(18);
        indicator.setTextColor(PURPLE);
        toolbar.addView(indicator);

        root.addView(toolbar);

        // Navigation drawer
        drawer = new LinearLayout(this);
        drawer.setOrientation(LinearLayout.VERTICAL);
        drawer.setPadding(dp(12), dp(12), dp(12), dp(12));
        drawer.setBackgroundColor(PANEL);
        drawer.setVisibility(View.GONE);

        addMenuItem("⌂   Home", "home");
        addMenuItem("≋   Payload", "payload");
        addMenuItem("⚙   Settings", "settings");

        root.addView(drawer);

        menuButton.setOnClickListener(v ->
                drawer.setVisibility(
                        drawer.getVisibility() == View.VISIBLE
                                ? View.GONE : View.VISIBLE));

        // Scrollable screen content
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);

        screen = new LinearLayout(this);
        screen.setOrientation(LinearLayout.VERTICAL);
        screen.setPadding(dp(16), dp(16), dp(16), dp(24));

        scroll.addView(screen);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        setContentView(root);
    }

    private void addMenuItem(String label, String page) {
        Button item = new Button(this);
        item.setText(label);
        item.setTextColor(WHITE);
        item.setTextSize(15);
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setAllCaps(false);
        item.setBackgroundColor(Color.TRANSPARENT);

        drawer.addView(item, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52)));

        item.setOnClickListener(v -> showPage(page));
    }

    private void showPage(String page) {
        currentPage = page;
        drawer.setVisibility(View.GONE);
        screen.removeAllViews();

        if ("home".equals(page)) {
            buildHomePage();
        } else if ("payload".equals(page)) {
            buildPayloadPage();
        } else if ("settings".equals(page)) {
            buildSettingsPage();
        }
    }

    private String protocolKey(String field) {
        return selectedProtocol + "_" + field;
    }

    private String saved(String protocol, String field, String fallback) {
        return preferences.getString(protocol + "_" + field, fallback);
    }

    private void attachInputPersistence(EditText input, String field) {
        input.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
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
    }

    private void saveCurrentProtocolForm() {
        preferences.edit()
                .putString(protocolKey("uuid"), editUuid.getText().toString())
                .putString(protocolKey("server"), editServer.getText().toString())
                .putString(protocolKey("connectIp"), editConnectIp.getText().toString())
                .putString(protocolKey("port"), editPort.getText().toString())
                .putString(protocolKey("sni"), editBug.getText().toString())
                .putString(protocolKey("path"), editPath.getText().toString())
                .putBoolean(protocolKey("insecure"), checkInsecure.isChecked())
                .putString(protocolKey("transport"), selectedTransport)
                .apply();
    }

    private void loadProtocolForm(String protocol) {
        editUuid.setText(saved(protocol, "uuid", ""));
        editServer.setText(saved(protocol, "server", ""));
        editConnectIp.setText(saved(protocol, "connectIp", ""));
        editPort.setText(saved(protocol, "port", ""));
        editBug.setText(saved(protocol, "sni", ""));
        editPath.setText(saved(protocol, "path", ""));
        checkInsecure.setChecked(preferences.getBoolean(protocol + "_insecure", false));
        selectedTransport = preferences.getString(protocol + "_transport", "TLS");
        updateProtocolFieldHints();
    }

    private void updateProtocolFieldHints() {
        boolean vmess = "VMess".equals(selectedProtocol);
        editUuid.setHint(vmess ? "VMess User ID (UUID)" : "VLESS UUID");
        editServer.setHint(vmess ? "VMess Server / Host Header" : "VLESS Server / Host Header");
        editConnectIp.setHint(vmess ? "VMess Connect IP" : "VLESS Connect IP");
        editPort.setHint(vmess ? "VMess Port" : "VLESS Port");
        editBug.setHint(vmess ? "VMess TLS SNI / Host" : "VLESS TLS SNI / Host");
        editPath.setHint(vmess ? "VMess WebSocket Path" : "VLESS WebSocket Path");
    }

    private void updateTransportFields() {
    boolean tls = "TLS".equals(selectedTransport);

    if (editBug != null) {
        editBug.setVisibility(tls ? View.VISIBLE : View.GONE);
    }

    if (checkInsecure != null) {
        checkInsecure.setVisibility(
                tls ? View.VISIBLE : View.GONE);
    }
    }

    private void buildHomePage() {
        addHeading("Connection");
        addText("Choose your protocol and transport mode.");

        // Protocol selection
        addSectionLabel("PROTOCOL");

        LinearLayout protocols = horizontalRow();
        vlessButton = modeButton("VLESS", PURPLE);
        vmessButton = modeButton("VMess", PURPLE);

        protocols.addView(vlessButton, weightedParams());
        protocols.addView(vmessButton, weightedParams());
        screen.addView(protocols);

        vlessButton.setOnClickListener(v -> switchProtocol("VLESS"));
        vmessButton.setOnClickListener(v -> switchProtocol("VMess"));

        // Transport selection
        addSectionLabel("TRANSPORT");

        LinearLayout transports = horizontalRow();
        tlsButton = modeButton("TLS", GREEN);
        nonTlsButton = modeButton("Non-TLS", GREEN);

        transports.addView(tlsButton, weightedParams());
        transports.addView(nonTlsButton, weightedParams());
        screen.addView(transports);

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

        addSectionLabel("VMess".equals(selectedProtocol)
                ? "VMESS CONFIGURATION" : "VLESS CONFIGURATION");
        updateProtocolFieldHints();
        addText("Settings are remembered separately for VLESS and VMess on this device.");
        if ("VMess".equals(selectedProtocol)) {
            addText("VMess configuration form selected. VMess transport support is not yet implemented in the current tunnel engine.");
        }

        screen.addView(editUuid);
        screen.addView(editServer);
        screen.addView(editConnectIp);
        screen.addView(editPort);
        screen.addView(editBug);
        screen.addView(editPath);
        screen.addView(checkInsecure);

        addText("Configure your default DNS under Settings.");

        statusLabel = new TextView(this);
        statusLabel.setTextSize(15);
        statusLabel.setGravity(Gravity.CENTER);
        statusLabel.setPadding(0, dp(18), 0, dp(18));
        statusLabel.setTextColor(MUTED);
        statusLabel.setText("DISCONNECTED");
        screen.addView(statusLabel);

        btnConnect = new Button(this);
        btnConnect.setText("START VPN");
        btnConnect.setTextColor(Color.BLACK);
        btnConnect.setTextSize(16);
        btnConnect.setTypeface(null, Typeface.BOLD);
        btnConnect.setAllCaps(false);
        btnConnect.setBackground(roundDrawable(GREEN, 14));

        LinearLayout.LayoutParams connectParams =
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dp(54));
        connectParams.setMargins(0, dp(4), 0, dp(18));
        screen.addView(btnConnect, connectParams);

        btnConnect.setOnClickListener(v -> onButton());

        addSectionLabel("CONNECTION LOG");

        logView = new TextView(this);
        logView.setTextColor(GREEN);
        logView.setTextSize(12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(dp(12), dp(12), dp(12), dp(12));
        logView.setBackground(roundDrawable(
                Color.rgb(8, 11, 15), 12));
        logView.setMinHeight(dp(150));
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setText(TunnelState.logText());

        screen.addView(logView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(190)));

        onState(TunnelState.state(), TunnelState.message());
        updateTransportFields();
    }

    private void buildPayloadPage() {
        addHeading("Payload");
        addText("Payload configuration");

        addSectionLabel("CUSTOM PAYLOAD");
        screen.addView(editPayload);

        addText("This field is a UI placeholder. It is not currently "
                + "sent to the VPN service.");

        Button back = modeButton("BACK TO CONNECTION", GREEN);
        screen.addView(back, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(50)));

        back.setOnClickListener(v -> showPage("home"));
    }

    private void buildSettingsPage() {
        addHeading("Settings");
        addText("Customize your connection preferences.");

        addSectionLabel("NETWORK");

        addText("Default DNS server");
        screen.addView(editDns);

        addText("This DNS value is saved on this device and reused "
                + "by the existing connection form.");

        Button save = modeButton("SAVE SETTINGS", GREEN);
        screen.addView(save, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(50)));

        save.setOnClickListener(v -> {
            String dns = editDns.getText().toString().trim();

            if (!dns.matches(
                    "\\d{1,3}(\\.\\d{1,3}){3}")) {
                editDns.setError("Enter a valid IPv4 address");
                return;
            }

            String[] parts = dns.split("\\.");
            for (String part : parts) {
                int octet = Integer.parseInt(part);
                if (octet > 255) {
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
        if (vlessButton == null || vmessButton == null
                || tlsButton == null || nonTlsButton == null) {
            return;
        }

        styleMode(vlessButton,
                "VLESS".equals(selectedProtocol), PURPLE);
        styleMode(vmessButton,
                "VMess".equals(selectedProtocol), PURPLE);
        styleMode(tlsButton,
                "TLS".equals(selectedTransport), GREEN);
        styleMode(nonTlsButton,
                "Non-TLS".equals(selectedTransport), GREEN);
    }

    private void styleMode(Button button, boolean selected, int accent) {
        button.setTextColor(selected ? Color.BLACK : WHITE);
        button.setBackground(roundDrawable(
                selected ? accent : PANEL, 12));
    }

    private Button modeButton(String text, int accent) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(13);
        button.setAllCaps(false);
        button.setTextColor(WHITE);
        button.setBackground(roundDrawable(PANEL, 12));
        return button;
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        return row;
    }

    private LinearLayout.LayoutParams weightedParams() {
        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(
                        0, dp(48), 1);
        params.setMargins(0, dp(4), dp(8), dp(4));
        return params;
    }

    private void addHeading(String text) {
        TextView heading = new TextView(this);
        heading.setText(text);
        heading.setTextColor(WHITE);
        heading.setTextSize(25);
        heading.setTypeface(null, Typeface.BOLD);
        heading.setPadding(0, dp(4), 0, dp(4));
        screen.addView(heading);
    }

    private void addSectionLabel(String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextColor(GREEN);
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
        input.setTextColor(WHITE);
        input.setHintTextColor(MUTED);
        input.setTextSize(14);
        input.setPadding(dp(12), dp(8), dp(12), dp(8));
        input.setBackground(roundDrawable(PANEL, 10));

        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        dp(52));
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
        return Math.round(
                value * getResources().getDisplayMetrics().density);
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
    protected void onStop() {
        if (editUuid != null) saveCurrentProtocolForm();
        if (editDns != null) {
            preferences.edit().putString(
                    "dns", editDns.getText().toString().trim()).apply();
        }

        TunnelState.setListener(null);
        super.onStop();
    }

    @Override
    public void onState(TunnelState.State state, String message) {
        if (statusLabel == null || btnConnect == null) return;

        switch (state) {
            case CONNECTED:
                statusLabel.setText("● CONNECTED");
                statusLabel.setTextColor(GREEN);
                btnConnect.setText("STOP");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(
                        roundDrawable(Color.rgb(183, 28, 28), 14));
                break;

            case CONNECTING:
                statusLabel.setText("◉ CONNECTING...");
                statusLabel.setTextColor(PURPLE);
                btnConnect.setText("CANCEL");
                btnConnect.setTextColor(WHITE);
                btnConnect.setBackground(
                        roundDrawable(Color.rgb(183, 28, 28), 14));
                break;

            case DISCONNECTING:
                statusLabel.setText("DISCONNECTING...");
                statusLabel.setTextColor(PURPLE);
                break;

            case ERROR:
                statusLabel.setText("ERROR: " + message);
                statusLabel.setTextColor(
                        Color.rgb(255, 82, 82));
                setIdleButton();
                break;

            default:
                statusLabel.setText("● DISCONNECTED");
                statusLabel.setTextColor(MUTED);
                setIdleButton();
                break;
        }
    }

    private void setIdleButton() {
        btnConnect.setText("START VPN");
        btnConnect.setTextColor(Color.BLACK);
        btnConnect.setBackground(roundDrawable(GREEN, 14));
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

            int y = logView.getLayout().getLineTop(
                    logView.getLineCount()) - logView.getHeight();

            logView.scrollTo(0, Math.max(y, 0));
        });
    }

    // Existing connection flow preserved
    private void onButton() {
        TunnelState.State state = TunnelState.state();

        if (state == TunnelState.State.CONNECTED
                || state == TunnelState.State.CONNECTING) {
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
            statusLabel.setTextColor(
                    Color.rgb(255, 82, 82));
            return;
        }

        Intent intent = new Intent(this, TunnelVpnService.class);
        intent.setAction(TunnelVpnService.ACTION_START);

        intent.putExtra("uuid",
                editUuid.getText().toString().trim());
        intent.putExtra("server",
                editServer.getText().toString().trim());
        intent.putExtra("connectIp",
                editConnectIp.getText().toString().trim());
        intent.putExtra("port",
                Integer.parseInt(editPort.getText().toString().trim()));
        intent.putExtra("bug",
                editBug.getText().toString().trim());
        intent.putExtra("path",
                editPath.getText().toString().trim());
        intent.putExtra("dns",
                editDns.getText().toString().trim());
        intent.putExtra("insecure", checkInsecure.isChecked());
        intent.putExtra("transport", selectedTransport);
        intent.putExtra("protocol", selectedProtocol);

        pendingStart = intent;

        if (Build.VERSION.SDK_INT >= 33
                && ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {

            notificationPermission.launch(
                    Manifest.permission.POST_NOTIFICATIONS);
        } else {
            askVpnPermission();
        }
    }

    private String validate() {
        try {
            VlessCodec.parseUuid(
                    editUuid.getText().toString());
        } catch (IllegalArgumentException e) {
            return "UUID: " + e.getMessage();
        }

        try {
            int port = Integer.parseInt(
                    editPort.getText().toString().trim());

            if (port < 1 || port > 65535) {
                return "Port must be 1-65535";
            }
        } catch (NumberFormatException e) {
            return "Port must be a number";
        }

       if ("TLS".equals(selectedTransport)
                && editBug.getText().toString().trim().isEmpty()) {
            return "SNI host is empty";
        } 

        
        if (editServer.getText().toString().trim().isEmpty()) {
            return "Host header is empty";
        }

        if (editConnectIp.getText().toString().trim().isEmpty()) {
            return "Connect IP is empty";
        }

        String dns = editDns.getText().toString().trim();

        if (!dns.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return "DNS must be an IPv4 address";
        }

        for (String part : dns.split("\\.")) {
            if (Integer.parseInt(part) > 255) {
                return "DNS must be a valid IPv4 address";
            }
        }

        return null;
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

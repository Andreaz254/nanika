package com.example.tunnel.ui;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Shader;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.OvershootInterpolator;

/**
 * The big round, raised (3D) connect button. It shows no text: only an icon that changes with the state
 *   IDLE        power symbol on a purple key
 *   CONNECTING  orange spinner (rotating spokes) on a white key with an orange rim and expanding ripples
 *   CONNECTED   check mark on a green key with a softly breathing halo
 *   FAILED      exclamation mark on a red key
 * Colours cross-fade between states, the key physically sinks when pressed and springs back on release.
 */
public class ConnectButton extends View {
    public static final int IDLE = 0, CONNECTING = 1, CONNECTED = 2, FAILED = 3;

    private static final int TOP = 0, BOTTOM = 1, EDGE = 2, HALO = 3, ICON = 4, RIM = 5;

    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private final RectF rect = new RectF();
    private final ArgbEvaluator argb = new ArgbEvaluator();
    private final float dp;

    private final int cardColor;
    private final int softColor;

    private int state = IDLE;
    private int prevState = IDLE;
    private final int[] from = new int[6];
    private final int[] to = new int[6];
    private final int[] cur = new int[6];
    private float fraction = 1f;        // 0..1 progress of the colour / icon cross-fade
    private float press;                // 0 (up) .. 1 (fully pressed)
    private float phase;                // 0..1 repeating, drives spinner / ripples / breathing

    private ValueAnimator colorAnim, pressAnim, phaseAnim;
    private boolean pressActive;

    private float cx, cy, r, depth;
    private Shader faceShader, bevelShader, glossShader;

    public ConnectButton(Context ctx, int cardColor, int softColor) {
        super(ctx);
        this.cardColor = cardColor;
        this.softColor = softColor;
        dp = ctx.getResources().getDisplayMetrics().density;
        look(IDLE, cur);
        look(IDLE, from);
        look(IDLE, to);
        setClickable(true);
        setFocusable(true);
        setContentDescription("Connect");
    }

    // ------------------------------------------------------------------ state

    public int getState() { return state; }

    public void setState(int s, boolean animate) {
        if (s == state) return;
        System.arraycopy(cur, 0, from, 0, 6);
        prevState = state;
        state = s;
        look(s, to);
        cancel(colorAnim);
        if (animate && isLaidOut()) {
            fraction = 0f;
            colorAnim = ValueAnimator.ofFloat(0f, 1f);
            colorAnim.setDuration(420);
            colorAnim.setInterpolator(new DecelerateInterpolator(1.4f));
            colorAnim.addUpdateListener(a -> {
                fraction = (Float) a.getAnimatedValue();
                blend();
                invalidate();
            });
            colorAnim.start();
        } else {
            fraction = 1f;
            prevState = s;
            blend();
            invalidate();
        }
        updatePhase();
        setContentDescription(s == CONNECTING ? "Connecting" : s == CONNECTED ? "Connected, tap to disconnect"
                : s == FAILED ? "Connection failed, tap to retry" : "Connect");
    }

    private void look(int s, int[] out) {
        switch (s) {
            case CONNECTING:
                out[TOP] = cardColor;
                out[BOTTOM] = softColor;
                out[EDGE] = Color.rgb(214, 100, 30);
                out[HALO] = Color.rgb(242, 107, 33);
                out[ICON] = Color.rgb(242, 107, 33);
                out[RIM] = Color.rgb(242, 107, 33);
                break;
            case CONNECTED:
                out[TOP] = Color.rgb(54, 196, 124);
                out[BOTTOM] = Color.rgb(20, 138, 82);
                out[EDGE] = Color.rgb(10, 88, 52);
                out[HALO] = Color.rgb(30, 160, 98);
                out[ICON] = Color.WHITE;
                out[RIM] = Color.argb(0, 30, 160, 98);
                break;
            case FAILED:
                out[TOP] = Color.rgb(252, 94, 98);
                out[BOTTOM] = Color.rgb(222, 40, 48);
                out[EDGE] = Color.rgb(146, 16, 26);
                out[HALO] = Color.rgb(238, 56, 62);
                out[ICON] = Color.WHITE;
                out[RIM] = Color.argb(0, 238, 56, 62);
                break;
            default:
                out[TOP] = Color.rgb(162, 84, 238);
                out[BOTTOM] = Color.rgb(104, 34, 196);
                out[EDGE] = Color.rgb(64, 16, 128);
                out[HALO] = Color.rgb(130, 50, 215);
                out[ICON] = Color.WHITE;
                out[RIM] = Color.argb(0, 130, 50, 215);
        }
    }

    private void blend() {
        for (int i = 0; i < 6; i++) cur[i] = (Integer) argb.evaluate(fraction, from[i], to[i]);
        buildShaders();
    }

    // ------------------------------------------------------------------ animation plumbing

    private static void cancel(ValueAnimator a) { if (a != null) a.cancel(); }

    private void updatePhase() {
        boolean need = isAttachedToWindow() && (state == CONNECTING || state == CONNECTED);
        if (need && phaseAnim == null) {
            phaseAnim = ValueAnimator.ofFloat(0f, 1f);
            phaseAnim.setDuration(1500);
            phaseAnim.setInterpolator(new LinearInterpolator());
            phaseAnim.setRepeatCount(ValueAnimator.INFINITE);
            phaseAnim.addUpdateListener(a -> {
                phase = (Float) a.getAnimatedValue();
                invalidate();
            });
            phaseAnim.start();
        } else if (!need && phaseAnim != null) {
            phaseAnim.cancel();
            phaseAnim = null;
            phase = 0f;
            invalidate();
        }
    }

    @Override protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        updatePhase();
    }

    @Override protected void onDetachedFromWindow() {
        cancel(phaseAnim);
        phaseAnim = null;
        cancel(colorAnim);
        cancel(pressAnim);
        super.onDetachedFromWindow();
    }

    private void animatePress(float target, long ms, boolean spring) {
        cancel(pressAnim);
        pressAnim = ValueAnimator.ofFloat(press, target);
        pressAnim.setDuration(ms);
        pressAnim.setInterpolator(spring ? new OvershootInterpolator(2.6f) : new DecelerateInterpolator());
        pressAnim.addUpdateListener(a -> {
            press = (Float) a.getAnimatedValue();
            invalidate();
        });
        pressAnim.start();
    }

    // ------------------------------------------------------------------ geometry

    @Override protected void onMeasure(int wSpec, int hSpec) {
        int d = (int) (200 * dp);
        setMeasuredDimension(resolveSize(d, wSpec), resolveSize(d, hSpec));
    }

    @Override protected void onSizeChanged(int w, int h, int ow, int oh) {
        float s = Math.min(w, h);
        cx = w / 2f;
        cy = h / 2f;
        r = s * 0.385f;
        depth = r * 0.12f;
        buildShaders();
    }

    private void buildShaders() {
        if (r <= 0) return;
        faceShader = new LinearGradient(0, -r, 0, r, cur[TOP], cur[BOTTOM], Shader.TileMode.CLAMP);
        bevelShader = new LinearGradient(0, -r, 0, r * 0.35f, 0xB0FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP);
        glossShader = new LinearGradient(0, -r * 0.95f, 0, -r * 0.05f, 0x4DFFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP);
    }

    private static int alpha(int color, int a) {
        return (color & 0x00FFFFFF) | (Math.max(0, Math.min(255, a)) << 24);
    }

    // ------------------------------------------------------------------ drawing

    @Override protected void onDraw(Canvas c) {
        if (r <= 0 || faceShader == null) return;
        float s = Math.min(getWidth(), getHeight());
        float breath = state == CONNECTED ? 1f + 0.025f * (float) Math.sin(phase * 2 * Math.PI) : 1f;

        // halo
        p.setStyle(Paint.Style.FILL);
        p.setShader(null);
        p.setColor(alpha(cur[HALO], 40));
        c.drawCircle(cx, cy, s * 0.5f * breath, p);
        p.setColor(alpha(cur[HALO], 58));
        c.drawCircle(cx, cy, s * 0.455f * breath, p);

        // expanding ripples while connecting
        if (state == CONNECTING || prevState == CONNECTING && fraction < 1f) {
            float k = state == CONNECTING ? fraction : 1f - fraction;
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeWidth(2f * dp);
            for (int i = 0; i < 2; i++) {
                float f = (phase + i * 0.5f) % 1f;
                float rad = r * 1.08f + f * (s * 0.5f - r * 1.08f);
                p.setColor(alpha(cur[HALO], (int) ((1f - f) * 110f * k)));
                c.drawCircle(cx, cy, rad, p);
            }
        }

        float baseY = cy + depth / 2f;
        float faceY = cy - depth / 2f + depth * 0.85f * press;

        // soft ground shadow (stacked translucent discs fake a blur without a software layer)
        p.setStyle(Paint.Style.FILL);
        float lift = 1f - 0.55f * press;
        for (int i = 0; i < 6; i++) {
            p.setColor(alpha(cur[EDGE], (int) ((20 - i * 2.4f) * (1f + 0.5f * press))));
            c.drawCircle(cx, baseY + (7f * dp) * lift, r + i * 2.4f * dp, p);
        }

        // side wall (the "thickness" of the key)
        p.setColor(cur[EDGE]);
        c.drawCircle(cx, baseY, r, p);
        if (faceY < baseY) {
            rect.set(cx - r, faceY, cx + r, baseY);
            c.drawRect(rect, p);
        }

        // top face
        c.save();
        c.translate(cx, faceY);
        p.setShader(faceShader);
        c.drawCircle(0, 0, r, p);
        p.setShader(null);

        float rimA = Color.alpha(cur[RIM]) / 255f;

        // glossy highlight on the upper half
        p.setShader(glossShader);
        rect.set(-r * 0.78f, -r * 0.96f, r * 0.78f, -r * 0.06f);
        c.drawOval(rect, p);
        p.setShader(null);

        // bevel: bright top edge fading downwards
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(2f * dp);
        p.setShader(bevelShader);
        c.drawCircle(0, 0, r - dp, p);
        p.setShader(null);

        // inner ring (coloured keys) or orange rim (connecting)
        p.setStrokeWidth(1.2f * dp);
        p.setColor(alpha(Color.WHITE, (int) (46 * (1f - rimA))));
        c.drawCircle(0, 0, r * 0.80f, p);
        if (rimA > 0.01f) {
            p.setStrokeWidth(4f * dp);
            p.setColor(cur[RIM]);
            c.drawCircle(0, 0, r - 2.5f * dp, p);
        }

        // icon (cross-fades with the previous one)
        if (fraction < 1f && prevState != state) {
            icon(c, prevState, from[ICON], 1f - fraction, 1f - 0.25f * fraction);
            icon(c, state, to[ICON], fraction, 0.75f + 0.25f * fraction);
        } else {
            icon(c, state, to[ICON], 1f, 1f);
        }
        c.restore();
    }

    private void icon(Canvas c, int kind, int color, float a, float scale) {
        if (a <= 0.01f) return;
        p.setShader(null);
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeCap(Paint.Cap.ROUND);
        p.setStrokeJoin(Paint.Join.ROUND);
        p.setColor(alpha(color, (int) (255 * a)));
        c.save();
        c.scale(scale, scale);
        switch (kind) {
            case CONNECTING: {
                p.setStrokeWidth(r * 0.075f);
                float lead = phase * 12f;
                for (int i = 0; i < 12; i++) {
                    float behind = ((lead - i) % 12f + 12f) % 12f;          // 0 = brightest spoke
                    float al = Math.max(0.12f, 1f - behind / 12f * 0.95f);
                    p.setColor(alpha(color, (int) (255 * a * al)));
                    double ang = Math.toRadians(i * 30.0 - 90.0);
                    float cs = (float) Math.cos(ang), sn = (float) Math.sin(ang);
                    c.drawLine(cs * r * 0.17f, sn * r * 0.17f, cs * r * 0.37f, sn * r * 0.37f, p);
                }
                break;
            }
            case CONNECTED: {
                p.setStrokeWidth(r * 0.14f);
                path.reset();
                path.moveTo(-r * 0.30f, r * 0.02f);
                path.lineTo(-r * 0.08f, r * 0.26f);
                path.lineTo(r * 0.32f, -r * 0.22f);
                c.drawPath(path, p);
                break;
            }
            case FAILED: {
                p.setStrokeWidth(r * 0.15f);
                c.drawLine(0, -r * 0.38f, 0, r * 0.06f, p);
                p.setStyle(Paint.Style.FILL);
                c.drawCircle(0, r * 0.32f, r * 0.085f, p);
                break;
            }
            default: {
                p.setStrokeWidth(r * 0.115f);
                float rho = r * 0.33f;
                rect.set(-rho, -rho + r * 0.03f, rho, rho + r * 0.03f);
                c.drawArc(rect, 308f, 284f, false, p);
                c.drawLine(0, -r * 0.41f, 0, -r * 0.06f, p);
            }
        }
        c.restore();
    }

    // ------------------------------------------------------------------ touch

    private boolean inside(MotionEvent e) {
        float dx = e.getX() - cx, dy = e.getY() - cy;
        return dx * dx + dy * dy <= r * r * 1.35f;
    }

    @Override public boolean onTouchEvent(MotionEvent e) {
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                if (!inside(e)) return false;
                pressActive = true;
                animatePress(1f, 110, false);
                performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                return true;
            case MotionEvent.ACTION_MOVE:
                if (pressActive && !inside(e)) {
                    pressActive = false;
                    animatePress(0f, 200, true);
                }
                return true;
            case MotionEvent.ACTION_UP: {
                boolean was = pressActive;
                pressActive = false;
                animatePress(0f, 260, true);
                if (was) performClick();
                return true;
            }
            case MotionEvent.ACTION_CANCEL:
                pressActive = false;
                animatePress(0f, 200, true);
                return true;
            default:
                return true;
        }
    }

    @Override public boolean performClick() { return super.performClick(); }
}

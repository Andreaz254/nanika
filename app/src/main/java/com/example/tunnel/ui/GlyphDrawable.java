package com.example.tunnel.ui;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/**
 * Crisp, code-drawn protocol icons (SSH terminal, VLESS paper plane, VMess cube) on a 24x24 grid.
 * Drawn with a Canvas so they always render, at any size, in any colour (use ImageView.setColorFilter).
 */
public final class GlyphDrawable extends Drawable {
    public static final int SSH = 0, VLESS = 1, VMESS = 2;

    private final int kind;
    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private final RectF rect = new RectF();

    public GlyphDrawable(int kind) {
        this.kind = kind;
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeCap(Paint.Cap.ROUND);
        p.setStrokeJoin(Paint.Join.ROUND);
        p.setStrokeWidth(1.9f);
        p.setColor(0xFF000000);
    }

    @Override
    public void draw(Canvas c) {
        float s = Math.min(getBounds().width(), getBounds().height()) / 24f;
        if (s <= 0) return;
        c.save();
        c.translate(getBounds().left, getBounds().top);
        c.scale(s, s);
        path.reset();
        if (kind == SSH) {
            rect.set(2.5f, 3.5f, 21.5f, 20.5f);
            c.drawRoundRect(rect, 2.4f, 2.4f, p);
            path.moveTo(6.8f, 9.2f);
            path.lineTo(10f, 12f);
            path.lineTo(6.8f, 14.8f);
            c.drawPath(path, p);
            c.drawLine(12f, 16f, 17f, 16f, p);
        } else if (kind == VLESS) {
            path.moveTo(21f, 3f);
            path.lineTo(3f, 10.5f);
            path.lineTo(10f, 13.5f);
            path.lineTo(13f, 21f);
            path.close();
            c.drawPath(path, p);
            c.drawLine(10f, 13.5f, 21f, 3f, p);
        } else {
            path.moveTo(12f, 2.5f);
            path.lineTo(20.5f, 7.25f);
            path.lineTo(20.5f, 16.75f);
            path.lineTo(12f, 21.5f);
            path.lineTo(3.5f, 16.75f);
            path.lineTo(3.5f, 7.25f);
            path.close();
            c.drawPath(path, p);
            path.reset();
            path.moveTo(3.5f, 7.25f);
            path.lineTo(12f, 12f);
            path.lineTo(20.5f, 7.25f);
            c.drawPath(path, p);
            c.drawLine(12f, 12f, 12f, 21.5f, p);
        }
        c.restore();
    }

    @Override public void setAlpha(int alpha) { p.setAlpha(alpha); invalidateSelf(); }
    @Override public void setColorFilter(ColorFilter cf) { p.setColorFilter(cf); invalidateSelf(); }
    @Override public int getOpacity() { return PixelFormat.TRANSLUCENT; }
}

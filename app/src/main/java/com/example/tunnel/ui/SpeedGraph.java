package com.example.tunnel.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Shader;
import android.view.View;

import com.example.tunnel.share.SpeedMonitor;

/** Live line graph of download (orange) and upload (purple) speed over the last minute and a half. */
public class SpeedGraph extends View {
    private final Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint grid = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint label = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path(), area = new Path();
    private final float dp;
    private float[] down = new float[0], up = new float[0];
    private float shownMax = 20000;
    private int downColor = 0xFFF26B21, upColor = 0xFF8A4DE0, gridColor = 0x33888888, textColor = 0xFF888888;

    public SpeedGraph(Context c) {
        super(c);
        dp = c.getResources().getDisplayMetrics().density;
        line.setStyle(Paint.Style.STROKE);
        line.setStrokeWidth(2.2f * dp);
        line.setStrokeCap(Paint.Cap.ROUND);
        line.setStrokeJoin(Paint.Join.ROUND);
        grid.setStyle(Paint.Style.STROKE);
        grid.setStrokeWidth(1f * dp);
        label.setTextSize(10f * dp);
    }

    public void setColors(int down, int up, int grid, int text) {
        downColor = down; upColor = up; gridColor = grid; textColor = text;
        invalidate();
    }

    public void setData(float[] down, float[] up) {
        this.down = down;
        this.up = up;
        invalidate();
    }

    @Override protected void onMeasure(int w, int h) {
        setMeasuredDimension(resolveSize((int) (300 * dp), w), resolveSize((int) (190 * dp), h));
    }

    private static float niceCeil(float v) {
        float[] steps = {1, 2, 5};
        float mag = 1;
        while (mag * 10 < v) mag *= 10;
        for (float s : steps) if (s * mag >= v) return s * mag;
        return mag * 10;
    }

    @Override protected void onDraw(Canvas c) {
        float left = 46 * dp, right = getWidth() - 8 * dp, top = 8 * dp, bottom = getHeight() - 16 * dp;
        float w = right - left, h = bottom - top;
        float peak = 10000;
        for (float v : down) peak = Math.max(peak, v);
        for (float v : up) peak = Math.max(peak, v);
        float target = niceCeil(peak * 1.15f);
        shownMax += (target - shownMax) * 0.35f;                 // eased, so the scale does not jump
        if (Math.abs(target - shownMax) > 1f) postInvalidateDelayed(40);

        grid.setColor(gridColor);
        label.setColor(textColor);
        label.setTextAlign(Paint.Align.RIGHT);
        for (int i = 0; i <= 4; i++) {
            float y = bottom - h * i / 4f;
            c.drawLine(left, y, right, y, grid);
            c.drawText(SpeedMonitor.speed(shownMax * i / 4f).replace("/s", ""), left - 5 * dp, y + 3.5f * dp, label);
        }
        label.setTextAlign(Paint.Align.LEFT);
        c.drawText("90 s ago", left, getHeight() - 3 * dp, label);
        label.setTextAlign(Paint.Align.RIGHT);
        c.drawText("now", right, getHeight() - 3 * dp, label);

        series(c, up, upColor, left, bottom, w, h);
        series(c, down, downColor, left, bottom, w, h);
    }

    private void series(Canvas c, float[] d, int color, float left, float bottom, float w, float h) {
        int n = d.length;
        if (n < 2) return;
        float step = w / (SpeedMonitor.HISTORY - 1);
        float x0 = left + w - step * (n - 1);                   // newest sample sits on the right edge
        path.reset();
        area.reset();
        float px = x0, py = y(d[0], bottom, h);
        path.moveTo(px, py);
        area.moveTo(px, bottom);
        area.lineTo(px, py);
        for (int i = 1; i < n; i++) {
            float x = x0 + step * i, yv = y(d[i], bottom, h);
            float mx = (px + x) / 2f;
            path.cubicTo(mx, py, mx, yv, x, yv);
            area.cubicTo(mx, py, mx, yv, x, yv);
            px = x;
            py = yv;
        }
        area.lineTo(px, bottom);
        area.close();
        fill.setShader(new LinearGradient(0, bottom - h, 0, bottom, (color & 0x00FFFFFF) | 0x66000000,
                (color & 0x00FFFFFF) | 0x05000000, Shader.TileMode.CLAMP));
        c.drawPath(area, fill);
        line.setColor(color);
        c.drawPath(path, line);
    }

    private float y(float v, float bottom, float h) {
        return bottom - Math.min(1f, v / shownMax) * h;
    }
}

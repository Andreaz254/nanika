#!/usr/bin/env python3
"""
Builds every Nanika icon from ONE picture.

    python tools/make_icons.py path/to/images.jpg            # your artwork
    python tools/make_icons.py path/to/images.jpg --bg 1B1B1F # force the adaptive-icon background colour
    python tools/make_icons.py --placeholder                  # draws the stand-in fox that ships with the project

Writes into app/src/main/res/:
    mipmap-*/ic_launcher.png, ic_launcher_round.png, ic_launcher_foreground.png   (launcher icon)
    mipmap-anydpi-v26/ic_launcher.xml, ic_launcher_round.xml                      (adaptive icon, Android 8+)
    values/ic_launcher_background.xml                                             (adaptive background colour)
    drawable-nodpi/nanika_logo.png                                                (small round logo in the side panel)
and branding/nanika_512.png (for a store listing).

Needs Pillow:  pip install pillow
Tip: a square picture with the subject centred works best; the script centre-crops to a square.
"""
import argparse, os, sys
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "app", "src", "main", "res")
DENSITIES = {"mdpi": 1.0, "hdpi": 1.5, "xhdpi": 2.0, "xxhdpi": 3.0, "xxxhdpi": 4.0}


def placeholder(size=1024):
    """A simple orange fox head on a dark tile - only used until the real artwork is supplied."""
    im = Image.new("RGB", (size, size), (27, 27, 31))
    d = ImageDraw.Draw(im)
    s = size / 100.0
    def P(*pts): return [(x * s, y * s) for x, y in pts]
    orange, light, dark = (242, 107, 33), (255, 244, 234), (40, 24, 14)
    d.polygon(P((18, 14), (40, 36), (22, 52)), fill=orange)           # ears
    d.polygon(P((82, 14), (60, 36), (78, 52)), fill=orange)
    d.polygon(P((23, 24), (35, 37), (25, 46)), fill=dark)
    d.polygon(P((77, 24), (65, 37), (75, 46)), fill=dark)
    d.polygon(P((50, 30), (80, 48), (72, 70), (50, 88), (28, 70), (20, 48)), fill=orange)   # head
    d.polygon(P((50, 56), (74, 66), (62, 80), (50, 88), (38, 80), (26, 66)), fill=light)    # muzzle
    d.polygon(P((50, 80), (46, 84), (54, 84)), fill=dark)             # nose
    d.ellipse(P((33, 50), (41, 58)), fill=dark)                       # eyes
    d.ellipse(P((59, 50), (67, 58)), fill=dark)
    return im


def centre_square(im):
    w, h = im.size
    m = min(w, h)
    return im.crop(((w - m) // 2, (h - m) // 2, (w - m) // 2 + m, (h - m) // 2 + m))


def circle(im):
    im = im.convert("RGBA")
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, im.size[0] - 1, im.size[1] - 1), fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(0.6))
    out = Image.new("RGBA", im.size, (0, 0, 0, 0))
    out.paste(im, (0, 0), mask)
    return out


def rounded(im, radius_frac=0.22):
    im = im.convert("RGBA")
    mask = Image.new("L", im.size, 0)
    r = int(im.size[0] * radius_frac)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.size[0] - 1, im.size[1] - 1), radius=r, fill=255)
    out = Image.new("RGBA", im.size, (0, 0, 0, 0))
    out.paste(im, (0, 0), mask)
    return out


def corner_colour(im):
    px = im.convert("RGB").resize((8, 8))
    pts = [px.getpixel(p) for p in ((0, 0), (7, 0), (0, 7), (7, 7))]
    return tuple(sum(c[i] for c in pts) // 4 for i in range(3))


def save(im, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--bg", help="adaptive icon background, hex like 1B1B1F (default: the picture's corner colour)")
    ap.add_argument("--placeholder", action="store_true")
    a = ap.parse_args()
    if a.placeholder:
        src = placeholder()
    elif a.image:
        src = centre_square(Image.open(a.image).convert("RGB"))
    else:
        ap.error("give an image path or --placeholder")

    bg = tuple(int(a.bg[i:i + 2], 16) for i in (0, 2, 4)) if a.bg else corner_colour(src)
    src = src.resize((1024, 1024), Image.LANCZOS)

    for name, k in DENSITIES.items():
        legacy = int(round(48 * k))
        save(rounded(src.resize((legacy, legacy), Image.LANCZOS)), f"{RES}/mipmap-{name}/ic_launcher.png")
        save(circle(src.resize((legacy, legacy), Image.LANCZOS)), f"{RES}/mipmap-{name}/ic_launcher_round.png")
        # adaptive foreground: 108dp canvas, artwork inside the 66dp safe zone (the launcher masks the rest)
        full = int(round(108 * k))
        inner = int(round(66 * k))
        fg = Image.new("RGBA", (full, full), (0, 0, 0, 0))
        art = src.resize((inner, inner), Image.LANCZOS).convert("RGBA")
        fg.paste(art, ((full - inner) // 2, (full - inner) // 2))
        save(fg, f"{RES}/mipmap-{name}/ic_launcher_foreground.png")

    hexbg = "#%02X%02X%02X" % bg
    os.makedirs(f"{RES}/values", exist_ok=True)
    open(f"{RES}/values/ic_launcher_background.xml", "w").write(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
        f'    <color name="ic_launcher_background">{hexbg}</color>\n</resources>\n')
    os.makedirs(f"{RES}/mipmap-anydpi-v26", exist_ok=True)
    adaptive = ('<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@color/ic_launcher_background"/>\n'
                '    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>\n'
                '</adaptive-icon>\n')
    for n in ("ic_launcher.xml", "ic_launcher_round.xml"):
        open(f"{RES}/mipmap-anydpi-v26/{n}", "w").write(adaptive)

    save(circle(src.resize((160, 160), Image.LANCZOS)), f"{RES}/drawable-nodpi/nanika_logo.png")
    save(rounded(src.resize((512, 512), Image.LANCZOS)), os.path.join(ROOT, "branding", "nanika_512.png"))
    print("icons written to", RES, "(adaptive background", hexbg + ")")


if __name__ == "__main__":
    main()

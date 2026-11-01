#!/usr/bin/env python3
"""Generate the app's icons, logo and dashboard header from the brand logo.

Usage: python tools/gen_brand_assets.py   (needs Pillow, see requirements-dev.txt)

Source: assets/brand/shadowtrackr-logo.png (1024x1024, white helmet with a
red visor on brand blue). Everything is drawn at a large size and scaled down
with a Lanczos filter, which also smooths the source's hard pixel edges.

The wordmark uses Avenir Next from macOS. The generated PNGs are committed, so
only regenerating them needs that font.

Outputs:
  package/static/appIcon.png, appIcon_2x.png        36/72 px tile (light UI)
  package/static/appIconAlt.png, appIconAlt_2x.png  36/72 px tile with a rim (dark UI)
  package/static/appLogo.png, appLogo_2x.png        160x40/320x80 helmet + wordmark,
                                                    transparent, for the brand-blue app bar
  package/appserver/static/images/logo_tile.png     256 px tile for the Overview header
  assets/brand/splunkbase-icon-512.png              Splunkbase listing icon
"""

import os

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "assets", "brand", "shadowtrackr-logo.png")
FONT = "/System/Library/Fonts/Avenir Next.ttc"
FONT_DEMI_BOLD = 2

BLUE = (0x14, 0x55, 0x82)
BLUE_LIGHT = (0x1F, 0x6A, 0x9C)
WHITE = (255, 255, 255)

WORK = 1024  # working size for the square tile


def figure() -> Image.Image:
    """The helmet on a transparent background, cropped to its bounding box."""
    src = Image.open(SOURCE).convert("RGB")
    background = src.getpixel((0, 0))
    diff = ImageChops.difference(src, Image.new("RGB", src.size, background)).convert("L")
    alpha = diff.point(lambda v: 255 if v > 24 else 0)
    rgba = src.convert("RGBA")
    rgba.putalpha(alpha)
    return rgba.crop(alpha.getbbox())


def vertical_gradient(size, top, bottom) -> Image.Image:
    w, h = size
    grad = Image.new("RGB", (1, h))
    for y in range(h):
        t = y / max(h - 1, 1)
        grad.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)))
    return grad.resize((w, h))


def rounded_mask(size, radius) -> Image.Image:
    mask = Image.new("L", size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size[0] - 1, size[1] - 1), radius=radius, fill=255)
    return mask


def tile(rim: bool = False) -> Image.Image:
    """Rounded brand-blue tile with the helmet, at WORK x WORK."""
    canvas = Image.new("RGBA", (WORK, WORK), (0, 0, 0, 0))
    body = vertical_gradient((WORK, WORK), BLUE_LIGHT, BLUE).convert("RGBA")
    head = figure()
    # The helmet fills about 78% of the tile height, like the source logo.
    scale = (WORK * 0.78) / head.height
    head = head.resize((round(head.width * scale), round(head.height * scale)), Image.LANCZOS)
    body.alpha_composite(head, ((WORK - head.width) // 2, round(WORK * 0.115)))
    canvas.paste(body, (0, 0), rounded_mask((WORK, WORK), round(WORK * 0.22)))
    if rim:
        # A faint light edge keeps the tile from sinking into dark menus.
        ring = Image.new("RGBA", (WORK, WORK), (0, 0, 0, 0))
        ImageDraw.Draw(ring).rounded_rectangle(
            (6, 6, WORK - 7, WORK - 7), radius=round(WORK * 0.21), outline=(255, 255, 255, 70), width=14
        )
        canvas.alpha_composite(ring)
    return canvas


def save(img: Image.Image, *path: str, size=None) -> None:
    out = os.path.join(ROOT, *path)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if size:
        img = img.resize(size, Image.LANCZOS)
    if size and size[0] <= 72:
        # A light sharpen restores crispness lost in the big downscale.
        img = img.filter(ImageFilter.UnsharpMask(radius=0.6, percent=60, threshold=2))
    img.save(out, optimize=True)
    print("wrote", os.path.relpath(out, ROOT), img.size)


def font(index: int, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT, size, index=index)


def app_logo(scale: int) -> Image.Image:
    """Helmet plus wordmark, white on transparent, for the brand-blue app bar."""
    w, h = 160 * scale, 40 * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    head = figure()
    head_h = round(h * 0.84)
    head = head.resize((round(head.width * head_h / head.height), head_h), Image.LANCZOS)
    img.alpha_composite(head, (round(2 * scale), (h - head_h) // 2))
    draw = ImageDraw.Draw(img)
    text_font = font(FONT_DEMI_BOLD, round(17 * scale))
    x = head.width + round(8 * scale)
    bbox = draw.textbbox((0, 0), "ShadowTrackr", font=text_font)
    y = (h - (bbox[3] - bbox[1])) // 2 - bbox[1]
    draw.text((x, y), "ShadowTrackr", font=text_font, fill=WHITE)
    return img


def main():
    light = tile()
    dark = tile(rim=True)
    save(light, "package", "static", "appIcon.png", size=(36, 36))
    save(light, "package", "static", "appIcon_2x.png", size=(72, 72))
    save(dark, "package", "static", "appIconAlt.png", size=(36, 36))
    save(dark, "package", "static", "appIconAlt_2x.png", size=(72, 72))
    save(app_logo(1), "package", "static", "appLogo.png")
    save(app_logo(2), "package", "static", "appLogo_2x.png")
    save(light, "package", "appserver", "static", "images", "logo_tile.png", size=(256, 256))
    save(light, "assets", "brand", "splunkbase-icon-512.png", size=(512, 512))


if __name__ == "__main__":
    main()

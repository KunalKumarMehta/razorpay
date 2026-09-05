import os
from PIL import Image, ImageDraw, ImageFilter

def create_backgrounds():
    os.makedirs("build/assets", exist_ok=True)
    width, height = 2400, 1350  # 16:9 1080p/4K presentation canvas

    # =========================================================================
    # 1. Content Slide Background: Deep Obsidian-Navy with Butter-Smooth Ambient Bloom
    #    (ZERO concentric circles, ZERO divider lines, 100% clean reading canvas)
    # =========================================================================
    bg_content = Image.new("RGB", (width, height), (8, 13, 24))
    draw_c = ImageDraw.Draw(bg_content)

    # Ultra-smooth vertical gradient: #080D18 to #03060B
    for y in range(height):
        p = y / height
        r = int(8 * (1 - p) + 3 * p)
        g = int(13 * (1 - p) + 6 * p)
        b = int(24 * (1 - p) + 11 * p)
        draw_c.line([(0, y), (width, y)], fill=(r, g, b))

    # Soft ambient glow in top-right corner (diffuse Razorpay Blue bloom, no rings)
    glow_c = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    glow_draw_c = ImageDraw.Draw(glow_c)
    glow_draw_c.ellipse(
        [(int(width * 0.70), -int(height * 0.25)), (int(width * 1.15), int(height * 0.55))],
        fill=(0, 110, 255, 30)
    )
    glow_c = glow_c.filter(ImageFilter.GaussianBlur(radius=150))
    bg_content.paste(glow_c, (0, 0), glow_c)

    content_path = "build/assets/slide_bg_content.png"
    bg_content.save(content_path, "PNG", quality=95)
    print(f"Generated clean content background: {content_path}")

    # =========================================================================
    # 2. Hero Slide Background: Deep Midnight with Centered Subtle Radial Aura
    # =========================================================================
    bg_hero = Image.new("RGB", (width, height), (6, 10, 20))
    draw_h = ImageDraw.Draw(bg_hero)

    for y in range(height):
        p = y / height
        r = int(6 * (1 - p) + 2 * p)
        g = int(10 * (1 - p) + 4 * p)
        b = int(20 * (1 - p) + 8 * p)
        draw_h.line([(0, y), (width, y)], fill=(r, g, b))

    # Gentle center-top ambient diffuse bloom
    glow_h = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    glow_draw_h = ImageDraw.Draw(glow_h)
    glow_draw_h.ellipse(
        [(int(width * 0.25), int(height * 0.05)), (int(width * 0.75), int(height * 0.75))],
        fill=(0, 140, 255, 28)
    )
    # Subtle secondary cyan touch
    glow_draw_h.ellipse(
        [(int(width * 0.35), int(height * 0.15)), (int(width * 0.65), int(height * 0.60))],
        fill=(0, 220, 255, 18)
    )
    glow_h = glow_h.filter(ImageFilter.GaussianBlur(radius=160))
    bg_hero.paste(glow_h, (0, 0), glow_h)

    hero_path = "build/assets/slide_bg_hero.png"
    bg_hero.save(hero_path, "PNG", quality=95)
    print(f"Generated clean hero background: {hero_path}")

if __name__ == "__main__":
    create_backgrounds()

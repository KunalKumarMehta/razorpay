import os
import math
from PIL import Image, ImageDraw

def create_backgrounds():
    os.makedirs("build/assets", exist_ok=True)
    width, height = 2400, 1350  # 16:9 ultra-clean canvas

    # ==========================================
    # 1. Content Slides Background: Deep Obsidian to Midnight Navy Gradient + Subtle Glow
    # ==========================================
    img_content = Image.new("RGB", (width, height), "#060A14")
    draw_c = ImageDraw.Draw(img_content)

    # Linear vertical gradient
    for y in range(height):
        # Progress 0.0 to 1.0
        p = y / height
        # Blend from #070D1A to #0D1A33
        r = int(7 + p * (13 - 7))
        g = int(13 + p * (26 - 13))
        b = int(26 + p * (51 - 26))
        draw_c.line([(0, y), (width, y)], fill=(r, g, b))

    # Add soft radial glow at top-right (Razorpay Blue aura)
    cx, cy = int(width * 0.85), int(height * 0.15)
    max_radius = 900
    for rad in range(max_radius, 0, -10):
        alpha = int((1.0 - (rad / max_radius) ** 0.8) * 32)
        if alpha > 0:
            glow_color = (26, 86, 230)
            # Soft concentric circles
            draw_c.ellipse(
                [(cx - rad, cy - rad), (cx + rad, cy + rad)],
                outline=glow_color,
                width=8
            )

    # Subtle horizontal grid line near top header
    header_y = int(height * 0.20)
    draw_c.line([(80, header_y), (width - 80, header_y)], fill=(30, 50, 85), width=2)

    content_path = "build/assets/slide_bg_content.png"
    img_content.save(content_path, "PNG")
    print(f"Generated: {content_path}")

    # ==========================================
    # 2. Hero Slide Background: Dramatic Central Accent Aura
    # ==========================================
    img_hero = Image.new("RGB", (width, height), "#050811")
    draw_h = ImageDraw.Draw(img_hero)

    # Vertical gradient
    for y in range(height):
        p = y / height
        r = int(5 + p * (15 - 5))
        g = int(8 + p * (24 - 8))
        b = int(17 + p * (54 - 17))
        draw_h.line([(0, y), (width, y)], fill=(r, g, b))

    # Central Blue / Cyan Aura
    hcx, hcy = int(width * 0.5), int(height * 0.45)
    h_radius = 1100
    for rad in range(h_radius, 0, -8):
        alpha = (1.0 - (rad / h_radius) ** 0.6)
        r = int(10 + alpha * 30)
        g = int(40 + alpha * 90)
        b = int(120 + alpha * 135)
        draw_h.ellipse(
            [(hcx - rad, hcy - rad), (hcx + rad, hcy + rad)],
            outline=(r, g, b),
            width=6
        )

    hero_path = "build/assets/slide_bg_hero.png"
    img_hero.save(hero_path, "PNG")
    print(f"Generated: {hero_path}")

if __name__ == "__main__":
    create_backgrounds()

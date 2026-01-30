#!/usr/bin/env python3
"""
Create Teams app icons with AWS branding and authentication indicators
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_teams_icons():
    """Create color and outline icons for Teams app"""
    
    # Create color icon (192x192) with AWS styling
    color_img = Image.new('RGB', (192, 192), color='#232F3E')  # AWS Dark Blue
    draw = ImageDraw.Draw(color_img)

    # Draw AWS-style background with gradient effect
    draw.rectangle([16, 16, 176, 176], fill='#FF9900', outline='#232F3E', width=4)  # AWS Orange

    # Draw OpsAgent logo
    draw.ellipse([48, 48, 144, 144], fill='#232F3E')
    draw.ellipse([56, 56, 136, 136], fill='#FF9900')

    # Add text
    try:
        font_large = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 32)
        font_small = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
    except:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    draw.text((96, 88), 'OA', fill='#232F3E', anchor='mm', font=font_large)
    draw.text((96, 118), 'AWS', fill='#232F3E', anchor='mm', font=font_small)

    # Add authentication indicator
    draw.ellipse([140, 40, 160, 60], fill='#28a745')  # Green dot for auth
    draw.text((150, 50), '🔐', fill='white', anchor='mm')

    color_img.save('color.png')

    # Create outline icon (32x32) with AWS styling
    outline_img = Image.new('RGBA', (32, 32), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(outline_img)

    # AWS-style outline
    draw.rectangle([2, 2, 30, 30], outline='#FF9900', width=2)
    draw.ellipse([6, 6, 26, 26], outline='white', width=2)
    draw.text((16, 16), 'O', fill='white', anchor='mm')

    # Add small auth indicator
    draw.ellipse([22, 6, 28, 12], fill='#28a745')

    outline_img.save('outline.png')
    
    print("✅ Created Teams app icons: color.png (192x192) and outline.png (32x32)")

if __name__ == "__main__":
    create_teams_icons()
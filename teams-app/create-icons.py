#!/usr/bin/env python3
"""
Create simple placeholder icons for the Teams app
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_color_icon():
    """Create a 192x192 color icon"""
    # Create image with orange background
    img = Image.new('RGB', (192, 192), '#FF6B35')
    draw = ImageDraw.Draw(img)
    
    # Draw a simple robot/ops icon
    # Head circle
    draw.ellipse([60, 40, 132, 112], fill='white', outline='#333333', width=3)
    
    # Eyes
    draw.ellipse([75, 60, 85, 70], fill='#333333')
    draw.ellipse([107, 60, 117, 70], fill='#333333')
    
    # Mouth
    draw.arc([80, 80, 112, 95], 0, 180, fill='#333333', width=3)
    
    # Body rectangle
    draw.rectangle([75, 112, 117, 160], fill='white', outline='#333333', width=3)
    
    # Arms
    draw.rectangle([45, 125, 75, 135], fill='white', outline='#333333', width=2)
    draw.rectangle([117, 125, 147, 135], fill='white', outline='#333333', width=2)
    
    # Add "OPS" text
    try:
        # Try to use a system font
        font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
    except:
        # Fallback to default font
        font = ImageFont.load_default()
    
    draw.text((85, 140), "OPS", fill='#333333', font=font, anchor="mm")
    
    img.save('color.png')
    print("Created color.png (192x192)")

def create_outline_icon():
    """Create a 32x32 outline icon"""
    # Create transparent image
    img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw simple white outline robot
    # Head circle
    draw.ellipse([8, 4, 24, 20], fill=None, outline='white', width=2)
    
    # Eyes
    draw.point([12, 10], fill='white')
    draw.point([20, 10], fill='white')
    
    # Body rectangle
    draw.rectangle([10, 20, 22, 28], fill=None, outline='white', width=2)
    
    img.save('outline.png')
    print("Created outline.png (32x32)")

if __name__ == "__main__":
    create_color_icon()
    create_outline_icon()
    print("Icons created successfully!")
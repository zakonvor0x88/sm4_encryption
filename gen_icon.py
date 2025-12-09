#!/usr/bin/env python3
"""Generate simple ICO icon with padlock design"""

import struct
import os


def gen_icon():
    """Create 16x16 ICO with padlock"""
    # Use PIL if available, else create raw ICO
    try:
        from PIL import Image, ImageDraw
        # Create image
        img = Image.new('RGB', (32, 32), color=(15, 20, 25))
        draw = ImageDraw.Draw(img)
        
        # Draw lock: arc + body + hole
        # Arc (padlock top)
        draw.arc([(10, 8), (22, 20)], 0, 180, fill=(0, 217, 255), width=2)
        # Body
        draw.rectangle([(9, 16), (23, 26)], fill=(0, 217, 255))
        # Hole
        draw.ellipse([(14, 18), (18, 22)], fill=(0, 0, 0))
        
        img.save('sm4_app_icon.ico')
        print("✅ Icon created with PIL")
        return
    except ImportError:
        pass
    
    # Fallback: write minimal ICO directly
    width, height = 16, 16
    
    ico = bytearray()
    # ICO header
    ico += struct.pack('<HHH', 0, 1, 1)
    # Image dir entry
    ico += struct.pack('<2BI2HI', width, height, 0, 1, 1, 8, 1078, 22)
    
    # INFOHEADER
    ico += struct.pack('<2I2HI4I', 40, width, height*2, 1, 8, 0, 0, 0, 0, 0)
    
    # Simple palette (grays + cyan)
    for i in range(256):
        if i == 0:
            ico += struct.pack('<BBBB', 15, 20, 25, 0)  # dark bg
        elif 1 <= i <= 6:
            val = 30 + i * 40
            ico += struct.pack('<BBBB', val, val, val, 0)
        elif i == 7:
            ico += struct.pack('<BBBB', 255, 217, 0, 0)  # cyan
        else:
            ico += struct.pack('<BBBB', 128, 128, 128, 0)
    
    # Pixels (bottom-up)
    pixels = [[0] * width for _ in range(height)]
    
    # Draw simple padlock (cyan color #7)
    # Arc
    for y in range(3, 9):
        for x in range(3, 13):
            dx, dy = x - 8, y - 5
            if 4 < (dx*dx + dy*dy)**0.5 < 6:
                pixels[y][x] = 7
    
    # Body
    for y in range(8, 14):
        for x in range(2, 14):
            pixels[y][x] = 7
    
    # Hole
    for y in range(9, 12):
        for x in range(7, 10):
            if (x - 8.5)**2 + (y - 10.5)**2 <= 1.5:
                pixels[y][x] = 0
    
    # Write pixels (upside down)
    for y in range(height - 1, -1, -1):
        for x in range(width):
            ico += struct.pack('B', pixels[y][x])
    
    # AND mask
    for _ in range(height):
        ico += b'\xff' * width
    
    with open('sm4_app_icon.ico', 'wb') as f:
        f.write(ico)
    
    print("✅ Icon created: sm4_app_icon.ico")


if __name__ == '__main__':
    gen_icon()

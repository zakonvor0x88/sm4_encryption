#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create a simple pen icon (ICO) without external libraries.
"""

def create_pen_icon():
    # Minimal ICO construction reusing the simple BMP approach used before
    # This draws a dark-blue background and a white/yellow pen shape
    ico_data = bytearray([
        0x00,0x00,0x01,0x00,0x01,0x00,0x20,0x20,0x20,0x00,0x01,0x00,0x20,0x00,0x48,0x00,0x00,0x00,0x16,0x00,0x00,0x00
    ])

    bmp = bytearray()
    # BMP header
    bmp.extend([
        0x42,0x4D,  # BM
        0x86,0x00,0x04,0x00,
        0x00,0x00,0x00,0x00,
        0x36,0x00,0x00,0x00,
    ])
    # DIB header
    bmp.extend([
        0x28,0x00,0x00,0x00,
        0x20,0x00,0x00,0x00,
        0x40,0x00,0x00,0x00,
        0x01,0x00,
        0x20,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x04,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
    ])

    # Colors
    blue = bytes([0xd4,0x78,0x00,0xFF])
    white = bytes([0xFF,0xFF,0xFF,0xFF])
    yellow = bytes([0x00,0xC8,0xFF,0xFF])  # BGR-ish

    # Draw 32x32 pixels with simple pen shape
    for y in range(32):
        for x in range(32):
            # Pen diagonal from top-left to bottom-right
            if 6 <= x <= 25 and 6 <= y <= 25 and abs(x-y) <= 2 and x+y > 12:
                # pen body
                bmp.extend(yellow)
            elif 12 <= x <= 20 and 20 <= y <= 26:
                # pen tip area darker
                bmp.extend(white)
            else:
                bmp.extend(blue)
    # mask
    for _ in range(32*32):
        bmp.extend([0x00,0x00,0x00,0x00])

    ico_data.extend(bmp)
    with open('sm4_pen_icon.ico','wb') as f:
        f.write(ico_data)
    print('✅ Created sm4_pen_icon.ico')

if __name__=='__main__':
    create_pen_icon()

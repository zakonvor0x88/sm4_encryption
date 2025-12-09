#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор іконки для SM4 Encryption у форматі BMP
"""

def create_simple_icon():
    """Створити просту іконку як BMP файл."""
    
    # Розмір: 256x256 пікселів
    width, height = 256, 256
    
    # ICO файл з одним простим зображенням (16x16)
    # Це мінімальна валідна ICO структура
    
    ico_data = bytearray([
        # ICO Header
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20,
        0x20, 0x00, 0x01, 0x00, 0x20, 0x00, 0x48, 0x00,
        0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    ])
    
    # BMP Header для 32x32 зображення
    bmp_data = bytearray()
    
    # BMP File Header (14 байтів)
    bmp_data.extend([
        0x42, 0x4D,  # "BM"
        0x86, 0x00, 0x04, 0x00,  # Розмір файлу
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x36, 0x00, 0x00, 0x00,  # Offset to pixel data
    ])
    
    # BMP Info Header (40 байтів)
    bmp_data.extend([
        0x28, 0x00, 0x00, 0x00,  # Header size
        0x20, 0x00, 0x00, 0x00,  # Width: 32
        0x40, 0x00, 0x00, 0x00,  # Height: 64 (32 + 32 mask)
        0x01, 0x00,  # Planes: 1
        0x20, 0x00,  # Bits per pixel: 32
        0x00, 0x00, 0x00, 0x00,  # Compression: none
        0x00, 0x00, 0x04, 0x00,  # Image size
        0x00, 0x00, 0x00, 0x00,  # X pixels per meter
        0x00, 0x00, 0x00, 0x00,  # Y pixels per meter
        0x00, 0x00, 0x00, 0x00,  # Colors used
        0x00, 0x00, 0x00, 0x00,  # Important colors
    ])
    
    # Pixel data - синій квадрат з білим замком
    # Синій фон: #0078d4 = (212, 120, 0) в BGR
    blue = bytes([0xd4, 0x78, 0x00, 0xFF])  # BGRA
    white = bytes([0xFF, 0xFF, 0xFF, 0xFF])
    
    # 32x32 пікселі
    for y in range(32):
        for x in range(32):
            # Малюємо замок (білий) на синьому фоні
            # Дужка замка (гарний半圓arc)
            if 8 <= x <= 24 and 6 <= y <= 12:
                dx = x - 16
                dy = y - 6
                if dx*dx + dy*dy <= 64:
                    bmp_data.extend(white)
                else:
                    bmp_data.extend(blue)
            # Тіло замка
            elif 10 <= x <= 22 and 12 <= y <= 28:
                bmp_data.extend(white)
            # Скважина замка
            elif 13 <= x <= 19 and 15 <= y <= 21:
                dx = x - 16
                dy = y - 18
                if dx*dx + dy*dy <= 9:
                    bmp_data.extend(blue)
                else:
                    bmp_data.extend(white)
            else:
                bmp_data.extend(blue)
    
    # Маска (32x32 білі пікселі)
    for _ in range(32 * 32):
        bmp_data.extend([0x00, 0x00, 0x00, 0x00])
    
    # Об'єднати ICO header і BMP дані
    ico_data.extend(bmp_data)
    
    # Зберегти файл
    with open('sm4_app_icon.ico', 'wb') as f:
        f.write(ico_data)
    
    print("✅ Іконка успішно створена: sm4_app_icon.ico")

if __name__ == "__main__":
    create_simple_icon()

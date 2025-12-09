#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор іконки для SM4 Encryption
Створює ICO файл програматично
"""

from PIL import Image, ImageDraw
import os

def create_icon(size=256):
    """Створити іконку для SM4 Encryption."""
    
    # Створити новий образ з блакитним фоном
    img = Image.new('RGB', (size, size), color='#0078d4')
    draw = ImageDraw.Draw(img)
    
    # Малюємо замок (символ безпеки)
    lock_width = int(size * 0.4)
    lock_height = int(size * 0.45)
    lock_x = (size - lock_width) // 2
    lock_y = (size - lock_height) // 2 + int(size * 0.05)
    
    # Тіло замка (прямокутник)
    draw.rectangle(
        [lock_x, lock_y + int(lock_height * 0.45), 
         lock_x + lock_width, lock_y + lock_height],
        fill='white',
        outline='white'
    )
    
    # Дужка замка (дуга)
    draw.arc(
        [lock_x + int(lock_width * 0.15), lock_y,
         lock_x + lock_width - int(lock_width * 0.15), lock_y + int(lock_height * 0.5)],
        start=0,
        end=180,
        fill='white',
        width=int(size * 0.04)
    )
    
    # Замкова скважина
    keyhole_x = lock_x + lock_width // 2
    keyhole_y = lock_y + int(lock_height * 0.65)
    keyhole_radius = int(size * 0.05)
    
    draw.ellipse(
        [keyhole_x - keyhole_radius, keyhole_y - keyhole_radius,
         keyhole_x + keyhole_radius, keyhole_y + keyhole_radius],
        fill='#0078d4'
    )
    
    return img

def create_all_sizes():
    """Створити іконку в різних розмірах."""
    sizes = [16, 32, 64, 128, 256]
    images = []
    
    for size in sizes:
        img = create_icon(size)
        images.append(img)
    
    # Зберегти як ICO з кількома розмірами
    images[0].save(
        'sm4_app_icon.ico',
        format='ICO',
        sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256)],
        append_images=images[1:]
    )
    
    print("✅ Іконка успішно створена: sm4_app_icon.ico")

if __name__ == "__main__":
    create_all_sizes()

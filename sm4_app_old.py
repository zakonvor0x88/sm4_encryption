#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 Encryption - Мінімалістична утиліта для шифрування файлів
"""

from __future__ import annotations

import os
import secrets
import sys
from typing import List, Tuple
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading


# ===================== ЯДРО АЛГОРИТМУ SM4 =====================

SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]


def _rotl(x: int, n: int) -> int:
    """Кільцева ротація 32-бітного слова вліво."""
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _tau(a: int) -> int:
    """Нелінійна підстановка τ: застосування S-box до кожного байта."""
    b0 = SBOX[(a >> 24) & 0xFF]
    b1 = SBOX[(a >> 16) & 0xFF]
    b2 = SBOX[(a >> 8) & 0xFF]
    b3 = SBOX[a & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def _L_enc(b: int) -> int:
    """Лінійне перетворення L для раундової функції."""
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _L_key(b: int) -> int:
    """Лінійне перетворення L' для розгортання ключа."""
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _T_enc(x: int) -> int:
    return _L_enc(_tau(x))


def _T_key(x: int) -> int:
    return _L_key(_tau(x))


def _bytes_to_words(block: bytes) -> List[int]:
    if len(block) != 16:
        raise ValueError("Блок SM4 повинен містити рівно 16 байтів.")
    return [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]


def _words_to_bytes(words: List[int]) -> bytes:
    if len(words) != 4:
        raise ValueError("Очікується чотири 32-бітні слова.")
    return b"".join(w.to_bytes(4, "big") for w in words)


class SM4:
    """Реалізація блочного шифру SM4 (SMS4)."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("Ключ SM4 повинен бути довжиною 16 байтів (128 біт).")
        self._rk_enc = self._key_schedule(key)
        self._rk_dec = list(reversed(self._rk_enc))

    def _key_schedule(self, key: bytes) -> List[int]:
        MK = _bytes_to_words(key)
        K = [MK[i] ^ FK[i] for i in range(4)]
        rk: List[int] = []
        for i in range(32):
            t = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]
            K.append(K[i] ^ _T_key(t))
            rk.append(K[i + 4])
        return rk

    def _crypt_block(self, block: bytes, round_keys: List[int]) -> bytes:
        X = _bytes_to_words(block)
        for i in range(32):
            t = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ round_keys[i]
            X.append(X[i] ^ _T_enc(t))
        Y = [X[35], X[34], X[33], X[32]]
        return _words_to_bytes(Y)

    def encrypt_block(self, block: bytes) -> bytes:
        """Шифрування одного блоку (16 байтів)."""
        return self._crypt_block(block, self._rk_enc)

    def decrypt_block(self, block: bytes) -> bytes:
        """Розшифрування одного блоку (16 байтів)."""
        return self._crypt_block(block, self._rk_dec)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Некоректна довжина даних: не кратна розміру блоку.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Некоректні байти доповнення (PKCS#7).")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Пошкоджене або некоректне доповнення (PKCS#7).")
    return data[:-pad_len]


def sm4_encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Шифрування довільних даних у режимі ECB з PKCS#7."""
    cipher = SM4(key)
    padded = pkcs7_pad(data, 16)
    out = bytearray()
    for i in range(0, len(padded), 16):
        out.extend(cipher.encrypt_block(padded[i:i + 16]))
    return bytes(out)


def sm4_decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Розшифрування даних у режимі ECB з видаленням PKCS#7."""
    if len(data) % 16 != 0:
        raise ValueError("Шифртекст у режимі ECB повинен мати довжину, кратну 16 байтам.")
    cipher = SM4(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out.extend(cipher.decrypt_block(data[i:i + 16]))
    return pkcs7_unpad(bytes(out), 16)


def generate_key() -> bytes:
    """Генерація випадкового 128-бітного ключа SM4."""
    return secrets.token_bytes(16)


def save_key_hex(key: bytes, path: str) -> None:
    """Збереження ключа у текстовий файл у форматі hex."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(key.hex() + "\n")


def load_key_hex(path: str) -> bytes:
    """Завантаження ключа з текстового файлу (hex)."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("Файл ключа містить некоректні символи (очікується hex).") from exc
    if len(key) != 16:
        raise ValueError("Ключ у файлі має некоректну довжину (очікується 16 байтів).")
    return key


# ===================== ГРАФІЧНИЙ ІНТЕРФЕЙС (СУЧАСНИЙ ДИЗАЙН) =====================

class AboutWindow(tk.Toplevel):
    """Вікно з інформацією про програму."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Про програму")
        self.geometry("500x400")
        self.resizable(False, False)
        
        # Центрування вікна
        self.transient(parent)
        self.grab_set()
        
        # Заголовок
        title_frame = ttk.Frame(self, padding=15)
        title_frame.pack(fill="x", expand=False)
        
        title_label = ttk.Label(
            title_frame,
            text="ℹ SM4 Encryption",
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack()
        
        # Основний текст
        text_frame = ttk.Frame(self, padding=15)
        text_frame.pack(fill="both", expand=True)
        
        info_text = tk.Text(
            text_frame,
            wrap="word",
            height=16,
            font=("Segoe UI", 10),
            bg="#f5f5f5",
            relief="flat",
            borderwidth=0
        )
        info_text.pack(fill="both", expand=True)
        
        info_content = """SM4 Encryption - мінімалістична утиліта для шифрування файлів

🔐 АЛГОРИТМ
Використовує китайський стандартний блоковий шифр SM4 (SMS4):
• Розмір блоку: 128 біт (16 байтів)
• Розмір ключа: 128 біт (16 байтів)
• Режим: ECB з доповненням PKCS#7

📋 ЯК КОРИСТУВАТИСЯ

1. Шифрування:
   • Виберіть файл для шифрування
   • Виберіть або згенеруйте ключ (можна додатково вказати місце збереження)
   • Натисніть "Зашифрувати"
   • Файл буде зберіжено в папці вхідного файлу з розширенням .enc

2. Розшифрування:
   • Виберіть зашифрований файл
   • Виберіть ключ, що використовується
   • Натисніть "Розшифрувати"
   • Результат буде збережено в папці вхідного файлу з розширенням .dec

⚙️ КЛЮЧІ
• Ключі можна генерувати автоматично
• Ключі зберігаються у форматі HEX
• Для успішного розшифрування потрібен точно той же ключ
"""
        
        info_text.insert("1.0", info_content)
        info_text.config(state="disabled")
        
        # Кнопка закриття
        close_btn = ttk.Button(self, text="Закрити", command=self.destroy)
        close_btn.pack(pady=10)


class SM4App(tk.Tk):
    """Головне вікно програми з мінімалістичним дизайном."""

    def __init__(self):
        super().__init__()

        self.title("SM4 Encryption")
        # Більше вікно за замовчуванням, фіксований розмір як у класичних Windows додатках
        self.geometry("1400x900")
        self.resizable(False, False)

        # Кольорова схема — Windows-like
        self.bg_color = "#F3F6FB"
        self.accent_color = "#0078D4"
        self.text_color = "#202124"
        self.warning_color = "#FF6B6B"

        self.configure(bg=self.bg_color)

        # Налаштування стилю — спробувати сучасну тему, падати назад на 'clam'
        style = ttk.Style()
        # force a reliable theme for styling on Windows
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        # Make buttons use the accent color (avoid default gray)
        style.configure('TButton', font=('Segoe UI', 11), padding=8, background='#FFFFFF', foreground=self.text_color)
        style.configure('Accent.TButton', font=('Segoe UI', 12, 'bold'), padding=10, background=self.accent_color, foreground='white')
        style.map('Accent.TButton', background=[('active', '#005A9E')], foreground=[('active', 'white')])

        # Якщо нема іконки, спробуємо її згенерувати (Pillow потрібна)
        try:
            icon_path = Path(__file__).resolve().parent / "sm4_app_icon.ico"
            if not icon_path.exists():
                try:
                    from create_security_icon import generate_icon
                    generate_icon(str(icon_path))
                except Exception:
                    # не критично — продовжити без іконки
                    pass
            if icon_path.exists():
                try:
                    self.iconbitmap(str(icon_path))
                except Exception:
                    pass
        except Exception:
            pass

        self._build_ui()

    def _build_ui(self):
        """Побудова інтерфейсу."""
        # Головна рамка
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Верхня панель з назвою та кнопкою інформації
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 20))

        title = ttk.Label(
            header_frame,
            text="🔐 SM4 Encryption",
            font=("Segoe UI", 26, "bold"),
            foreground=self.accent_color
        )
        title.pack(side="left")

        info_btn = ttk.Button(
            header_frame,
            text="ℹ",
            width=3,
            command=self._show_about
        )
        info_btn.pack(side="right")

        # Сучасна структура: ліворуч панель управління, праворуч - контент
        paned = ttk.Panedwindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True)

        # Ліва панель з налаштуваннями (режим, операція, ползунки)
        sidebar = ttk.Frame(paned, width=260, style='Dark.TFrame', padding=12)
        paned.add(sidebar, weight=0)

        ttk.Label(sidebar, text="Режим роботи", font=("Segoe UI", 11, "bold"), style='Dark.TLabel').pack(anchor="w", pady=(0,6))
        self.mode_var = tk.StringVar(value="text")
        ttk.Radiobutton(sidebar, text="Текст (вікно)", variable=self.mode_var, value="text", command=self._update_mode).pack(anchor="w")
        ttk.Radiobutton(sidebar, text="Файли", variable=self.mode_var, value="file", command=self._update_mode).pack(anchor="w")

        ttk.Separator(sidebar).pack(fill="x", pady=8)

        ttk.Label(sidebar, text="Операція", font=("Segoe UI", 11, "bold"), style='Dark.TLabel').pack(anchor="w", pady=(0,6))
        self.op_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(sidebar, text="Шифрування", variable=self.op_var, value="encrypt", command=self._update_operation).pack(anchor="w")
        ttk.Radiobutton(sidebar, text="Розшифрування", variable=self.op_var, value="decrypt", command=self._update_operation).pack(anchor="w")

        ttk.Separator(sidebar).pack(fill="x", pady=8)
        ttk.Label(sidebar, text="Інтерфейс зафіксовано", font=("Segoe UI", 11, "bold"), style='Dark.TLabel').pack(anchor="w", pady=(0,6))
        ttk.Label(sidebar, text="Розмір та макет фіксовані для стабільного вигляду.", wraplength=220, style='Dark.TLabel').pack(anchor="w")
        ttk.Separator(sidebar).pack(fill="x", pady=8)

        ttk.Label(sidebar, text="Інтерактивність", font=("Segoe UI", 11, "bold"), style='Dark.TLabel').pack(anchor="w", pady=(0,6))
        ttk.Label(sidebar, text="Вибирайте режим та операцію — праворуч зміниться інтерфейс.", wraplength=220, style='Dark.TLabel').pack(anchor="w")

        # Права частина — контент
        content = ttk.Frame(paned, style='Dark.TFrame', padding=12)
        paned.add(content, weight=1)

        # Frames for file and text content (we reuse builders)
        self.content_file_frame = ttk.Frame(content, style='Dark.TFrame')
        self.content_file_frame.pack(fill="both", expand=True)
        # Use a small notebook inside content_file_frame to hold Encrypt/Decrypt file UIs
        inner_nb = ttk.Notebook(self.content_file_frame)
        inner_nb.pack(fill="both", expand=True)
        enc_parent = ttk.Frame(inner_nb, padding=8)
        dec_parent = ttk.Frame(inner_nb, padding=8)
        inner_nb.add(enc_parent, text="🔒 Зашифрувати файл")
        inner_nb.add(dec_parent, text="🔓 Розшифрувати файл")
        self._build_encrypt_tab(enc_parent)
        self._build_decrypt_tab(dec_parent)

        self.content_text_frame = ttk.Frame(content, style='Dark.TFrame')
        # do not pack now; will be packed when active
        self._build_text_tab(self.content_text_frame)

        # За замовчуванням показуємо текстовий режим або файл
        self._update_mode()

        # Підвал з авторством
        footer = ttk.Frame(main_frame, style='Dark.TFrame')
        footer.pack(side="bottom", fill="x", pady=(6,0))
        footer_lbl = ttk.Label(footer, text="by Roman Sadovskyi", font=("Segoe UI", 9), foreground="#909090", style='Dark.TLabel')
        footer_lbl.pack(pady=6)

    def _build_encrypt_tab(self, parent):
        """Побудова вкладки шифрування."""
        
        # Файл для шифрування
        ttk.Label(parent, text="📄 Файл для шифрування (TXT):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        enc_file_frame = ttk.Frame(parent)
        enc_file_frame.pack(fill="x", pady=(0, 15))
        
        self.enc_file_label = ttk.Label(enc_file_frame, text="Не обрано", foreground="#888888")
        self.enc_file_label.pack(side="left", fill="x", expand=True)
        
        ttk.Button(enc_file_frame, text="Обрати файл", command=self._browse_encrypt_file).pack(side="right", padx=(5, 0))

        # ===== КЛЮЧ: Три варіанти =====
        ttk.Label(parent, text="🔑 Ключ шифрування:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        key_frame = ttk.Frame(parent)
        key_frame.pack(fill="x", pady=(0, 15))
        
        ttk.Button(key_frame, text="Генерувати", command=self._generate_key_enc).pack(side="left", padx=(0, 5))
        ttk.Button(key_frame, text="Обрати файл", command=self._browse_encrypt_key).pack(side="left", padx=(0, 5))
        ttk.Button(key_frame, text="Ввести HEX", command=self._input_key_hex_enc).pack(side="left", padx=(0, 5))
        
        self.enc_key_display = ttk.Label(key_frame, text="Ключ не вибрано", foreground="#888888", font=("Segoe UI", 9))
        self.enc_key_display.pack(side="left", fill="x", expand=True)

        # Формат збереження
        ttk.Label(parent, text="💾 Формат збереження шифртексту:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        format_frame = ttk.Frame(parent)
        format_frame.pack(fill="x", pady=(0, 15))
        
        self.enc_format_var = tk.StringVar(value="hex")
        ttk.Radiobutton(format_frame, text="HEX (шістнадцятковий)", variable=self.enc_format_var, value="hex").pack(anchor="w")
        ttk.Radiobutton(format_frame, text="TXT (текстовий)", variable=self.enc_format_var, value="txt").pack(anchor="w")

        # Місце збереження (опціонально)
        ttk.Label(parent, text="📁 Місце збереження (опціонально):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        output_frame = ttk.Frame(parent)
        output_frame.pack(fill="x", pady=(0, 15))
        
        self.enc_output_label = ttk.Label(output_frame, text="Автоматично: [оригінальний файл]", foreground="#888888")
        self.enc_output_label.pack(side="left", fill="x", expand=True)
        
        ttk.Button(output_frame, text="Вказати місце", command=self._browse_encrypt_output).pack(side="right", padx=(5, 0))

        # Кнопка шифрування
        ttk.Button(
            parent,
            text="▶ Зашифрувати",
            command=self._encrypt_file,
            style="Accent.TButton"
        ).pack(fill="x", pady=(20, 0), ipady=10)

        # Зберігання даних
        self.enc_file = None
        self.enc_key = None  # Об'єкт bytes з ключем
        self.enc_output = None


    def _build_decrypt_tab(self, parent):
        """Побудова вкладки розшифрування."""
        
        # Файл для розшифрування
        ttk.Label(parent, text="📄 Файл для розшифрування (TXT):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        dec_file_frame = ttk.Frame(parent)
        dec_file_frame.pack(fill="x", pady=(0, 15))
        
        self.dec_file_label = ttk.Label(dec_file_frame, text="Не обрано", foreground="#888888")
        self.dec_file_label.pack(side="left", fill="x", expand=True)
        
        ttk.Button(dec_file_frame, text="Обрати файл", command=self._browse_decrypt_file).pack(side="right", padx=(5, 0))

        # ===== КЛЮЧ: Три варіанти =====
        ttk.Label(parent, text="🔑 Ключ розшифрування:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        key_frame = ttk.Frame(parent)
        key_frame.pack(fill="x", pady=(0, 15))
        
        ttk.Button(key_frame, text="Обрати файл", command=self._browse_decrypt_key).pack(side="left", padx=(0, 5))
        ttk.Button(key_frame, text="Ввести HEX", command=self._input_key_hex_dec).pack(side="left", padx=(0, 5))
        
        self.dec_key_display = ttk.Label(key_frame, text="Ключ не вибрано", foreground="#888888", font=("Segoe UI", 9))
        self.dec_key_display.pack(side="left", fill="x", expand=True)

        # Місце збереження (опціонально)
        ttk.Label(parent, text="📁 Місце збереження (опціонально):", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        output_frame = ttk.Frame(parent)
        output_frame.pack(fill="x", pady=(0, 15))
        
        self.dec_output_label = ttk.Label(output_frame, text="Автоматично: [оригінальний файл]", foreground="#888888")
        self.dec_output_label.pack(side="left", fill="x", expand=True)
        
        ttk.Button(output_frame, text="Вказати місце", command=self._browse_decrypt_output).pack(side="right", padx=(5, 0))

        # Кнопка розшифрування
        ttk.Button(
            parent,
            text="▶ Розшифрувати",
            command=self._decrypt_file,
            style="Accent.TButton"
        ).pack(fill="x", pady=(20, 0), ipady=10)

        # Зберігання даних
        self.dec_file = None
        self.dec_key = None  # Об'єкт bytes з ключем
        self.dec_output = None

    def _build_text_tab(self, parent):
        """Вкладка для шифрування/розшифрування тексту без файлів."""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Введіть або вставте текст нижче:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.text_input = tk.Text(frame, height=10, font=("Segoe UI", 11))
        self.text_input.pack(fill="both", expand=False, pady=(5, 10))

        key_row = ttk.Frame(frame)
        key_row.pack(fill="x", pady=(0, 10))
        ttk.Label(key_row, text="Ключ (16 байтів):", font=("Segoe UI", 10)).pack(side="left")
        self.textkey_entry = ttk.Entry(key_row, width=48, font=("Courier", 10))
        self.textkey_entry.pack(side="left", padx=(8, 0))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="🔒 Зашифрувати", command=self._encrypt_text).pack(side="left", padx=5)
        ttk.Button(btn_row, text="🔓 Розшифрувати", command=self._decrypt_text).pack(side="left", padx=5)
        ttk.Button(btn_row, text="Скопіювати результат", command=self._copy_text_result).pack(side="left", padx=5)

        ttk.Label(frame, text="Результат:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 0))
        self.text_output = tk.Text(frame, height=8, font=("Courier", 10))
        self.text_output.pack(fill="both", expand=True, pady=(5, 0))

        # internal
        self._last_text_result = None

    def _update_mode(self):
        """Показати відповідний контент залежно від режиму (text/file)."""
        mode = self.mode_var.get()
        if mode == "text":
            try:
                self.content_file_frame.forget()
            except Exception:
                pass
            self.content_text_frame.pack(fill="both", expand=True)
        else:
            try:
                self.content_text_frame.forget()
            except Exception:
                pass
            self.content_file_frame.pack(fill="both", expand=True)

    def _update_operation(self):
        """Adjust UI hints depending on operation (encrypt/decrypt)."""
        # Currently we don't need to change structure, but we could update labels or defaults.
        op = self.op_var.get()
        # Example: update main buttons' text if needed (not intrusive now)
        return

    def _on_font_change(self, *_):
        size = self.font_size_var.get()
        try:
            if hasattr(self, 'text_input') and self.text_input:
                self.text_input.config(font=("Segoe UI", int(size)))
            if hasattr(self, 'text_output') and self.text_output:
                self.text_output.config(font=("Courier", int(size)))
        except Exception:
            pass

    def _on_line_spacing_change(self, *_):
        spacing = self.line_spacing_var.get()
        try:
            if hasattr(self, 'text_input') and self.text_input:
                self.text_input.config(spacing3=spacing)
            if hasattr(self, 'text_output') and self.text_output:
                self.text_output.config(spacing3=spacing)
        except Exception:
            pass


    # ===== Обробники для шифрування =====

    def _browse_encrypt_file(self):
        """Обрати файл для шифрування (TXT)."""
        path = filedialog.askopenfilename(
            title="Обрати файл для шифрування",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.enc_file = path
            filename = Path(path).name
            self.enc_file_label.config(text=filename)

    def _browse_encrypt_key(self):
        """Обрати файл ключа."""
        path = filedialog.askopenfilename(
            title="Обрати файл ключа",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                self.enc_key = load_key_hex(path)
                self.enc_key_display.config(text=f"✅ {Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка ключа", str(e))
                self.enc_key = None

    def _input_key_hex_enc(self):
        """Ввести ключ у форматі HEX вручну."""
        dialog = tk.Toplevel(self)
        dialog.title("Ввести HEX ключ")
        dialog.geometry("400x150")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Введіть ключ у форматі HEX (16 байтів):", font=("Segoe UI", 10)).pack(pady=10)
        
        key_entry = ttk.Entry(dialog, font=("Courier", 10), width=40)
        key_entry.pack(pady=5, padx=20)
        key_entry.focus()
        
        def apply_key():
            hex_str = key_entry.get().strip()
            if not hex_str:
                messagebox.showwarning("Помилка", "Ключ не вказано")
                return
            
            try:
                self.enc_key = bytes.fromhex(hex_str)
                if len(self.enc_key) != 16:
                    raise ValueError("Ключ повинен бути 16 байтів (32 символи hex)")
                self.enc_key_display.config(text="✅ Ключ введено (HEX)")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Помилка", str(e))
        
        ttk.Button(dialog, text="OK", command=apply_key).pack(pady=10)

    def _generate_key_enc(self):
        """Генерація ключа для шифрування."""
        path = filedialog.asksaveasfilename(
            title="Зберегти ключ як",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            key = generate_key()
            try:
                save_key_hex(key, path)
                self.enc_key = key
                self.enc_key_display.config(text=f"✅ Ключ згенеровано і збережено")
                messagebox.showinfo("Успіх", f"Ключ збережено в:\n{Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося зберегти ключ:\n{e}")

    def _browse_encrypt_output(self):
        """Обрати місце збереження зашифрованого файлу."""
        path = filedialog.asksaveasfilename(
            title="Місце збереження зашифрованого файлу",
            defaultextension=".enc"
        )
        if path:
            self.enc_output = path
            filename = Path(path).name
            self.enc_output_label.config(text=filename)

    def _encrypt_file(self):
        """Шифрування файлу."""
        # Перевірка файлу
        if not self.enc_file:
            messagebox.showwarning("Помилка", "Виберіть файл для шифрування")
            return
        
        if not os.path.exists(self.enc_file):
            messagebox.showerror("Помилка", "Файл не знайдено")
            return

        if not self.enc_file.lower().endswith('.txt'):
            messagebox.showwarning("Помилка", "Файл повинен мати розширення .txt")
            return

        # Перевірка ключа
        if self.enc_key is None:
            messagebox.showwarning("Помилка", "Виберіть або створіть ключ")
            return

        # Читання файлу
        try:
            with open(self.enc_file, "r", encoding="utf-8") as f:
                data_str = f.read()
            data = data_str.encode("utf-8")
        except Exception as e:
            messagebox.showerror("Помилка читання файлу", str(e))
            return

        # Шифрування
        try:
            ciphertext = sm4_encrypt_ecb(data, self.enc_key)
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))
            return

        # Форматування результату
        format_type = self.enc_format_var.get()

        if format_type == "hex":
            # Зберігаємо сирі байти (без розширення за замовчуванням)
            result_data = ciphertext
            file_extension = ""  # без розширення
        else:  # txt - зберігаємо як текстовий файл із hex-рядком
            result_data = ciphertext.hex().encode("utf-8")
            file_extension = ".txt"

        # Визначення місця збереження
        if self.enc_output:
            output_path = self.enc_output
        else:
            base_path = Path(self.enc_file)
            # Якщо формат "hex" - знімемо розширення (без розширення)
            if file_extension == "":
                output_path = str(base_path.parent / f"{base_path.stem}")
            else:
                output_path = str(base_path.parent / f"{base_path.stem}{file_extension}")

        # Запис файлу
        try:
            with open(output_path, "wb") as f:
                f.write(result_data)
        except Exception as e:
            messagebox.showerror("Помилка запису файлу", str(e))
            return

        messagebox.showinfo(
            "Успіх",
            f"Файл зашифровано!\n\n"
            f"📁 {Path(output_path).name}\n"
            f"📊 Розмір: {len(result_data)} байт\n"
            f"🔐 Формат: {format_type.upper()}"
        )

    # ===== Обробники для розшифрування =====

    def _browse_decrypt_file(self):
        """Обрати зашифрований файл (підтримуються .txt (hex) або файл без розширення (raw))."""
        path = filedialog.askopenfilename(
            title="Обрати зашифрований файл",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.dec_file = path
            filename = Path(path).name
            self.dec_file_label.config(text=filename)

    def _browse_decrypt_key(self):
        """Обрати файл ключа."""
        path = filedialog.askopenfilename(
            title="Обрати файл ключа",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                self.dec_key = load_key_hex(path)
                self.dec_key_display.config(text=f"✅ {Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка ключа", str(e))
                self.dec_key = None

    def _input_key_hex_dec(self):
        """Ввести ключ у форматі HEX вручну."""
        dialog = tk.Toplevel(self)
        dialog.title("Ввести HEX ключ")
        dialog.geometry("400x150")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Введіть ключ у форматі HEX (16 байтів):", font=("Segoe UI", 10)).pack(pady=10)
        
        key_entry = ttk.Entry(dialog, font=("Courier", 10), width=40)
        key_entry.pack(pady=5, padx=20)
        key_entry.focus()
        
        def apply_key():
            hex_str = key_entry.get().strip()
            if not hex_str:
                messagebox.showwarning("Помилка", "Ключ не вказано")
                return
            
            try:
                self.dec_key = bytes.fromhex(hex_str)
                if len(self.dec_key) != 16:
                    raise ValueError("Ключ повинен бути 16 байтів (32 символи hex)")
                self.dec_key_display.config(text="✅ Ключ введено (HEX)")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Помилка", str(e))
        
        ttk.Button(dialog, text="OK", command=apply_key).pack(pady=10)

    def _browse_decrypt_output(self):
        """Обрати місце збереження розшифрованого файлу."""
        path = filedialog.asksaveasfilename(
            title="Місце збереження розшифрованого файлу",
            defaultextension=".txt"
        )
        if path:
            self.dec_output = path
            filename = Path(path).name
            self.dec_output_label.config(text=filename)

    def _decrypt_file(self):
        """Розшифрування файлу."""
        # Перевірка файлу
        if not self.dec_file:
            messagebox.showwarning("Помилка", "Виберіть файл для розшифрування")
            return
        
        if not os.path.exists(self.dec_file):
            messagebox.showerror("Помилка", "Файл не знайдено")
            return

        # Допускаємо або .txt (hex-рядок) або файл будь-якого формату (наприклад, без розширення) -
        # будемо пробувати розпізнати автоматично

        # Перевірка ключа
        if self.dec_key is None:
            messagebox.showwarning("Помилка", "Виберіть або введіть ключ")
            return

        # Читання файлу
        try:
            with open(self.dec_file, "r", encoding="utf-8") as f:
                file_content = f.read().strip()
        except Exception as e:
            messagebox.showerror("Помилка читання файлу", str(e))
            return

        # Спроба розпізнати формат (файл може містити hex-рядок у тексті або бути raw-бінаром)
        ciphertext = None
        # Якщо файл має розширення .txt, припускаємо що в ньому міститься hex-рядок
        if Path(self.dec_file).suffix.lower() == ".txt":
            try:
                ciphertext = bytes.fromhex(file_content)
            except ValueError as e:
                messagebox.showerror("Помилка", f"Файл .txt не містить коректного hex-рядка:\n{e}")
                return
        else:
            # Спробуємо прочитати як raw-бінар
            try:
                with open(self.dec_file, "rb") as f:
                    ciphertext = f.read()
            except Exception as e:
                # Якщо не вдалось, спробуємо взяти текст і перетворити з hex
                try:
                    ciphertext = bytes.fromhex(file_content)
                except Exception as e2:
                    messagebox.showerror("Помилка", f"Не вдалося прочитати файл як бінар або hex:\n{e2}")
                    return

        # Розшифрування
        try:
            plaintext = sm4_decrypt_ecb(ciphertext, self.dec_key)
        except ValueError as e:
            messagebox.showerror(
                "Помилка розшифрування",
                f"{e}\n\nПеревірте:\n"
                f"- Правильність ключа\n"
                f"- Формат файлу\n"
                f"- Цілісність файлу"
            )
            return
        except Exception as e:
            messagebox.showerror("Помилка розшифрування", str(e))
            return

        # Запис результату як TXT
        if self.dec_output:
            output_path = self.dec_output
        else:
            base_path = Path(self.dec_file)
            output_path = str(base_path.parent / f"{base_path.stem}.dec")

        try:
            # Зберігаємо як текст
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(plaintext.decode("utf-8", errors="replace"))
        except Exception as e:
            messagebox.showerror("Помилка запису файлу", str(e))
            return

        messagebox.showinfo(
            "Успіх",
            f"Файл розшифровано!\n\n"
            f"📁 {Path(output_path).name}\n"
            f"📊 Розмір: {len(plaintext)} байт"
        )

    def _show_about(self):
        """Показати вікно інформації."""
        AboutWindow(self)

    # ===== Текстові операції (прямо у вікні) =====
    def _encrypt_text(self):
        txt = self.text_input.get("1.0", "end-1c")
        if not txt:
            messagebox.showwarning("Помилка", "Введіть текст для шифрування.")
            return
        hexk = self.textkey_entry.get().strip()
        if not hexk:
            messagebox.showwarning("Помилка", "Введіть ключ у форматі HEX (32 символи).")
            return
        try:
            key = bytes.fromhex(hexk)
            if len(key) != 16:
                raise ValueError("Неправильна довжина ключа (очікується 16 байтів).")
        except Exception as e:
            messagebox.showerror("Помилка ключа", f"Некоректний HEX ключ:\n{e}")
            return

        try:
            ct = sm4_encrypt_ecb(txt.encode("utf-8"), key)
            res = ct.hex()
            self.text_output.config(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", res)
            self.text_output.config(state="normal")
            self._last_text_result = res
            messagebox.showinfo("Успіх", "Текст зашифровано.")
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))

    def _decrypt_text(self):
        hex_in = self.text_input.get("1.0", "end-1c").strip()
        if not hex_in:
            messagebox.showwarning("Помилка", "Введіть HEX шифртекст для розшифрування.")
            return
        hexk = self.textkey_entry.get().strip()
        if not hexk:
            messagebox.showwarning("Помилка", "Введіть ключ у форматі HEX (32 символи).")
            return
        try:
            key = bytes.fromhex(hexk)
            if len(key) != 16:
                raise ValueError("Неправильна довжина ключа (очікується 16 байтів).")
            ct = bytes.fromhex(hex_in)
        except Exception as e:
            messagebox.showerror("Помилка", f"Некоректні вхідні дані:\n{e}")
            return

        try:
            pt = sm4_decrypt_ecb(ct, key)
            res = pt.decode("utf-8", errors="replace")
            self.text_output.config(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", res)
            self.text_output.config(state="normal")
            self._last_text_result = res
            messagebox.showinfo("Успіх", "Текст розшифровано.")
        except Exception as e:
            messagebox.showerror("Помилка розшифрування", str(e))

    def _copy_text_result(self):
        if not self._last_text_result:
            messagebox.showwarning("Помилка", "Немає результату для копіювання.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(self._last_text_result)
            messagebox.showinfo("Успіх", "Результат скопійовано в буфер обміну.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося скопіювати: {e}")

# ===================== ТОЧКА ВХОДУ =====================

def main():
    app = SM4App()
    app.mainloop()

if __name__ == "__main__":
    main()

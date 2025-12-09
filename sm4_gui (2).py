#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sm4_app_final.py

SM4 Encryption/Decryption Utility with CustomTkinter UI.
Режими: робота з текстом та шифрування/розшифрування файлів (ECB + PKCS#7).
"""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk

import customtkinter as ctk
from customtkinter import (
    CTkLabel,
    CTkButton,
    CTkEntry,
    CTkTextbox,
    CTkFrame,
    CTkSegmentedButton,
    CTkScrollableFrame,
)

from sm4_core import (
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    generate_key,
    load_key_hex,
)

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


def create_tooltip(widget, text: str):
    """Простий тултіп при наведенні миші."""
    tooltip_window = [None]

    def on_enter(event):
        if tooltip_window[0] is None:
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            label = CTkLabel(
                tooltip,
                text=text,
                text_color="white",
                fg_color="#333333",
                corner_radius=4,
                padx=8,
                pady=4,
                font=("Segoe UI", 9),
            )
            label.pack()
            tooltip_window[0] = tooltip

    def on_leave(event):
        if tooltip_window[0] is not None:
            tooltip_window[0].destroy()
            tooltip_window[0] = None

    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)


class SM4App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("🔐 SM4 Encryption")
        self.geometry("1000x650")
        self.minsize(800, 550)

        # Colors
        self.accent_color = "#0078D4"
        self.bg_color = "#F5F5F5"
        self.text_color = "#1F1F1F"
        self.info_color = "#E8F4F8"
        self.success_color = "#27AE60"
        self.warning_color = "#FF9800"

        self.enc_file: Path | None = None
        self.enc_key: bytes | None = None
        self.show_text_info = False
        self.show_file_info = False
        self.show_prog_info_text = False
        self.show_prog_info_file = False

        self._build_ui()

    # ============================ БАЗОВИЙ ІНТЕРФЕЙС ============================

    def _build_ui(self) -> None:
        main = CTkFrame(self, fg_color=self.bg_color)
        main.pack(fill="both", expand=True, padx=20, pady=20)

        # ----- HEADER -----
        header = CTkFrame(main, fg_color=self.bg_color)
        header.pack(fill="x", pady=(0, 15))

        title_frame = CTkFrame(header, fg_color=self.bg_color)
        title_frame.pack(side="left", fill="x", expand=True)

        title = CTkLabel(
            title_frame,
            text="🔐 SM4 Encryption/Decryption Utility",
            font=("Segoe UI", 28, "bold"),
            text_color=self.text_color,
        )
        title.pack(anchor="w")

        subtitle = CTkLabel(
            title_frame,
            text="Безпечне шифрування текстів та файлів за стандартом SM4 ",
            font=("Segoe UI", 11, "bold"),
            text_color="#555555",
        )
        subtitle.pack(anchor="w", pady=(4, 0))

        # Перемикач режимів
        self.mode_var = ctk.StringVar(value="📁 Файли")
        segmented = CTkSegmentedButton(
            header,
            values=["📝 Текст", "📁 Файли"],
            variable=self.mode_var,
            command=self._on_mode_change,
            font=("Segoe UI", 12, "bold"),
        )
        segmented.pack(side="right")

        # Контент з прокруткою
        self.content = CTkScrollableFrame(main, fg_color=self.bg_color)
        self.content.pack(fill="both", expand=True)

        self.text_frame = CTkFrame(self.content, fg_color=self.bg_color)
        self.file_frame = CTkFrame(self.content, fg_color=self.bg_color)

        self._build_text_tab()
        self._build_file_tab()
        self._on_mode_change()

        # ----- FOOTER -----
        footer = CTkFrame(main, fg_color=self.bg_color, height=30)
        footer.pack(fill="x", pady=(10, 0), side="bottom")

        footer_label = CTkLabel(
            footer,
            text="© 2025 by Roman Sadovskyi  •  SM4 ECB Mode Utility",
            font=("Segoe UI", 12),
            text_color="#999999",
        )
        footer_label.pack(anchor="center", padx=5, pady=2)

    def _on_mode_change(self, value=None):
        for w in self.content.winfo_children():
            w.pack_forget()
        if self.mode_var.get() == "📝 Текст":
            self.text_frame.pack(fill="both", expand=True)
        else:
            self.file_frame.pack(fill="both", expand=True)

    # ============================ ТАБ «ТЕКСТ» ============================

    def _build_text_tab(self):
        f = self.text_frame

        # --- Блок "Про програму" ---
        prog_btn_frame = CTkFrame(f, fg_color=self.bg_color)
        prog_btn_frame.pack(fill="x", pady=(0, 8))

        def toggle_prog_info():
            if self.show_prog_info_text:
                self.prog_info_box_text.pack_forget()
                prog_info_btn.configure(text="▶ Про програму")
                self.show_prog_info_text = False
            else:
                self.prog_info_box_text.pack(fill="x", pady=(0, 12), before=info_btn_frame)
                prog_info_btn.configure(text="▼ Про програму")
                self.show_prog_info_text = True

        prog_info_btn = CTkButton(
            prog_btn_frame,
            text="▶ Про програму",
            command=toggle_prog_info,
            fg_color="#FFB74D",
            hover_color="#FF9800",
            font=("Segoe UI", 12, "bold"),
            height=36,
        )
        prog_info_btn.pack(anchor="w")

        self.prog_info_box_text = CTkFrame(f, fg_color="#FFE8D6", corner_radius=8)

        prog_title = CTkLabel(
            self.prog_info_box_text,
            text="ℹ️ Про програму",
            font=("Segoe UI", 13, "bold"),
            text_color="#E65100",
        )
        prog_title.pack(anchor="w", padx=12, pady=(10, 4))

        prog_text = CTkLabel(
            self.prog_info_box_text,
            text=(
                "📋 SM4 — китайський державний стандарт симетричного блочного шифрування.\n"
                "   Офіційна назва: GB/T 32907-2016 (SMS4 / 国密SM4).\n"
                "   Розроблена як альтернатива AES для китайських державних установ.\n\n"
                "📑 Основні характеристики алгоритму:\n"
                "  • Довжина ключа: 128 біт (16 байтів, 32 HEX-символи)\n"
                "  • Розмір блоку: 128 біт (16 байтів)\n"
                "  • Кількість раундів: 32\n"
                "  • Функція: вузька с-скринька (S-Box) 8×8 з чотирма нелінійними трансформаціями\n\n"
                "🔄 Режим роботи (ECB — Electronic CodeBook):\n"
                "  • Кожен 16-байтовий блок шифрується НЕЗАЛЕЖНО одним і тим же ключем\n"
                "  • Простий, але менш безпечний для великих даних (ідентичні блоки → ідентичні шифртексти)\n"
                "  • Дані доповнюються PKCS#7: добавляється N байтів значення N\n\n"
                "🛠️ Як користуватися цією утилітою:\n"
                "  1) Режим Текст: введіть текст, генеруйте/введіть ключ, натисніть 'Зашифрувати'\n"
                "  2) Режим Файли: оберіть файл, встановіть ключ, зашифруйте (результат з розширенням .txt)\n"
                "  3) Для розшифрування повторіть процес з 'Розшифрувати' кнопкою та HEX-текстом\n\n"
                "⚠️ ВАЖЛИВО! Рекомендації щодо безпеки:\n"
                "  • Ключі повинні бути ВИПАДКОВИМИ (не передбачуваними)\n"
                "  • Без правильного ключа неможливо відновити оригінальні дані\n"
                "  • ECB режим НЕ рекомендується для комерційних сторінок (див. ECB penguin)\n"
                "  • Для особливо критичних даних використовуйте режим CBC або CTR\n"
                "  • Зберігайте ключі в безпечному місці, окремо від зашифрованих даних\n"
                "  • Регулярно перевіряйте цілісність шифртекстів (рекомендується HMAC)"
            ),
            font=("Segoe UI", 12),
            text_color="#E65100",
            justify="left",
        )
        prog_text.pack(anchor="w", padx=12, pady=(0, 10))

        # --- Блок «Як це працює?» ---
        info_btn_frame = CTkFrame(f, fg_color=self.bg_color)
        info_btn_frame.pack(fill="x", pady=(0, 8))

        def toggle_text_info():
            self.show_text_info = not self.show_text_info
            if self.show_text_info:
                self.text_info_box.pack(fill="x", pady=(0, 12), before=self.text_input_frame)
                toggle_btn.configure(text="▼ Як це працює?")
            else:
                self.text_info_box.pack_forget()
           

                toggle_btn.configure(text="▶ Як це працює?")

        toggle_btn = CTkButton(
            info_btn_frame,
            text="▶ Як це працює?",
            command=toggle_text_info,
            fg_color="#9E9E9E",
            hover_color="#757575",
            font=("Segoe UI", 12, "bold"),
            height=32,
        )
        toggle_btn.pack(anchor="w")

        self.text_info_box = CTkFrame(f, fg_color=self.info_color, corner_radius=8)

        info_title = CTkLabel(
            self.text_info_box,
            text="ℹ️ Як користуватися режимом «Текст»",
            font=("Segoe UI", 14, "bold"),
            text_color=self.text_color,
        )
        info_title.pack(anchor="w", padx=12, pady=(10, 4))

        info_text = CTkLabel(
            self.text_info_box,
            text=(
                "① Введіть або вставте текст у поле «Вхідний текст».\n\n"
                "② Задайте ключ: введіть 32 HEX-символи АБО натисніть «Згенерувати новий ключ».\n\n"
                "③ Натисніть «Зашифрувати» — у нижньому полі з'явиться шифртекст у HEX-форматі.\n\n"
                "④ Для розшифрування вставте шифртекст у поле «Вхідний текст»,\n"
                "   вкажіть той самий ключ і натисніть «Розшифрувати».\n\n"
                "⑤ Режим ECB шифрує кожен блок по 16 байтів незалежно."
            ),
            font=("Segoe UI", 11, "bold"),
            text_color=self.text_color,
            justify="left",
        )
        info_text.pack(anchor="w", padx=12, pady=(0, 10))

        # --- Вхідний текст ---
        self.text_input_frame = CTkFrame(f, fg_color=self.bg_color)
        self.text_input_frame.pack(fill="both", expand=True)

        in_sec = CTkFrame(
            self.text_input_frame,
            fg_color="white",
            border_width=1,
            border_color="#D0D0D0",
            corner_radius=8,
        )
        in_sec.pack(fill="x", pady=(0, 10))

        in_header = CTkFrame(in_sec, fg_color="white")
        in_header.pack(fill="x", padx=12, pady=(10, 0))

        in_lbl = CTkLabel(in_header, text="📝 Вхідний текст", font=("Segoe UI", 15, "bold"))
        in_lbl.pack(side="left")

        q_mark = CTkLabel(in_header, text="❓", font=("Segoe UI", 14))
        q_mark.pack(side="left", padx=(6, 0))
        create_tooltip(q_mark, "Вводьте будь-який текст. Довжина не обмежена.")

        paste_btn = CTkButton(
            in_header,
            text="📋 Вставити",
            command=self._paste_to_text,
            fg_color="#F3F3F3",
            hover_color="#E0E0E0",
            height=30,
            width=90,
            font=("Segoe UI", 11, "bold"),
        )
        paste_btn.pack(side="right")
        create_tooltip(paste_btn, "Вставити текст із буфера обміну (Ctrl+V).")

        self.text_input = CTkTextbox(in_sec, height=130, font=("Segoe UI", 13))
        self.text_input.pack(fill="both", padx=12, pady=(6, 12))

        # --- Ключ ---
        key_sec = CTkFrame(
            self.text_input_frame,
            fg_color="white",
            border_width=1,
            border_color="#D0D0D0",
            corner_radius=8,
        )
        key_sec.pack(fill="x", pady=(0, 10))

        key_header = CTkFrame(key_sec, fg_color="white")
        key_header.pack(fill="x", padx=12, pady=(10, 0))

        key_lbl = CTkLabel(
            key_header, text="🔑 Ключ шифрування", font=("Segoe UI", 15, "bold")
        )
        key_lbl.pack(side="left")

        key_q = CTkLabel(key_header, text="❓", font=("Segoe UI", 14))
        key_q.pack(side="left", padx=(6, 0))
        create_tooltip(
            key_q,
            "Ключ має містити рівно 32 HEX-символи (0–9, a–f).\n"
            "Приклад: 0123456789abcdef0123456789abcdef.\n"
            "Натисніть «Згенерувати» для випадкового ключа.",
        )

        paste_key_btn = CTkButton(
            key_header,
            text="📋 Вставити ключ",
            command=self._paste_to_key,
            fg_color="#F3F3F3",
            hover_color="#E0E0E0",
            height=30,
            width=130,
            font=("Segoe UI", 11, "bold"),
        )
        paste_key_btn.pack(side="right")
        create_tooltip(paste_key_btn, "Вставити ключ із буфера обміну (Ctrl+V).")

        self.text_key = CTkEntry(
            key_sec,
            placeholder_text="Введіть або згенеруйте ключ (32 HEX)",
            font=("Courier New", 13, "bold"),
        )
        self.text_key.pack(fill="x", padx=12, pady=(6, 12))

        # Прив'язки Ctrl+V та контекстного меню
        self.text_input.bind("<Control-v>", self._paste_to_text)
        self.text_input.bind("<Control-V>", self._paste_to_text)
        self.text_input.bind("<Button-3>", self._show_text_context_menu)

        self.text_key.bind("<Control-v>", self._paste_to_key)
        self.text_key.bind("<Control-V>", self._paste_to_key)
        self.text_key.bind("<Button-3>", self._show_key_context_menu)

        # --- Кнопки ---
        btn_frame = CTkFrame(self.text_input_frame, fg_color=self.bg_color)
        btn_frame.pack(fill="x", pady=(0, 10))

        gen_btn = CTkButton(
            btn_frame,
            text="🎲 Згенерувати новий ключ",
            command=self._gen_key_text,
            fg_color=self.warning_color,
            hover_color="#E68900",
            font=("Segoe UI", 12, "bold"),
            height=40,
        )
        gen_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(gen_btn, "Створити випадковий 128-бітний ключ.")

        enc_btn = CTkButton(
            btn_frame,
            text="🔒 Зашифрувати",
            command=self._encrypt_text,
            fg_color=self.accent_color,
            hover_color="#005A9E",
            font=("Segoe UI", 12, "bold"),
            height=40,
        )
        enc_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(enc_btn, "Зашифрувати текст за алгоритмом SM4 (ECB).")

        dec_btn = CTkButton(
            btn_frame,
            text="🔓 Розшифрувати",
            command=self._decrypt_text,
            fg_color=self.success_color,
            hover_color="#1F8449",
            font=("Segoe UI", 12, "bold"),
            height=40,
        )
        dec_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(dec_btn, "Розшифрувати HEX-шифртекст у початковий текст.")

        # --- Результат ---
        out_sec = CTkFrame(
            self.text_input_frame,
            fg_color="white",
            border_width=1,
            border_color="#D0D0D0",
            corner_radius=8,
        )
        out_sec.pack(fill="both", expand=True)

        out_header = CTkFrame(out_sec, fg_color="white")
        out_header.pack(fill="x", padx=12, pady=(10, 0))

        out_lbl = CTkLabel(
            out_header,
            text="📤 Результат",
            font=("Segoe UI", 15, "bold"),
        )
        out_lbl.pack(side="left")

        out_q = CTkLabel(out_header, text="❓", font=("Segoe UI", 14))
        out_q.pack(side="left", padx=(6, 0))
        create_tooltip(
            out_q,
            "У цьому полі показується результат операції.\n"
            "• Після шифрування — шифртекст у HEX.\n"
            "• Після розшифрування — відновлений текст.",
        )

        copy_info = CTkLabel(
            out_header,
            text="(Ctrl+A – виділити все, Ctrl+C – скопіювати)",
            font=("Segoe UI", 10, "bold"),
            text_color="#999999",
        )
        copy_info.pack(side="right")

        self.text_output = CTkTextbox(out_sec, height=160, font=("Courier New", 13))
        self.text_output.pack(fill="both", padx=12, pady=(6, 12))
        self.text_output.configure(state="disabled")

    # ---------- Допоміжні обробники для вставки та контекстного меню ----------

    def _paste_to_text(self, event=None):
        """Вставка з буфера обміну у поле вхідного тексту."""
        try:
            txt = self.clipboard_get()
        except tk.TclError:
            messagebox.showwarning(
                "Буфер обміну порожній",
                "Спочатку скопіюйте текст (Ctrl+C), а потім спробуйте вставити ще раз.",
            )
            return "break"
        if not txt:
            messagebox.showwarning(
                "Буфер обміну порожній",
                "Буфер обміну не містить тексту.",
            )
            return "break"
        self.text_input.insert("insert", txt)
        return "break"

    def _paste_to_key(self, event=None):
        """Вставка з буфера обміну у поле ключа."""
        try:
            txt = self.clipboard_get()
        except tk.TclError:
            messagebox.showwarning(
                "Буфер обміну порожній",
                "Скопіюйте ключ (Ctrl+C), а потім вставте його (Ctrl+V) у поле.",
            )
            return "break"
        if not txt:
            messagebox.showwarning(
                "Буфер обміну порожній",
                "Буфер обміну не містить тексту ключа.",
            )
            return "break"
        # замінюємо вміст поля ключа вставленим текстом
        self.text_key.delete(0, tk.END)
        self.text_key.insert(0, txt.strip())
        return "break"

    def _show_text_context_menu(self, event=None):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Вставити", command=self._paste_to_text)
        menu.add_command(
            label="Копіювати",
            command=lambda: self.text_input.event_generate("<<Copy>>"),
        )
        menu.add_command(
            label="Вирізати",
            command=lambda: self.text_input.event_generate("<<Cut>>"),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_key_context_menu(self, event=None):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Вставити", command=self._paste_to_key)
        menu.add_command(
            label="Копіювати",
            command=lambda: self.text_key.event_generate("<<Copy>>"),
        )
        menu.add_command(
            label="Вирізати",
            command=lambda: self.text_key.event_generate("<<Cut>>"),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ============================ ЛОГІКА РЕЖИМУ «ТЕКСТ» ============================

    def _gen_key_text(self):
        try:
            k = generate_key()
            self.text_key.delete(0, "end")
            self.text_key.insert(0, k.hex())
            messagebox.showinfo(
                "Ключ згенеровано",
                "Новий випадковий 128-бітний ключ успішно згенеровано\n"
                "та вставлено у поле ключа.",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка генерації ключа",
                f"Під час генерації ключа сталася помилка:\n{e}",
            )

    def _encrypt_text(self):
        txt = self.text_input.get("1.0", "end").strip()
        if not txt:
            messagebox.showwarning(
                "Немає даних",
                "Введіть або вставте текст, який потрібно зашифрувати.",
            )
            return

        k = self.text_key.get().strip()
        if not k:
            messagebox.showwarning(
                "Ключ не задано",
                "Введіть ключ (32 HEX-символи) або натисніть «Згенерувати новий ключ».",
            )
            return

        try:
            key = bytes.fromhex(k)
        except ValueError:
            messagebox.showerror(
                "Некоректний формат ключа",
                "Ключ містить недопустимі символи.\n"
                "Дозволені тільки цифри 0–9 та літери a–f (A–F), без пробілів.",
            )
            return

        if len(key) != 16:
            messagebox.showerror(
                "Некоректна довжина ключа",
                f"Отримано {len(key)} байтів ключа.\n"
                "Для SM4 потрібен ключ рівно 16 байтів (32 HEX-символи).",
            )
            return

        try:
            ct = sm4_encrypt_ecb(txt.encode("utf-8"), key)
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", ct.hex())
            self.text_output.configure(state="disabled")
            messagebox.showinfo(
                "Шифрування виконано",
                f"Текст успішно зашифровано.\n"
                f"Довжина шифртексту у HEX: {len(ct.hex())} символів.",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка шифрування",
                f"Під час шифрування сталася помилка:\n{e}",
            )

    def _decrypt_text(self):
        hex_in = self.text_input.get("1.0", "end").strip()
        if not hex_in:
            messagebox.showwarning(
                "Немає даних",
                "Вставте або введіть HEX-шифртекст, який потрібно розшифрувати.",
            )
            return

        k = self.text_key.get().strip()
        if not k:
            messagebox.showwarning(
                "Ключ не задано",
                "Введіть ключ (32 HEX-символи), який використовувався при шифруванні.",
            )
            return

        try:
            key = bytes.fromhex(k)
        except ValueError:
            messagebox.showerror(
                "Некоректний формат ключа",
                "Ключ містить недопустимі символи.\n"
                "Перевірте, що у ключі тільки 0–9 та a–f, без пробілів.",
            )
            return

        if len(key) != 16:
            messagebox.showerror(
                "Некоректна довжина ключа",
                f"Отримано {len(key)} байтів ключа.\n"
                "Для SM4 потрібен ключ рівно 16 байтів (32 HEX-символи).",
            )
            return

        try:
            ct = bytes.fromhex(hex_in)
        except ValueError:
            messagebox.showerror(
                "Некоректний HEX-шифртекст",
                "Поле «Вхідний текст» має містити тільки HEX-символи (0–9, a–f), без пробілів.\n"
                "Скопіюйте шифртекст з поля результату шифрування без змін.",
            )
            return

        try:
            pt = sm4_decrypt_ecb(ct, key)
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            # показуємо як UTF-8, некоректні байти замінюємо символом �
            self.text_output.insert("1.0", pt.decode("utf-8", errors="replace"))
            self.text_output.configure(state="disabled")
            messagebox.showinfo(
                "Розшифрування виконано",
                "Шифртекст успішно розшифровано.",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка розшифрування",
                "Не вдалося розшифрувати текст.\n\n"
                "Можливі причини:\n"
                " • використано неправильний ключ;\n"
                " • шифртекст пошкоджений або обрізаний;\n"
                " • дані були зашифровані іншим алгоритмом чи режимом.\n\n"
                f"Технічна інформація:\n{e}",
            )

    # ============================ ТАБ «ФАЙЛИ» ============================

    def _build_file_tab(self):
        f = self.file_frame

        # Блок «Про програму»
        prog_btn_frame = CTkFrame(f, fg_color=self.bg_color)
        prog_btn_frame.pack(fill="x", pady=(0, 8))

        def toggle_prog_info():
            if self.show_prog_info_file:
                self.prog_info_box_file.pack_forget()
                prog_info_btn.configure(text="▶ Про програму")
                self.show_prog_info_file = False
            else:
                self.prog_info_box_file.pack(fill="x", pady=(0, 12), before=info_btn_frame)
                prog_info_btn.configure(text="▼ Про програму")
                self.show_prog_info_file = True

        prog_info_btn = CTkButton(
            prog_btn_frame,
            text="▶ Про програму",
            command=toggle_prog_info,
            fg_color="#FFB74D",
            hover_color="#FF9800",
            font=("Segoe UI", 12, "bold"),
            height=36,
        )
        prog_info_btn.pack(anchor="w")

        self.prog_info_box_file = CTkFrame(f, fg_color="#FFE8D6", corner_radius=8)

        prog_title = CTkLabel(
            self.prog_info_box_file,
            text="ℹ️ Про програму",
            font=("Segoe UI", 13, "bold"),
            text_color="#E65100",
        )
        prog_title.pack(anchor="w", padx=12, pady=(10, 4))

        prog_text = CTkLabel(
            self.prog_info_box_file,
            text=(
                "📋 SM4 — китайський державний стандарт симетричного блочного шифрування.\n"
                "   Офіційна назва: GB/T 32907-2016 (SMS4 / 国密SM4).\n"
                "   Розроблена як альтернатива AES для китайських державних установ.\n\n"
                "📑 Основні характеристики алгоритму:\n"
                "  • Довжина ключа: 128 біт (16 байтів, 32 HEX-символи)\n"
                "  • Розмір блоку: 128 біт (16 байтів)\n"
                "  • Кількість раундів: 32\n"
                "  • Функція: вузька с-скринька (S-Box) 8×8 з чотирма нелінійними трансформаціями\n\n"
                "🔄 Режим роботи (ECB — Electronic CodeBook):\n"
                "  • Кожен 16-байтовий блок файлу шифрується НЕЗАЛЕЖНО одним і тим же ключем\n"
                "  • Простий для файлів будь-якого розміру (автоматичне доповнення PKCS#7)\n"
                "  • Менш безпечний для великих однотипних блоків (ідентичні блоки → ідентичні шифртексти)\n\n"
                "🛠️ Як користуватися режимом «Файли»:\n"
                "  1) Оберіть файл для шифрування (будь-який тип: .txt, .pdf, .jpg, .zip, тощо)\n"
                "  2) Генеруйте/завантажте 128-бітний ключ (32 HEX-символи)\n"
                "  3) Натисніть 'Зашифрувати файл' — результат збережеться як FILENAME.EXTENSION.txt\n"
                "  4) Для розшифрування оберіть .txt-файл та використайте той же ключ\n\n"
                "⚠️ ВАЖЛИВО! Рекомендації щодо безпеки:\n"
                "  • Ключі повинні бути ВИПАДКОВИМИ (генеруйте програмою!)\n"
                "  • Без правильного ключа неможливо відновити оригінальні дані\n"
                "  • ECB режим НЕ рекомендується для великих файлів (див. ECB penguin)\n"
                "  • Зберігайте ключі в безпечному місці, окремо від зашифрованих файлів\n"
                "  • Перевіряйте ім'я та розмір файлу перед розшифруванням"
            ),
            font=("Segoe UI", 12),
            text_color="#E65100",
            justify="left",
        )
        prog_text.pack(anchor="w", padx=12, pady=(0, 10))

        # Блок «Як це працює?»
        info_btn_frame = CTkFrame(f, fg_color=self.bg_color)
        info_btn_frame.pack(fill="x", pady=(0, 8))

        def toggle_file_info():
            self.show_file_info = not self.show_file_info
            if self.show_file_info:
                self.file_info_box.pack(fill="x", pady=(0, 12), before=self.file_content_frame)
                toggle_btn.configure(text="▼ Як це працює?")
            else:
                self.file_info_box.pack_forget()
                toggle_btn.configure(text="▶ Як це працює?")

        toggle_btn = CTkButton(
            info_btn_frame,
            text="▶ Як це працює?",
            command=toggle_file_info,
            fg_color="#9E9E9E",
            hover_color="#757575",
            font=("Segoe UI", 12, "bold"),
            height=32,
        )
        toggle_btn.pack(anchor="w")

        self.file_info_box = CTkFrame(f, fg_color=self.info_color, corner_radius=8)

        info_title = CTkLabel(
            self.file_info_box,
            text="ℹ️ Як користуватися режимом «Файли»",
            font=("Segoe UI", 14, "bold"),
            text_color=self.text_color,
        )
        info_title.pack(anchor="w", padx=12, pady=(10, 4))

        info_text = CTkLabel(
            self.file_info_box,
            text=(
                "① Оберіть файл для шифрування (будь-який тип).\n\n"
                "② Задайте ключ: згенеруйте новий або завантажте з файлу (HEX).\n\n"
                "③ Натисніть «Зашифрувати файл» — результуючий файл буде\n"
                "   записаний поруч з оригінальним і матиме розширення .txt.\n\n"
                "④ Для розшифрування оберіть зашифрований .txt-файл,\n"
                "   переконайтеся, що використовується той самий ключ,\n"
                "   і натисніть «Розшифрувати файл». Відновлений файл буде\n"
                "   записано поруч без розширення .txt.\n\n"
                "⚠️ Якщо ключ буде іншим, файл не вдасться коректно розшифрувати."
            ),
            font=("Segoe UI", 11, "bold"),
            text_color=self.text_color,
            justify="left",
        )
        info_text.pack(anchor="w", padx=12, pady=(0, 10))

        # Основний контент
        self.file_content_frame = CTkFrame(f, fg_color=self.bg_color)
        self.file_content_frame.pack(fill="both", expand=True)

        # Вибір файлу
        file_frame = CTkFrame(
            self.file_content_frame,
            fg_color="white",
            border_width=1,
            border_color="#D0D0D0",
            corner_radius=8,
        )
        file_frame.pack(fill="x", pady=(0, 10))

        file_header = CTkFrame(file_frame, fg_color="white")
        file_header.pack(fill="x", padx=12, pady=(10, 0))

        file_lbl = CTkLabel(
            file_header, text="📁 Вибір файлу", font=("Segoe UI", 15, "bold")
        )
        file_lbl.pack(side="left")

        file_q = CTkLabel(file_header, text="❓", font=("Segoe UI", 14))
        file_q.pack(side="left", padx=(6, 0))
        create_tooltip(file_q, "Виберіть файл, який потрібно зашифрувати або розшифрувати.")

        self.file_label = CTkLabel(
            file_frame,
            text="📎 Файл не обрано",
            text_color="#888888",
            font=("Segoe UI", 13, "bold"),
        )
        self.file_label.pack(side="left", padx=12, pady=10, fill="x", expand=True)

        browse_btn = CTkButton(
            file_frame,
            text="📂 Обрати файл",
            command=self._browse_file,
            fg_color=self.accent_color,
            hover_color="#005A9E",
            font=("Segoe UI", 11, "bold"),
            height=40,
        )
        browse_btn.pack(side="right", padx=12, pady=10)
        create_tooltip(browse_btn, "Відкрити діалог вибору файлу.")

        # Управління ключем
        key_frame = CTkFrame(
            self.file_content_frame,
            fg_color="white",
            border_width=1,
            border_color="#D0D0D0",
            corner_radius=8,
        )
        key_frame.pack(fill="x", pady=(0, 10))

        key_header = CTkFrame(key_frame, fg_color="white")
        key_header.pack(fill="x", padx=12, pady=(10, 0))

        key_lbl = CTkLabel(
            key_header, text="🔑 Управління ключем", font=("Segoe UI", 15, "bold")
        )
        key_lbl.pack(side="left")

        key_q = CTkLabel(key_header, text="❓", font=("Segoe UI", 14))
        key_q.pack(side="left", padx=(6, 0))
        create_tooltip(
            key_q,
            "Згенеруйте новий ключ або завантажте існуючий з файлу (32 HEX-символи).",
        )

        key_btn_frame = CTkFrame(key_frame, fg_color="white")
        key_btn_frame.pack(fill="x", padx=12, pady=(6, 0))

        gen_btn = CTkButton(
            key_btn_frame,
            text="🎲 Згенерувати ключ",
            command=self._gen_key,
            fg_color=self.warning_color,
            hover_color="#E68900",
            font=("Segoe UI", 11, "bold"),
            height=40,
        )
        gen_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(gen_btn, "Створити новий випадковий 128-бітний ключ.")

        load_btn = CTkButton(
            key_btn_frame,
            text="📥 Завантажити ключ",
            command=self._load_key,
            fg_color="#9C27B0",
            hover_color="#7B1FA2",
            font=("Segoe UI", 11, "bold"),
            height=40,
        )
        load_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(load_btn, "Завантажити ключ з текстового файлу в HEX-форматі.")

        key_label_frame = CTkFrame(key_frame, fg_color="white")
        key_label_frame.pack(fill="x", padx=12, pady=(6, 12))

        self.key_label = CTkLabel(
            key_label_frame,
            text="🔑 Ключ не обрано",
            text_color="#888888",
            font=("Segoe UI", 12, "bold"),
        )
        self.key_label.pack(side="left", fill="x", expand=True)

        # Кнопки дій
        action_frame = CTkFrame(self.file_content_frame, fg_color=self.bg_color)
        action_frame.pack(fill="both", expand=True)

        enc_btn = CTkButton(
            action_frame,
            text="🔒 Зашифрувати файл",
            command=self._encrypt_file,
            fg_color=self.accent_color,
            hover_color="#005A9E",
            font=("Segoe UI", 12, "bold"),
            height=48,
        )
        enc_btn.pack(fill="x", pady=(0, 8))
        create_tooltip(enc_btn, "Зашифрувати обраний файл з використанням поточного ключа.")

        dec_btn = CTkButton(
            action_frame,
            text="🔓 Розшифрувати файл",
            command=self._decrypt_file,
            fg_color=self.success_color,
            hover_color="#1F8449",
            font=("Segoe UI", 12, "bold"),
            height=48,
        )
        dec_btn.pack(fill="x")
        create_tooltip(dec_btn, "Розшифрувати раніше зашифрований файл (.txt).")

    # ---------- Логіка для файлів ----------

    def _browse_file(self):
        p = filedialog.askopenfilename(
            title="Виберіть файл для шифрування / розшифрування",
            filetypes=[("Усі файли", "*.*")],
        )
        if not p:
            return
        self.enc_file = Path(p)
        self.file_label.configure(text=f"📎 {self.enc_file.name}")
        messagebox.showinfo(
            "Файл обрано",
            f"Файл для обробки:\n{self.enc_file.name}",
        )

    def _gen_key(self):
        try:
            k = generate_key()
            self.enc_key = k
            self.key_label.configure(text=f"🔑 {k.hex()}")
            messagebox.showinfo(
                "Ключ згенеровано",
                "Новий випадковий 128-бітний ключ успішно згенеровано.",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка генерації ключа",
                f"Під час генерації ключа сталася помилка:\n{e}",
            )

    def _load_key(self):
        p = filedialog.askopenfilename(
            title="Виберіть файл ключа (HEX)",
            filetypes=[("Усі файли", "*.*")],
        )
        if not p:
            return
        try:
            k = load_key_hex(p)
        except Exception as e:
            messagebox.showerror(
                "Помилка завантаження ключа",
                f"Не вдалося завантажити ключ з файлу:\n{e}",
            )
            return
        self.enc_key = k
        self.key_label.configure(text=f"🔑 {k.hex()}")
        messagebox.showinfo(
            "Ключ завантажено",
            f"Ключ успішно завантажено з файлу:\n{Path(p).name}",
        )

    def _encrypt_file(self):
        if not self.enc_file:
            messagebox.showwarning(
                "Файл не вибрано",
                "Спочатку оберіть файл, який потрібно зашифрувати.",
            )
            return
        if not self.enc_key:
            messagebox.showwarning(
                "Ключ не задано",
                "Згенеруйте новий ключ або завантажте його з файлу\n"
                "перед шифруванням.",
            )
            return
        try:
            data = self.enc_file.read_bytes()
            ct = sm4_encrypt_ecb(data, self.enc_key)
            out = self.enc_file.with_suffix(self.enc_file.suffix + ".txt")
            out.write_bytes(ct)
            messagebox.showinfo(
                "Шифрування файлу виконано",
                f"Файл успішно зашифровано.\n\nРезультат збережено як:\n{out.name}",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка шифрування файлу",
                f"Під час шифрування файлу сталася помилка:\n{e}",
            )

    def _decrypt_file(self):
        p = filedialog.askopenfilename(
            title="Виберіть зашифрований файл (.txt)",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
        )
        if not p:
            return

        if not self.enc_key:
            k_file = filedialog.askopenfilename(
                title="Ключ не задано. Виберіть файл ключа (HEX)",
                filetypes=[("Усі файли", "*.*")],
            )
            if not k_file:
                messagebox.showwarning(
                    "Ключ не задано",
                    "Без ключа неможливо розшифрувати файл.\n"
                    "Повторіть спробу та вкажіть файл ключа.",
                )
                return
            try:
                key = load_key_hex(k_file)
            except Exception as e:
                messagebox.showerror(
                    "Помилка завантаження ключа",
                    f"Не вдалося завантажити ключ з файлу:\n{e}",
                )
                return
        else:
            key = self.enc_key

        try:
            ct = Path(p).read_bytes()
            pt = sm4_decrypt_ecb(ct, key)
            out = Path(p).with_suffix("")
            out.write_bytes(pt)
            messagebox.showinfo(
                "Розшифрування файлу виконано",
                f"Файл успішно розшифровано.\n\nРезультат збережено як:\n{out.name}",
            )
        except Exception as e:
            messagebox.showerror(
                "Помилка розшифрування файлу",
                "Не вдалося розшифрувати файл.\n\n"
                "Можливі причини:\n"
                " • використано неправильний ключ;\n"
                " • файл було змінено або пошкоджено;\n"
                " • файл не був зашифрований цією програмою.\n\n"
                f"Технічна інформація:\n{e}",
            )


if __name__ == "__main__":
    app = SM4App()
    app.mainloop()

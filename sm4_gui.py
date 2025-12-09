#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sm4_app_final.py
Enhanced CustomTkinter UI with expandable instructions, improved fonts, and larger window.
SM4 Encryption utility with text and file modes.
"""
from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk

import customtkinter as ctk
from customtkinter import CTkLabel, CTkButton, CTkEntry, CTkTextbox, CTkFrame, CTkSegmentedButton, CTkScrollableFrame

from sm4_core import (
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    generate_key,
    save_key_hex,
    load_key_hex,
)

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


def create_tooltip(widget, text):
    """Create a simple tooltip on mouse hover."""
    tooltip_window = [None]
    
    def on_enter(event):
        if tooltip_window[0] is None:
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f'+{event.x_root+10}+{event.y_root+10}')
            label = CTkLabel(tooltip, text=text, text_color='white', fg_color='#333333', 
                           corner_radius=4, padx=8, pady=4, font=("Segoe UI", 9))
            label.pack()
            tooltip_window[0] = tooltip
    
    def on_leave(event):
        if tooltip_window[0] is not None:
            tooltip_window[0].destroy()
            tooltip_window[0] = None
    
    widget.bind('<Enter>', on_enter)
    widget.bind('<Leave>', on_leave)


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

    def _build_ui(self) -> None:
        main = CTkFrame(self, fg_color=self.bg_color)
        main.pack(fill="both", expand=True, padx=20, pady=20)

        # ===== HEADER =====
        header = CTkFrame(main, fg_color=self.bg_color)
        header.pack(fill="x", pady=(0, 15))

        # Title section
        title_frame = CTkFrame(header, fg_color=self.bg_color)
        title_frame.pack(side="left", fill="x", expand=True)
        
        title = CTkLabel(title_frame, text="🔐 SM4 Encryption/Decryption Utility", 
                        font=("Segoe UI", 28, "bold"), text_color=self.text_color)
        title.pack(anchor="w")
        
        subtitle = CTkLabel(title_frame, 
                           text="Безпечне шифрування текстів та файлів за стандартом SM4", 
                           font=("Segoe UI", 11, "bold"), text_color="#555555")
        subtitle.pack(anchor="w", pady=(4, 0))

        # Mode switcher
        self.mode_var = ctk.StringVar(value="📁 Файли")
        segmented = CTkSegmentedButton(
            header, 
            values=["📝 Текст", "📁 Файли"], 
            variable=self.mode_var, 
            command=self._on_mode_change,
            font=("Segoe UI", 12, "bold")
        )
        segmented.pack(side="right")

        # Content area with scrollbar
        self.content = CTkScrollableFrame(main, fg_color=self.bg_color)
        self.content.pack(fill="both", expand=True)

        self.text_frame = CTkFrame(self.content, fg_color=self.bg_color)
        self.file_frame = CTkFrame(self.content, fg_color=self.bg_color)

        self._build_text_tab()
        self._build_file_tab()
        self._on_mode_change()
        
        # ===== FOOTER =====
        footer = CTkFrame(main, fg_color=self.bg_color, height=30)
        footer.pack(fill="x", pady=(10, 0), side="bottom")
        
        footer_label = CTkLabel(footer, text="© 2025 by Roman Sadovskyi  •  SM4 ECB Mode Utility", 
                               font=("Segoe UI", 12), text_color="#999999")
        footer_label.pack(anchor="center", padx=5, pady=2)

    def _on_mode_change(self, value=None):
        for w in self.content.winfo_children():
            w.pack_forget()
        if self.mode_var.get() == "📝 Текст":
            self.text_frame.pack(fill="both", expand=True)
        else:
            self.file_frame.pack(fill="both", expand=True)

    def _build_text_tab(self):
        f = self.text_frame
        
        # Program info button (collapsible)
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
        
        prog_info_btn = CTkButton(prog_btn_frame, text="▶ Про програму", 
                                 command=toggle_prog_info, fg_color="#FFB74D", hover_color="#FF9800",
                                 font=("Segoe UI", 12, "bold"), height=36)
        prog_info_btn.pack(anchor="w")
        
        # Hidden program info box
        self.prog_info_box_text = CTkFrame(f, fg_color="#FFE8D6", corner_radius=8)
        
        prog_title = CTkLabel(self.prog_info_box_text, text="ℹ️ Про програму", 
                             font=("Segoe UI", 13, "bold"), text_color="#E65100")
        prog_title.pack(anchor="w", padx=12, pady=(10, 4))
        
        prog_text = CTkLabel(self.prog_info_box_text, 
                            text="📋 SM4 — китайський державний стандарт симетричного шифрування\n\n"
                                 "📑 Основні характеристики:\n"
                                 "  • Довжина ключа: 128 бітів (32 HEX символи)\n"
                                 "  • Розмір блоку: 128 бітів (16 байтів)\n"
                                 "  • Кількість раундів: 32\n\n"
                                 "🔄 Режим роботи: ECB (Electronic CodeBook)\n"
                                 "  Кожен блок даних шифрується незалежно.\n\n"
                                 "⚠️  Важливо: Без правильного ключа неможливо розшифрувати дані!\n"
                                 "Зберігайте ключі в безпечному місці.",
                            font=("Segoe UI", 10), text_color="#E65100", justify="left")
        prog_text.pack(anchor="w", padx=12, pady=(0, 10))
        
        # Info button and box
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
        
        toggle_btn = CTkButton(info_btn_frame, text="▶ Як це працює?", 
                              command=toggle_text_info, fg_color="#9E9E9E", hover_color="#757575",
                              font=("Segoe UI", 12, "bold"), height=32)
        toggle_btn.pack(anchor="w")
        
        # Hidden info box
        self.text_info_box = CTkFrame(f, fg_color=self.info_color, corner_radius=8)
        
        info_title = CTkLabel(self.text_info_box, text="ℹ️ Як користуватися режимом Текст", 
                             font=("Segoe UI", 14, "bold"), text_color=self.text_color)
        info_title.pack(anchor="w", padx=12, pady=(10, 4))
        
        info_text = CTkLabel(
            self.text_info_box, 
            text="① Введіть або вставте текст у поле вводу\n\n"
                 "② Згенеруйте новий ключ або введіть існуючий\n"
                 "   (32 HEX символи = 128-бітний ключ)\n\n"
                 "③ Натисніть кнопку 'Зашифрувати'\n"
                 "   Результат відобразиться у HEX форматі\n\n"
                 "④ Для розшифрування повторіть процес\n"
                 "   з HEX текстом та кнопкою 'Розшифрувати'\n\n"
                 "⑤ Режим роботи ECB: Кожен блок тексту (16 байт)\n"
                 "   шифрується незалежно тим самим ключем",
            font=("Segoe UI", 11, "bold"),
            text_color=self.text_color,
            justify="left"
        )
        info_text.pack(anchor="w", padx=12, pady=(0, 10))
        
        # Input section
        self.text_input_frame = CTkFrame(f, fg_color=self.bg_color)
        self.text_input_frame.pack(fill="both", expand=True)
        
        in_sec = CTkFrame(self.text_input_frame, fg_color="white", border_width=1, border_color="#D0D0D0", corner_radius=8)
        in_sec.pack(fill="x", pady=(0, 10))
        
        in_header = CTkFrame(in_sec, fg_color="white")
        in_header.pack(fill="x", padx=12, pady=(10, 0))
        
        in_lbl = CTkLabel(in_header, text="📝 Вхідний текст", font=("Segoe UI", 15, "bold"))
        in_lbl.pack(side="left")
        
        q_mark = CTkLabel(in_header, text="❓", font=("Segoe UI", 14))
        q_mark.pack(side="left", padx=(6, 0))
        create_tooltip(q_mark, "Вводьте будь-який текст\nМаксимальна довжина не обмежена")
        
        self.text_input = CTkTextbox(in_sec, height=130, font=("Segoe UI", 13, "bold"))
        self.text_input.pack(fill="both", padx=12, pady=(6, 12))
        # Enable common paste bindings (Ctrl+V / Shift+Insert) and right-click context menu
        self.text_input.bind("<Control-v>", self._handle_paste)
        self.text_input.bind("<Control-V>", self._handle_paste)
        self.text_input.bind("<Shift-Insert>", self._handle_paste)
        self.text_input.bind("<Button-3>", self._show_text_context_menu)
        
        # Key section
        key_sec = CTkFrame(self.text_input_frame, fg_color="white", border_width=1, border_color="#D0D0D0", corner_radius=8)
        key_sec.pack(fill="x", pady=(0, 10))
        
        key_header = CTkFrame(key_sec, fg_color="white")
        key_header.pack(fill="x", padx=12, pady=(10, 0))
        
        key_lbl = CTkLabel(key_header, text="🔑 Ключ шифрування", font=("Segoe UI", 15, "bold"))
        key_lbl.pack(side="left")
        
        key_q = CTkLabel(key_header, text="❓", font=("Segoe UI", 14))
        key_q.pack(side="left", padx=(6, 0))
        create_tooltip(key_q, 
                      "Ключ має бути 32 символи в HEX\n"
                      "Приклад: 0123456789abcdef0123456789abcdef\n"
                      "Натисніть 'Згенерувати' для випадкового ключа")
        
        self.text_key = CTkEntry(key_sec, placeholder_text="Введіть або згенеруйте ключ (32 HEX)", 
                                font=("Courier", 13, "bold"))
        self.text_key.pack(fill="x", padx=12, pady=(6, 12))
        
        # Buttons
        btn_frame = CTkFrame(self.text_input_frame, fg_color=self.bg_color)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        gen_btn = CTkButton(btn_frame, text="🎲 Згенерувати новий ключ", 
                           command=self._gen_key_text, 
                           fg_color=self.warning_color, hover_color="#E68900", 
                           font=("Segoe UI", 12, "bold"), height=40)
        gen_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(gen_btn, "Створити випадковий 128-бітний ключ")
        
        enc_btn = CTkButton(btn_frame, text="🔒 Зашифрувати", 
                           command=self._encrypt_text, 
                           fg_color=self.accent_color, hover_color="#005A9E", 
                           font=("Segoe UI", 12, "bold"), height=40)
        enc_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(enc_btn, "Зашифрувати текст за алгоритмом SM4")
        
        dec_btn = CTkButton(btn_frame, text="🔓 Розшифрувати", 
                           command=self._decrypt_text, 
                           fg_color=self.success_color, hover_color="#1F8449", 
                           font=("Segoe UI", 12, "bold"), height=40)
        dec_btn.pack(side="left", padx=4, fill="x", expand=True)
        create_tooltip(dec_btn, "Розшифрувати HEX текст на оригінальний текст")
        
        # Output section
        out_sec = CTkFrame(self.text_input_frame, fg_color="white", border_width=1, border_color="#D0D0D0", corner_radius=8)
        out_sec.pack(fill="both", expand=True)
        
        out_header = CTkFrame(out_sec, fg_color="white")
        out_header.pack(fill="x", padx=12, pady=(10, 0))
        
        out_lbl = CTkLabel(out_header, text="📤 Результат (HEX формат)", font=("Segoe UI", 15, "bold"))
        out_lbl.pack(side="left")
        
        out_q = CTkLabel(out_header, text="❓", font=("Segoe UI", 14))
        out_q.pack(side="left", padx=(6, 0))
        create_tooltip(out_q, 
                      "Результат у шістнадцятковому форматі\n"
                      "Довжина завжди кратна 32 (16 байтів блоку)")
        
        copy_info = CTkLabel(out_header, text="(натисніть Ctrl+A для виділення і Ctrl+C для копіювання)", 
                            font=("Segoe UI", 10, "bold"), text_color="#999999")
        copy_info.pack(side="right")
        
        self.text_output = CTkTextbox(out_sec, height=160, font=("Courier", 13, "bold"))
        self.text_output.pack(fill="both", padx=12, pady=(6, 12))
        self.text_output.configure(state="disabled")

    def _gen_key_text(self):
        try:
            k = generate_key()
            self.text_key.delete(0, "end")
            self.text_key.insert(0, k.hex())
            messagebox.showinfo("✅ Готово", "Новий ключ згенерований та вставлений у поле.")
        except Exception as e:
            messagebox.showerror("❌ Помилка", f"Помилка генерації ключа:\n{str(e)}")

    def _encrypt_text(self):
        txt = self.text_input.get("1.0", "end").strip()
        if not txt:
            messagebox.showwarning("⚠️ Помилка", "Введіть текст для шифрування.")
            return
        k = self.text_key.get().strip()
        if not k:
            messagebox.showwarning("⚠️ Помилка", "Введіть або згенеруйте ключ (32 HEX символи).")
            return
        try:
            key = bytes.fromhex(k)
            if len(key) != 16:
                raise ValueError(f"Ключ має бути 16 байтів (32 HEX), отримано: {len(key)}")
            ct = sm4_encrypt_ecb(txt.encode('utf-8'), key)
            self.text_output.configure(state='normal')
            self.text_output.delete('1.0', 'end')
            self.text_output.insert('1.0', ct.hex())
            self.text_output.configure(state='disabled')
            messagebox.showinfo("✅ Готово", f"Текст зашифрований успішно.\nДовжина: {len(ct.hex())} символів.")
        except ValueError as ve:
            messagebox.showerror("❌ Помилка валідації", str(ve))
        except Exception as e:
            messagebox.showerror("❌ Помилка шифрування", str(e))

    def _decrypt_text(self):
        hex_in = self.text_input.get('1.0', 'end').strip()
        if not hex_in:
            messagebox.showwarning('⚠️ Помилка', 'Введіть HEX-шифртекст для розшифрування.')
            return
        k = self.text_key.get().strip()
        if not k:
            messagebox.showwarning('⚠️ Помилка', 'Введіть ключ (32 HEX символи).')
            return
        try:
            key = bytes.fromhex(k)
            if len(key) != 16:
                raise ValueError(f"Ключ має бути 16 байтів (32 HEX), отримано: {len(key)}")
            ct = bytes.fromhex(hex_in)
            pt = sm4_decrypt_ecb(ct, key)
            self.text_output.configure(state='normal')
            self.text_output.delete('1.0', 'end')
            self.text_output.insert('1.0', pt.decode('utf-8', errors='replace'))
            self.text_output.configure(state='disabled')
            messagebox.showinfo('✅ Готово', 'Текст розшифрований успішно.')
        except ValueError as ve:
            messagebox.showerror('❌ Помилка валідації', str(ve))
        except Exception as e:
            messagebox.showerror('❌ Помилка розшифрування', str(e))

    def _handle_paste(self, event=None):
        """Insert clipboard contents into the text input at the insert cursor.
        Returns 'break' so default handlers don't run when called via key event.
        """
        try:
            txt = self.clipboard_get()
            if txt:
                # Insert at current insert position
                self.text_input.insert('insert', txt)
        except Exception:
            # Ignore clipboard errors
            pass
        return "break"

    def _show_text_context_menu(self, event=None):
        """Show a simple right-click context menu for the text input."""
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Вставити", command=lambda: self._handle_paste())
        menu.add_command(label="Копіювати", command=lambda: self.text_input.event_generate('<<Copy>>'))
        menu.add_command(label="Вирізати", command=lambda: self.text_input.event_generate('<<Cut>>'))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _build_file_tab(self):
        f = self.file_frame
        
        # Program info button (collapsible)
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
        
        prog_info_btn = CTkButton(prog_btn_frame, text="▶ Про програму", 
                                 command=toggle_prog_info, fg_color="#FFB74D", hover_color="#FF9800",
                                 font=("Segoe UI", 12, "bold"), height=36)
        prog_info_btn.pack(anchor="w")
        
        # Hidden program info box
        self.prog_info_box_file = CTkFrame(f, fg_color="#FFE8D6", corner_radius=8)
        
        prog_title = CTkLabel(self.prog_info_box_file, text="ℹ️ Про програму", 
                             font=("Segoe UI", 13, "bold"), text_color="#E65100")
        prog_title.pack(anchor="w", padx=12, pady=(10, 4))
        
        prog_text = CTkLabel(self.prog_info_box_file, 
                            text="📋 SM4 — китайський державний стандарт симетричного шифрування\n\n"
                                 "📑 Основні характеристики:\n"
                                 "  • Довжина ключа: 128 бітів (32 HEX символи)\n"
                                 "  • Розмір блоку: 128 бітів (16 байтів)\n"
                                 "  • Кількість раундів: 32\n\n"
                                 "🔄 Режим роботи: ECB (Electronic CodeBook)\n"
                                 "  Кожен блок даних шифрується незалежно.\n\n"
                                 "⚠️  Важливо: Без правильного ключа неможливо розшифрувати дані!\n"
                                 "Зберігайте ключі в безпечному місці.",
                            font=("Segoe UI", 12), text_color="#E65100", justify="left")
        prog_text.pack(anchor="w", padx=12, pady=(0, 10))
        
        # Info button and box
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
        
        toggle_btn = CTkButton(info_btn_frame, text="▶ Як це працює?", 
                              command=toggle_file_info, fg_color="#9E9E9E", hover_color="#757575",
                              font=("Segoe UI", 12, "bold"), height=32)
        toggle_btn.pack(anchor="w")
        
        # Hidden info box
        self.file_info_box = CTkFrame(f, fg_color=self.info_color, corner_radius=8)
        
        info_title = CTkLabel(self.file_info_box, text="ℹ️ Як користуватися режимом Файли", 
                             font=("Segoe UI", 14, "bold"), text_color=self.text_color)
        info_title.pack(anchor="w", padx=12, pady=(10, 4))
        
        info_text = CTkLabel(
            self.file_info_box, 
            text="① Виберіть файл для шифрування\n"
                 "   Підтримуються всі типи файлів\n\n"
                 "② Згенеруйте новий ключ або завантажте існуючий\n"
                 "   Ключ у форматі HEX (128-біт)\n\n"
                 "③ Натисніть 'Зашифрувати файл'\n"
                 "   Результат буде збережено з розширенням .txt\n\n"
                 "④ Для розшифрування виберіть .txt файл\n"
                 "   та вкажіть правильний ключ\n"
                 "   ⚠️  Без ключа файл неможливо розшифрувати!\n\n"
                 "⑤ Режим роботи ECB: Кожен блок файлу (16 байт)\n"
                 "   шифрується незалежно тим самим ключем",
            font=("Segoe UI", 11, "bold"),
            text_color=self.text_color,
            justify="left"
        )
        info_text.pack(anchor="w", padx=12, pady=(0, 10))
        
        # File selection
        self.file_content_frame = CTkFrame(f, fg_color=self.bg_color)
        self.file_content_frame.pack(fill="both", expand=True)
        
        file_frame = CTkFrame(self.file_content_frame, fg_color="white", border_width=1, border_color="#D0D0D0", corner_radius=8)
        file_frame.pack(fill="x", pady=(0, 10))
        
        file_header = CTkFrame(file_frame, fg_color="white")
        file_header.pack(fill="x", padx=12, pady=(10, 0))
        
        file_lbl = CTkLabel(file_header, text="📁 Вибір файлу", font=("Segoe UI", 15, "bold"))
        file_lbl.pack(side="left")
        
        file_q = CTkLabel(file_header, text="❓", font=("Segoe UI", 14))
        file_q.pack(side="left", padx=(6, 0))
        create_tooltip(file_q, "Виберіть будь-який файл для шифрування")
        
        self.file_label = CTkLabel(file_frame, text='📎 Файл не обрано', text_color='#888888', 
                                  font=("Segoe UI", 13, "bold"))
        self.file_label.pack(side='left', padx=12, pady=10, fill='x', expand=True, anchor='center')
        
        browse_btn = CTkButton(file_frame, text='📂 Обрати файл', command=self._browse_file, 
                              fg_color=self.accent_color, hover_color="#005A9E", 
                              font=("Segoe UI", 11, "bold"), height=40)
        browse_btn.pack(side='right', padx=12, pady=10)
        create_tooltip(browse_btn, "Відкрити діалог для вибору файлу")
        
        # Key management
        key_frame = CTkFrame(self.file_content_frame, fg_color="white", border_width=1, border_color="#D0D0D0", corner_radius=8)
        key_frame.pack(fill="x", pady=(0, 10))
        
        key_header = CTkFrame(key_frame, fg_color="white")
        key_header.pack(fill="x", padx=12, pady=(10, 0))
        
        key_lbl = CTkLabel(key_header, text="🔑 Управління ключем", font=("Segoe UI", 15, "bold"))
        key_lbl.pack(side="left")
        
        key_q = CTkLabel(key_header, text="❓", font=("Segoe UI", 14))
        key_q.pack(side="left", padx=(6, 0))
        create_tooltip(key_q, "Виберіть, сгенеруйте або завантажте ключ")
        
        key_btn_frame = CTkFrame(key_frame, fg_color="white")
        key_btn_frame.pack(fill="x", padx=12, pady=(6, 0))
        
        gen_btn = CTkButton(key_btn_frame, text='🎲 Згенерувати ключ', command=self._gen_key, 
                           fg_color=self.warning_color, hover_color="#E68900", 
                           font=("Segoe UI", 11, "bold"), height=40)
        gen_btn.pack(side='left', padx=4, fill="x", expand=True)
        create_tooltip(gen_btn, "Створити новий 128-бітний випадковий ключ")
        
        load_btn = CTkButton(key_btn_frame, text='📥 Завантажити ключ', command=self._load_key, 
                            fg_color="#9C27B0", hover_color="#7B1FA2", 
                            font=("Segoe UI", 11, "bold"), height=40)
        load_btn.pack(side='left', padx=4, fill="x", expand=True)
        create_tooltip(load_btn, "Завантажити ключ з файлу (HEX формат)")
        
        key_label_frame = CTkFrame(key_frame, fg_color="white")
        key_label_frame.pack(fill="x", padx=12, pady=(6, 12))
        
        self.key_label = CTkLabel(key_label_frame, text='🔑 Ключ не обрано', text_color='#888888', 
                                 font=("Segoe UI", 12, "bold"))
        self.key_label.pack(side='left', fill='x', expand=True)
        
        # Action buttons
        action_frame = CTkFrame(self.file_content_frame, fg_color=self.bg_color)
        action_frame.pack(fill="both", expand=True)
        
        enc_btn = CTkButton(action_frame, text='🔒 Зашифрувати файл', command=self._encrypt_file, 
                           fg_color=self.accent_color, hover_color="#005A9E", 
                           font=("Segoe UI", 12, "bold"), height=48)
        enc_btn.pack(fill='x', pady=(0, 8))
        create_tooltip(enc_btn, "Зашифрувати вибраний файл за допомогою ключа")
        
        dec_btn = CTkButton(action_frame, text='🔓 Розшифрувати файл', command=self._decrypt_file, 
                           fg_color=self.success_color, hover_color="#1F8449", 
                           font=("Segoe UI", 12, "bold"), height=48)
        dec_btn.pack(fill='x')
        create_tooltip(dec_btn, "Розшифрувати файл з розширенням .txt")

    def _browse_file(self):
        p = filedialog.askopenfilename(title='Виберіть файл для шифрування', 
                                       filetypes=[('All files','*.*')])
        if not p:
            return
        self.enc_file = Path(p)
        self.file_label.configure(text=f"📎 {self.enc_file.name}")
        messagebox.showinfo('✅ Готово', f'Файл обраний: {self.enc_file.name}')

    def _gen_key(self):
        try:
            k = generate_key()
            self.enc_key = k
            self.key_label.configure(text=f"🔑 {k.hex()}")
            messagebox.showinfo('✅ Готово', 'Новий ключ згенерований успішно.')
        except Exception as e:
            messagebox.showerror('❌ Помилка', f"Помилка генерації ключа:\n{str(e)}")

    def _load_key(self):
        p = filedialog.askopenfilename(title='Виберіть файл ключа (HEX)', 
                                       filetypes=[('All files','*.*')])
        if not p:
            return
        try:
            k = load_key_hex(p)
        except Exception as e:
            messagebox.showerror('❌ Помилка завантаження ключа', str(e))
            return
        self.enc_key = k
        self.key_label.configure(text=f"🔑 {k.hex()}")
        messagebox.showinfo('✅ Готово', f'Ключ завантажено з {Path(p).name}')

    def _encrypt_file(self):
        if not self.enc_file:
            messagebox.showwarning('⚠️ Помилка', 'Виберіть файл для шифрування.')
            return
        if not self.enc_key:
            messagebox.showwarning('⚠️ Помилка', 'Ключ не обрано. Згенеруйте або завантажте ключ.')
            return
        try:
            data = self.enc_file.read_bytes()
            ct = sm4_encrypt_ecb(data, self.enc_key)
            out = self.enc_file.with_suffix(self.enc_file.suffix + '.txt')
            out.write_bytes(ct)
            messagebox.showinfo('✅ Готово', f'Файл зашифрований!\n\nЗбережено як:\n{out.name}')
        except Exception as e:
            messagebox.showerror('❌ Помилка шифрування файлу', str(e))

    def _decrypt_file(self):
        p = filedialog.askopenfilename(title='Виберіть зашифрований файл (.txt)', 
                                       filetypes=[('Text files','*.txt'),('All files','*.*')])
        if not p:
            return
        if not self.enc_key:
            k = filedialog.askopenfilename(title='Виберіть файл ключа (HEX)', 
                                          filetypes=[('All files','*.*')])
            if not k:
                messagebox.showwarning('⚠️ Помилка', 'Ключ необхідний для розшифрування.')
                return
        else:
            k = None
        try:
            key = self.enc_key if self.enc_key else load_key_hex(k)
            ct = Path(p).read_bytes()
            pt = sm4_decrypt_ecb(ct, key)
            out = Path(p).with_suffix('')
            out.write_bytes(pt)
            messagebox.showinfo('✅ Готово', f'Файл розшифрований!\n\nЗбережено як:\n{out.name}')
        except Exception as e:
            messagebox.showerror('❌ Помилка розшифрування файлу', str(e))


if __name__ == '__main__':
    app = SM4App()
    app.mainloop()

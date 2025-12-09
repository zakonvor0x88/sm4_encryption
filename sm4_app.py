#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sm4_app.py
Проста сучасна обгортка UI (CustomTkinter) для sm4_core.py
"""
from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from sm4_core import (
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    generate_key,
    save_key_hex,
    load_key_hex,
)

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


class SM4App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SM4 Encryption — сучасна утиліта")
        self.geometry("1000x700")
        self.minsize(800, 600)

        # Візуальні кольори
        self.accent_color = "#0078D4"
        self.bg_color = "#F5F5F5"
        self.text_color = "#1F1F1F"

        # Файли / ключі
        self.enc_file: Path | None = None
        self.enc_key: bytes | None = None
        self.dec_file: Path | None = None
        self.dec_key: bytes | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        main = ctk.CTkFrame(self, fg_color=self.bg_color)
        main.pack(fill="both", expand=True, padx=20, pady=20)

        header = ctk.CTkFrame(main, fg_color=self.bg_color)
        header.pack(fill="x", pady=(0, 10))

        title = ctk.CTkLabel(
            header,
            text="🔐 SM4 Encryption",
            font=("Segoe UI", 20, "bold"),
            text_color=self.text_color,
        )
        title.pack(side="left")

        # Mode switch
        self.mode_var = ctk.StringVar(value="text")
        segmented = ctk.CTkSegmentedButton(
            header,
            values=["Текст", "Файли"],
            variable=self.mode_var,
            command=self._on_mode_change,
            font=("Segoe UI", 12),
            fg_color="#E0E0E0",
        )
        segmented.pack(side="right")

        # Content area
        self.content = ctk.CTkFrame(main, fg_color=self.bg_color)
        self.content.pack(fill="both", expand=True)

        # Frames for modes
        self.text_frame = ctk.CTkFrame(self.content, fg_color=self.bg_color)
        self.file_frame = ctk.CTkFrame(self.content, fg_color=self.bg_color)

        self._build_text_tab()
        self._build_file_tab()

        self._on_mode_change()

    def _on_mode_change(self, value=None) -> None:
        mode = self.mode_var.get()
        for w in self.content.winfo_children():
            w.pack_forget()
        if mode == "text":
            self.text_frame.pack(fill="both", expand=True)
        else:
            self.file_frame.pack(fill="both", expand=True)

    # ---------- Text tab ----------
    def _build_text_tab(self) -> None:
        f = self.text_frame

        # input
        lbl_in = ctk.CTkLabel(f, text="Вхідний текст", font=("Segoe UI", 13, "bold"))
        lbl_in.pack(anchor="w", pady=(6, 0))

        self.text_input = ctk.CTkTextbox(f, height=150, font=("Segoe UI", 12))
        self.text_input.pack(fill="both", expand=False, pady=(6, 10))

        # key entry
        key_lbl = ctk.CTkLabel(f, text="Ключ (HEX, 32 символи)", font=("Segoe UI", 12))
        key_lbl.pack(anchor="w")

        self.text_key = ctk.CTkEntry(f, placeholder_text="Введіть ключ у HEX...", font=("Courier", 12))
        self.text_key.pack(fill="x", pady=(6, 10))

        # buttons
        btns = ctk.CTkFrame(f, fg_color=self.bg_color)
        btns.pack(fill="x", pady=(0, 10))

        enc_btn = ctk.CTkButton(btns, text="🔒 Зашифрувати", fg_color=self.accent_color, command=self._encrypt_text)
        enc_btn.pack(side="left", padx=(0, 8))

        dec_btn = ctk.CTkButton(btns, text="🔓 Розшифрувати", fg_color="#27AE60", command=self._decrypt_text)
        dec_btn.pack(side="left")

        # output
        out_lbl = ctk.CTkLabel(f, text="Результат (HEX)", font=("Segoe UI", 13, "bold"))
        out_lbl.pack(anchor="w", pady=(6, 0))

        self.text_output = ctk.CTkTextbox(f, height=150, font=("Courier", 11))
        self.text_output.pack(fill="both", expand=True, pady=(6, 0))
        self.text_output.configure(state="disabled")

    def _encrypt_text(self) -> None:
        txt = self.text_input.get("1.0", "end").strip()
        if not txt:
            messagebox.showwarning("Помилка", "Введіть текст для шифрування.")
            return
        key_hex = self.text_key.get().strip()
        if not key_hex:
            messagebox.showwarning("Помилка", "Введіть ключ у форматі HEX або згенеруйте його.")
            return
        try:
            key = bytes.fromhex(key_hex)
            ct = sm4_encrypt_ecb(txt.encode("utf-8"), key)
            self._set_text_output(ct.hex())
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))

    def _decrypt_text(self) -> None:
        hex_text = self.text_input.get("1.0", "end").strip()
        if not hex_text:
            messagebox.showwarning("Помилка", "Введіть HEX-шифртекст для розшифрування.")
            return
        key_hex = self.text_key.get().strip()
        if not key_hex:
            messagebox.showwarning("Помилка", "Введіть ключ у форматі HEX.")
            return
        try:
            ct = bytes.fromhex(hex_text)
            key = bytes.fromhex(key_hex)
            pt = sm4_decrypt_ecb(ct, key)
            self._set_text_output(pt.decode("utf-8", errors="replace"))
        except Exception as e:
            messagebox.showerror("Помилка розшифрування", str(e))

    def _set_text_output(self, text: str) -> None:
        self.text_output.configure(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.insert("1.0", text)
        self.text_output.configure(state="disabled")

    # ---------- File tab ----------
    def _build_file_tab(self) -> None:
        f = self.file_frame

        lbl = ctk.CTkLabel(f, text="Файловий режим (тільки .txt)", font=("Segoe UI", 14, "bold"))
        lbl.pack(anchor="w", pady=(6, 8))

        # input file
        in_frame = ctk.CTkFrame(f, fg_color="white", border_width=1, border_color="#D0D0D0")
        in_frame.pack(fill="x", pady=(6, 8))
        self.file_in_label = ctk.CTkLabel(in_frame, text="Файл не обрано", text_color="#888888")
        self.file_in_label.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        browse_in = ctk.CTkButton(in_frame, text="Обрати файл", fg_color=self.accent_color, command=self._browse_input_file)
        browse_in.pack(side="right", padx=10, pady=6)

        # key file / generate
        key_frame = ctk.CTkFrame(f, fg_color=self.bg_color)
        key_frame.pack(fill="x", pady=(0, 8))

        gen_btn = ctk.CTkButton(key_frame, text="Генерувати ключ", fg_color=self.accent_color, command=self._generate_key_file)
        gen_btn.pack(side="left", padx=(0, 8))

        load_btn = ctk.CTkButton(key_frame, text="Завантажити ключ", fg_color=self.accent_color, command=self._load_key_file)
        load_btn.pack(side="left")

        self.key_display = ctk.CTkLabel(key_frame, text="Ключ не обрано", text_color="#888888")
        self.key_display.pack(side="left", padx=(12, 0))

        # action buttons
        act_frame = ctk.CTkFrame(f, fg_color=self.bg_color)
        act_frame.pack(fill="x", pady=(8, 0))

        enc_btn = ctk.CTkButton(act_frame, text="Зашифрувати файл", fg_color=self.accent_color, command=self._encrypt_file)
        enc_btn.pack(side="left", padx=(0, 8))

        dec_btn = ctk.CTkButton(act_frame, text="Розшифрувати файл", fg_color="#27AE60", command=self._decrypt_file)
        dec_btn.pack(side="left")

    def _browse_input_file(self) -> None:
        p = filedialog.askopenfilename(title="Виберіть .txt файл", filetypes=[("Text files", "*.txt")])
        if not p:
            return
        self.enc_file = Path(p)
        self.file_in_label.configure(text=str(self.enc_file.name))

    def _generate_key_file(self) -> None:
        key = generate_key()
        self.enc_key = key
        self.key_display.configure(text=key.hex())

    def _load_key_file(self) -> None:
        p = filedialog.askopenfilename(title="Виберіть файл ключа (hex)", filetypes=[("Hex key", "*.txt;*.hex;*.key;*.txt")])
        if not p:
            return
        try:
            key = load_key_hex(p)
        except Exception as e:
            messagebox.showerror("Помилка", str(e))
            return
        self.enc_key = key
        self.key_display.configure(text=key.hex())

    def _encrypt_file(self) -> None:
        if not self.enc_file:
            messagebox.showwarning("Помилка", "Виберіть файл для шифрування.")
            return
        if not self.enc_key:
            messagebox.showwarning("Помилка", "Згенеруйте або завантажте ключ.")
            return
        try:
            data = self.enc_file.read_bytes()
            ct = sm4_encrypt_ecb(data, self.enc_key)
            out_path = self.enc_file.with_suffix(self.enc_file.suffix + ".enc")
            out_path.write_bytes(ct)
            messagebox.showinfo("Готово", f"Шифртекст збережено у: {out_path}")
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))

    def _decrypt_file(self) -> None:
        p = filedialog.askopenfilename(title="Виберіть файл з шифртекстом", filetypes=[("Encrypted files", "*.enc;*.txt;*.*")])
        if not p:
            return
        if not self.enc_key:
            # ask for key if not loaded
            k = filedialog.askopenfilename(title="Виберіть файл ключа (hex)", filetypes=[("Hex key", "*.txt;*.hex;*.key")])
            if not k:
                messagebox.showwarning("Помилка", "Ключ не обрано.")
                return
            try:
                key = load_key_hex(k)
            except Exception as e:
                messagebox.showerror("Помилка", str(e))
                return
        else:
            key = self.enc_key
        try:
            ct = Path(p).read_bytes()
            pt = sm4_decrypt_ecb(ct, key)
            out_path = Path(p).with_suffix("")
            out_path.write_bytes(pt)
            messagebox.showinfo("Готово", f"Розшифрований файл збережено у: {out_path}")
        except Exception as e:
            messagebox.showerror("Помилка розшифрування", str(e))


if __name__ == "__main__":
    app = SM4App()
    app.mainloop()
• Вводьте ключ вручну у форматі HEX

⚙️ ПАРАМЕТРИ
Ключі зберігаються у форматі HEX для легкого обміну та зберігання."""

        info_text.insert("1.0", info_content)
        info_text.configure(state="disabled")

        close_btn = ctk.CTkButton(
            about_window,
            text="Закрити",
            font=("Segoe UI", 11),
            fg_color=self.accent_color,
            hover_color="#005A9E",
            command=about_window.destroy
        )
        close_btn.pack(pady=(0, 20), padx=20, fill="x")

    # ===== ТЕКСТОВІ ОПЕРАЦІЇ =====

    def _encrypt_text(self):
        txt = self.text_input.get("1.0", "end-1c")
        if not txt:
            messagebox.showwarning("Помилка", "Введіть текст для шифрування.")
            return
        
        hexk = self.text_key_entry.get().strip()
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
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", res)
            self.text_output.configure(state="disabled")
            self._last_text_result = res
            messagebox.showinfo("Успіх", "Текст зашифровано.")
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))

    def _decrypt_text(self):
        hex_in = self.text_input.get("1.0", "end-1c").strip()
        if not hex_in:
            messagebox.showwarning("Помилка", "Введіть HEX для розшифрування.")
            return
        
        hexk = self.text_key_entry.get().strip()
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
            self.text_output.configure(state="normal")
            self.text_output.delete("1.0", "end")
            self.text_output.insert("1.0", res)
            self.text_output.configure(state="disabled")
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

    # ===== ФАЙЛОВІ ОПЕРАЦІЇ =====

    def _browse_encrypt_file(self):
        path = filedialog.askopenfilename(
            title="Обрати файл для шифрування",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.enc_file = path
            self.enc_file_label.configure(text=Path(path).name)

    def _browse_encrypt_key(self):
        path = filedialog.askopenfilename(
            title="Обрати файл ключа",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                self.enc_key = load_key_hex(path)
                self.enc_key_display.configure(text=f"✅ {Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка ключа", str(e))
                self.enc_key = None

    def _input_key_hex_enc(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Ввести HEX ключ")
        dialog.geometry("400x180")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)

        label = ctk.CTkLabel(
            dialog,
            text="Введіть ключ у форматі HEX (16 байтів = 32 символи):",
            font=("Segoe UI", 11)
        )
        label.pack(pady=15, padx=20)

        entry = ctk.CTkEntry(
            dialog,
            font=("Courier", 11),
            fg_color="white",
            border_color="#D0D0D0",
            border_width=1
        )
        entry.pack(fill="x", padx=20, pady=(0, 15))
        entry.focus()

        def apply():
            hexk = entry.get().strip()
            if not hexk:
                messagebox.showwarning("Помилка", "Ключ не вказано")
                return
            try:
                self.enc_key = bytes.fromhex(hexk)
                if len(self.enc_key) != 16:
                    raise ValueError("Ключ повинен бути 16 байтів (32 символи hex)")
                self.enc_key_display.configure(text="✅ Ключ введено (HEX)")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Помилка", str(e))

        ok_btn = ctk.CTkButton(
            dialog,
            text="OK",
            font=("Segoe UI", 11),
            fg_color=self.accent_color,
            hover_color="#005A9E",
            command=apply
        )
        ok_btn.pack(padx=20, pady=(0, 15), fill="x")

    def _generate_key_enc(self):
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
                self.enc_key_display.configure(text=f"✅ Ключ згенеровано")
                messagebox.showinfo("Успіх", f"Ключ збережено в:\n{Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося зберегти ключ:\n{e}")

    def _encrypt_file(self):
        if not self.enc_file:
            messagebox.showwarning("Помилка", "Виберіть файл для шифрування")
            return
        
        if not os.path.exists(self.enc_file):
            messagebox.showerror("Помилка", "Файл не знайдено")
            return

        if not self.enc_key:
            messagebox.showwarning("Помилка", "Виберіть або створіть ключ")
            return

        try:
            with open(self.enc_file, "r", encoding="utf-8") as f:
                data = f.read().encode("utf-8")
        except Exception as e:
            messagebox.showerror("Помилка читання файлу", str(e))
            return

        try:
            ciphertext = sm4_encrypt_ecb(data, self.enc_key)
        except Exception as e:
            messagebox.showerror("Помилка шифрування", str(e))
            return

        format_type = self.enc_format_var.get()
        if format_type == "hex":
            result_data = ciphertext
            file_ext = ""
        else:
            result_data = ciphertext.hex().encode("utf-8")
            file_ext = ".txt"

        base_path = Path(self.enc_file)
        if file_ext:
            output_path = str(base_path.parent / f"{base_path.stem}{file_ext}")
        else:
            output_path = str(base_path.parent / f"{base_path.stem}")

        try:
            with open(output_path, "wb") as f:
                f.write(result_data)
        except Exception as e:
            messagebox.showerror("Помилка запису файлу", str(e))
            return

        messagebox.showinfo(
            "Успіх",
            f"Файл зашифровано!\n\n📁 {Path(output_path).name}\n📊 Розмір: {len(result_data)} байт"
        )

    def _browse_decrypt_file(self):
        path = filedialog.askopenfilename(
            title="Обрати зашифрований файл",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.dec_file = path
            self.dec_file_label.configure(text=Path(path).name)

    def _browse_decrypt_key(self):
        path = filedialog.askopenfilename(
            title="Обрати файл ключа",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                self.dec_key = load_key_hex(path)
                self.dec_key_display.configure(text=f"✅ {Path(path).name}")
            except Exception as e:
                messagebox.showerror("Помилка ключа", str(e))
                self.dec_key = None

    def _input_key_hex_dec(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Ввести HEX ключ")
        dialog.geometry("400x180")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)

        label = ctk.CTkLabel(
            dialog,
            text="Введіть ключ у форматі HEX (16 байтів = 32 символи):",
            font=("Segoe UI", 11)
        )
        label.pack(pady=15, padx=20)

        entry = ctk.CTkEntry(
            dialog,
            font=("Courier", 11),
            fg_color="white",
            border_color="#D0D0D0",
            border_width=1
        )
        entry.pack(fill="x", padx=20, pady=(0, 15))
        entry.focus()

        def apply():
            hexk = entry.get().strip()
            if not hexk:
                messagebox.showwarning("Помилка", "Ключ не вказано")
                return
            try:
                self.dec_key = bytes.fromhex(hexk)
                if len(self.dec_key) != 16:
                    raise ValueError("Ключ повинен бути 16 байтів (32 символи hex)")
                self.dec_key_display.configure(text="✅ Ключ введено (HEX)")
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Помилка", str(e))

        ok_btn = ctk.CTkButton(
            dialog,
            text="OK",
            font=("Segoe UI", 11),
            fg_color=self.accent_color,
            hover_color="#005A9E",
            command=apply
        )
        ok_btn.pack(padx=20, pady=(0, 15), fill="x")

    def _decrypt_file(self):
        if not self.dec_file:
            messagebox.showwarning("Помилка", "Виберіть файл для розшифрування")
            return
        
        if not os.path.exists(self.dec_file):
            messagebox.showerror("Помилка", "Файл не знайдено")
            return

        if not self.dec_key:
            messagebox.showwarning("Помилка", "Виберіть або введіть ключ")
            return

        try:
            with open(self.dec_file, "r", encoding="utf-8") as f:
                file_content = f.read().strip()
        except Exception as e:
            messagebox.showerror("Помилка читання файлу", str(e))
            return

        ciphertext = None
        if Path(self.dec_file).suffix.lower() == ".txt":
            try:
                ciphertext = bytes.fromhex(file_content)
            except ValueError as e:
                messagebox.showerror("Помилка", f"Файл .txt не містить коректного hex-рядка:\n{e}")
                return
        else:
            try:
                with open(self.dec_file, "rb") as f:
                    ciphertext = f.read()
            except Exception:
                try:
                    ciphertext = bytes.fromhex(file_content)
                except Exception as e:
                    messagebox.showerror("Помилка", f"Не вдалося прочитати файл:\n{e}")
                    return

        try:
            plaintext = sm4_decrypt_ecb(ciphertext, self.dec_key)
        except ValueError as e:
            messagebox.showerror(
                "Помилка розшифрування",
                f"{e}\n\nПеревірте правильність ключа та цілісність файлу"
            )
            return

        base_path = Path(self.dec_file)
        output_path = str(base_path.parent / f"{base_path.stem}.dec")

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(plaintext.decode("utf-8", errors="replace"))
        except Exception as e:
            messagebox.showerror("Помилка запису файлу", str(e))
            return

        messagebox.showinfo(
            "Успіх",
            f"Файл розшифровано!\n\n📁 {Path(output_path).name}\n📊 Розмір: {len(plaintext)} байт"
        )


def main():
    app = SM4App()
    app.mainloop()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для збирання EXE файлу з PyInstaller
"""
import PyInstaller.__main__
import sys
from pathlib import Path

# Отримаємо шлях до директорії проекту
project_dir = Path(__file__).parent.absolute()

# Параметри для PyInstaller
args = [
    str(project_dir / "sm4_gui (2).py"),  # Основний файл
    "--onefile",  # Один файл EXE
    "--windowed",  # Без консолі
    "--name", "SM4_Encryption",  # Назва EXE
    "--distpath", str(project_dir / "dist"),  # Директорія з результатом
    "--workpath", str(project_dir / "build"),  # Директорія для тимчасових файлів
    "--specpath", str(project_dir),  # Директорія для spec файлу
    "--add-data", str(project_dir / "sm4_core.py") + ";.",  # Включити sm4_core.py
    "--hidden-import=customtkinter",  # Явно вказати CustomTkinter
    "--hidden-import=tkinter",
    "-i", "NONE",  # Без спеціальної іконки
]

# Запустимо PyInstaller
PyInstaller.__main__.run(args)

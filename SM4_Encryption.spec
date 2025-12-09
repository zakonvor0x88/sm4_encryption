# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Lenovo\\OneDrive\\Документи\\Навчання 3 курс\\Важливо\\SM4_Encryption_v2\\sm4_gui (2).py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\Lenovo\\OneDrive\\Документи\\Навчання 3 курс\\Важливо\\SM4_Encryption_v2\\sm4_core.py', '.')],
    hiddenimports=['customtkinter', 'tkinter'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SM4_Encryption',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='NONE',
)

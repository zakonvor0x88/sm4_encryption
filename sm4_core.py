#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sm4_core.py

Виділений модуль з реалізацією SM4 та допоміжними функціями.
"""
from __future__ import annotations

from typing import List
import secrets

# S-box, FK, CK - таблиці для SM4
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
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _tau(a: int) -> int:
    b0 = SBOX[(a >> 24) & 0xFF]
    b1 = SBOX[(a >> 16) & 0xFF]
    b2 = SBOX[(a >> 8) & 0xFF]
    b3 = SBOX[a & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def _L_enc(b: int) -> int:
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _L_key(b: int) -> int:
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _T_enc(x: int) -> int:
    return _L_enc(_tau(x))


def _T_key(x: int) -> int:
    return _L_key(_tau(x))


def _bytes_to_words(block: bytes) -> List[int]:
    if len(block) != 16:
        raise ValueError(
            "Внутрішня помилка: блок SM4 повинен містити рівно 16 байтів.\n"
            "Якщо ви бачите це повідомлення, зверніться до розробника."
        )
    return [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]


def _words_to_bytes(words: List[int]) -> bytes:
    if len(words) != 4:
        raise ValueError(
            "Внутрішня помилка: для перетворення у байти потрібно 4 32-бітні слова."
        )
    return b"".join(w.to_bytes(4, "big") for w in words)


class SM4:
    """Реалізація блочного шифру SM4 (SMS4)."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError(
                "Ключ SM4 повинен бути довжиною рівно 16 байтів (128 біт).\n"
                "Перевірте, що ключ містить 32 HEX-символи без пробілів."
            )
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
    """Доповнення PKCS#7 для довільних даних."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Зняття PKCS#7-доповнення з перевіркою коректності."""
    if not data or len(data) % block_size != 0:
        raise ValueError(
            "Шифртекст має некоректну довжину (не кратну 16 байтам).\n"
            "Можливо, файл пошкоджений або був зашифрований іншим режимом/алгоритмом."
        )
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(
            "Не вдалося зняти PKCS#7-доповнення.\n"
            "Можливі причини:\n"
            " • використано неправильний ключ;\n"
            " • шифртекст пошкоджений або змінений;\n"
            " • дані були зашифровані іншим алгоритмом чи режимом."
        )
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError(
            "Не вдалося зняти PKCS#7-доповнення.\n"
            "Можливі причини:\n"
            " • використано неправильний ключ;\n"
            " • шифртекст пошкоджений або змінений;\n"
            " • дані були зашифровані іншим алгоритмом чи режимом."
        )
    return data[:-pad_len]


def sm4_encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Шифрування довільних даних у режимі ECB з PKCS#7-доповненням."""
    cipher = SM4(key)
    padded = pkcs7_pad(data, 16)
    out = bytearray()
    for i in range(0, len(padded), 16):
        out.extend(cipher.encrypt_block(padded[i:i + 16]))
    return bytes(out)


def sm4_decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """Розшифрування даних у режимі ECB з видаленням PKCS#7-доповнення."""
    if len(data) % 16 != 0:
        raise ValueError(
            "Довжина шифртексту повинна бути кратною 16 байтам (розмір блоку SM4).\n"
            "Переконайтеся, що файл не був обрізаний або пошкоджений."
        )
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
        raise ValueError(
            "Файл ключа містить некоректні символи.\n"
            "Очікується 32 HEX-символи без пробілів (0–9, a–f)."
        ) from exc
    if len(key) != 16:
        raise ValueError(
            f"Ключ у файлі має довжину {len(key)} байтів.\n"
            "Для SM4 потрібен ключ рівно 16 байтів (32 HEX-символи).\n"
            "Виправте файл або згенеруйте новий ключ."
        )
    return key

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from sm4_core import SM4, sm4_encrypt_ecb, sm4_decrypt_ecb, generate_key


def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


# ---------- 1. Тестові вектори (KAT) ----------

def test_vector_1():
    """
    GB/T 32907-2016 Example 1:
    key = 0123456789ABCDEFFEDCBA9876543210
    pt  = 0123456789ABCDEFFEDCBA9876543210
    ct  = 681EDF34D206965E86B3E94F536E4246
    """
    key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    pt = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    exp_ct = "681EDF34D206965E86B3E94F536E4246"

    c = SM4(key)
    ct = c.encrypt_block(pt)

    assert ct.hex().upper() == exp_ct, "TV1: шифрування не співпало з еталоном"
    assert c.decrypt_block(ct) == pt, "TV1: розшифрування не повертає вихідний блок"


def test_vector_2():
    """
    Додатковий відомий вектор (OpenSSL):
    key = FEDCBA98765432100123456789ABCDEF
    pt  = 000102030405060708090A0B0C0D0E0F
    ct  = F766678F13F01ADEAC1B3EA955ADB594
    """
    key = hex_to_bytes("FEDCBA98765432100123456789ABCDEF")
    pt = hex_to_bytes("000102030405060708090A0B0C0D0E0F")
    exp_ct = "F766678F13F01ADEAC1B3EA955ADB594"

    c = SM4(key)
    ct = c.encrypt_block(pt)

    assert ct.hex().upper() == exp_ct, "TV2: шифрування не співпало з еталоном"
    assert c.decrypt_block(ct) == pt, "TV2: розшифрування не повертає вихідний блок"


# ---------- 2. Million-iteration test ----------

def test_million_iterations():
    """
    Тест 1 000 000 послідовних шифрувань одного блока.
    Обчислюється довго (десятки секунд), але це «залізний» тест.
    Очікуваний результат взято з стандарту.
    """
    key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    block = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    expected = "595298C7C6FD271F0402F804C33D3F66"

    c = SM4(key)
    for _ in range(1_000_000):
        block = c.encrypt_block(block)

    assert block.hex().upper() == expected, "Million-iteration test не пройдено"


# ---------- 3. Round-trip-тести для тексту ----------

def test_text_roundtrip():
    key = generate_key()
    texts = [
        "",  # порожній
        "A",
        "Симетричний блочний шифр SM4.",
        "1234567890 !@#$%^&*()_+{}|:\"<>?",
        "Довгий текст " * 100,
    ]

    for t in texts:
        ct = sm4_encrypt_ecb(t.encode("utf-8"), key)
        pt = sm4_decrypt_ecb(ct, key)
        assert pt.decode("utf-8") == t, "text roundtrip failed"


# ---------- 4. Round-trip-тести для файлів ----------

def test_file_roundtrip(tmp_dir: Path):
    key = generate_key()
    # 1) невеликий текстовий файл
    txt_path = tmp_dir / "test_text.txt"
    txt_data = "Це тестовий файл UTF-8.\nРядок 2.\n".encode("utf-8")
    txt_path.write_bytes(txt_data)

    ct = sm4_encrypt_ecb(txt_data, key)
    pt = sm4_decrypt_ecb(ct, key)
    assert pt == txt_data, "file text roundtrip failed"

    # 2) псевдо-бінарний файл (байти 0..255 * 4)
    bin_path = tmp_dir / "test_bin.bin"
    bin_data = bytes(range(256)) * 4
    bin_path.write_bytes(bin_data)

    ct = sm4_encrypt_ecb(bin_data, key)
    pt = sm4_decrypt_ecb(ct, key)
    assert pt == bin_data, "file binary roundtrip failed"


# ---------- 5. Негативні тести ----------

def test_wrong_key():
    key1 = generate_key()
    key2 = generate_key()
    data = b"Test data for wrong key"

    ct = sm4_encrypt_ecb(data, key1)

    try:
        pt = sm4_decrypt_ecb(ct, key2)
    except Exception:
        # очікувана поведінка: виняток через некоректне PKCS#7
        return

    # Якщо винятку не було, перевіряємо, що дані НЕ співпадають
    assert pt != data, "Розшифрування з неправильним ключем не повинно давати вихідний текст"


def test_truncated_ciphertext():
    key = generate_key()
    data = b"Some data"
    ct = sm4_encrypt_ecb(data, key)

    truncated = ct[:-5]  # обрізаємо

    try:
        sm4_decrypt_ecb(truncated, key)
    except Exception:
        # очікувано помилка
        return

    assert False, "Обрізаний шифртекст має викликати помилку"


# ---------- Запуск усіх тестів ----------

def run_all():
    print("Running test_vector_1 ...")
    test_vector_1()
    print("OK")

    print("Running test_vector_2 ...")
    test_vector_2()
    print("OK")

    print("Running million-iteration test (може зайняти час) ...")
    test_million_iterations()
    print("OK")

    print("Running text roundtrip tests ...")
    test_text_roundtrip()
    print("OK")

    tmp_dir = Path("sm4_test_tmp")
    tmp_dir.mkdir(exist_ok=True)
    print("Running file roundtrip tests ...")
    test_file_roundtrip(tmp_dir)
    print("OK")

    print("Running negative tests ...")
    test_wrong_key()
    test_truncated_ciphertext()
    print("OK")

    print("\n✅ УСІ ТЕСТИ ПРОЙДЕНІ УСПІШНО.")


if __name__ == "__main__":
    run_all()

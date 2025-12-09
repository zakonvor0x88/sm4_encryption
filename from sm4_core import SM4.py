from sm4_core import SM4

def test_vector_1():
    key_hex = "0123456789ABCDEFFEDCBA9876543210"
    pt_hex  = "0123456789ABCDEFFEDCBA9876543210"
    exp_ct  = "681EDF34D206965E86B3E94F536E4246"

    key = bytes.fromhex(key_hex)
    pt  = bytes.fromhex(pt_hex)

    cipher = SM4(key)
    ct = cipher.encrypt_block(pt)

    print("TV1 CT =", ct.hex())
    assert ct.hex().upper() == exp_ct, "TV1 FAILED"
    print("TV1 OK")

def test_vector_2():
    # З IETF/OpenSSL
    key_hex = "FEDCBA98765432100123456789ABCDEF"
    pt_hex  = "000102030405060708090A0B0C0D0E0F"
    exp_ct  = "F766678F13F01ADEAC1B3EA955ADB594"

    key = bytes.fromhex(key_hex)
    pt  = bytes.fromhex(pt_hex)

    cipher = SM4(key)
    ct = cipher.encrypt_block(pt)

    print("TV2 CT =", ct.hex())
    assert ct.hex().upper() == exp_ct, "TV2 FAILED"
    print("TV2 OK")

if __name__ == "__main__":
    test_vector_1()
    test_vector_2()
    print("All single-block tests passed.")
def test_encrypt_decrypt_block():
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    cipher = SM4(key)

    pt = b"ExampleBlock123"  # рівно 16 байт
    ct = cipher.encrypt_block(pt)
    dec = cipher.decrypt_block(ct)

    assert dec == pt, "Block decrypt mismatch"
    print("Block encrypt/decrypt OK")
def million_iter_test():
    key_hex = "0123456789ABCDEFFEDCBA9876543210"
    pt_hex  = "0123456789ABCDEFFEDCBA9876543210"
    expected = "595298C7C6FD271F0402F804C33D3F66"

    key = bytes.fromhex(key_hex)
    block = bytes.fromhex(pt_hex)
    cipher = SM4(key)

    for _ in range(1_000_000):
        block = cipher.encrypt_block(block)

    print("Million CT =", block.hex())
    assert block.hex().upper() == expected, "Million-iteration FAILED"
    print("Million-iteration test OK")

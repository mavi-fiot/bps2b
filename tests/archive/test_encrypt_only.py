# tests/test_encrypt_only.py

import time
from crypto.curves import generate_keypair
from crypto.encrypt_phase import encrypt_personalized_hash
from crypto.decrypt_phase import decrypt_and_verify

def test_encrypt_only():
    ballot_text = "Затвердити звіт за 2024 рік"
    voter_id = "voter_001"

    # Генерація ключових пар для серверу та секретаря
    server_priv, server_pub = generate_keypair()
    secretary_priv, secretary_pub = generate_keypair()

    # 1️ Шифрування точки (персоналізоване повідомлення)
    t1 = time.perf_counter()
    result = encrypt_personalized_hash(
        ballot_text=ballot_text,
        voter_id=voter_id,
        server_pub=server_pub,
        secretary_pub=secretary_pub
    )
    encrypt_time = (time.perf_counter() - t1) * 1000

    assert "encrypted_for_server" in result
    assert "encrypted_for_secretary" in result

    # 2️ Розшифрування обома ключами та перевірка відповідності
    t2 = time.perf_counter()
    decrypted = decrypt_and_verify(
        encrypted=result,
        server_priv=server_priv,
        secretary_priv=secretary_priv
    )
    decrypt_time = (time.perf_counter() - t2) * 1000

    assert decrypted["match"] is True

    print("\n--- Тест без підпису (тільки шифрування точки) ---")
    print(f" Шифрування: {encrypt_time:.2f} ms")
    print(f" Розшифрування та перевірка: {decrypt_time:.2f} ms")

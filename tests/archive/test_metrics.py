# tests/test_metrics.py

import time
from crypto.curves import generate_keypair
from crypto.encrypt_phase import encrypt_personalized_hash
from crypto.signature_phase import sign_vote, verify_vote_signature

def test_crypto_metrics():
    ballot_text = "Затвердити звіт за 2024 рік"
    voter_id = "voter_001"

    # Генерація ключів
    t0 = time.perf_counter()
    server_priv, server_pub = generate_keypair()
    secretary_priv, secretary_pub = generate_keypair()
    voter_priv, voter_pub = generate_keypair()
    keygen_time = (time.perf_counter() - t0) * 1000

    # Етап 1 — шифрування
    t1 = time.perf_counter()
    result = encrypt_personalized_hash(ballot_text, voter_id, server_pub, secretary_pub)
    encrypt_time = (time.perf_counter() - t1) * 1000

    # Етап 2 — підпис
    t2 = time.perf_counter()
    signed = sign_vote(ballot_text, voter_id, voter_priv)
    signature_time = (time.perf_counter() - t2) * 1000

    # Етап 3 — перевірка
    t3 = time.perf_counter()
    valid = verify_vote_signature(ballot_text, voter_id, signed["signature"], voter_pub)
    verify_time = (time.perf_counter() - t3) * 1000

    # Перевірки
    assert valid
    assert isinstance(result["encrypted_for_server"], tuple)
    assert isinstance(signed["signature"], tuple)

    print("\n--- МЕТРИКИ ---")
    print(f"time - Генерація ключів:      {keygen_time:.2f} ms")
    print(f"Secret - Шифрування гешу:       {encrypt_time:.2f} ms")
    print(f"Sighn  - Підпис повідомлення:   {signature_time:.2f} ms")
    print(f"Check - Перевірка підпису:     {verify_time:.2f} ms")

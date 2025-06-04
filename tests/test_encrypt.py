# tests/test_encrypt.py

from crypto.encrypt_phase import encrypt_personalized_hash
from crypto.curves import generate_keypair

def test_encrypt_personalized_hash():
    ballot_text = "Затвердити звіт за 2024 рік"
    voter_id = "voter_001"

    # Генеруємо пари публічних ключів для сервера та секретаря
    server_priv, server_pub = generate_keypair()
    secretary_priv, secretary_pub = generate_keypair()

    # Викликаємо функцію шифрування
    result = encrypt_personalized_hash(
        ballot_text=ballot_text,
        voter_id=voter_id,
        server_pub=server_pub,
        secretary_pub=secretary_pub
    )

    # Перевірка ключових значень у результаті
    assert "base_hash" in result
    assert "personalized_hash" in result
    assert "encrypted_for_server" in result
    assert "encrypted_for_secretary" in result

    # Перевірка типів
    assert isinstance(result["encrypted_for_server"], tuple)
    assert isinstance(result["encrypted_for_secretary"], tuple)
    assert result["encrypted_for_server"] != result["encrypted_for_secretary"]  # мають бути різні

    print("+ test_encrypt_personalized_hash пройдено")

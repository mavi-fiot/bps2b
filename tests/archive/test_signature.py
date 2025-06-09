# tests/test_signature.py

from crypto.signature_phase import sign_vote, verify_vote_signature
from crypto.curves import generate_keypair

def test_sign_and_verify_vote():
    ballot_text = "Затвердити звіт за 2024 рік"
    voter_id = "voter_001"

    # Генеруємо ключову пару для виборця
    voter_priv, voter_pub = generate_keypair()

    # Підписуємо персоналізований геш
    signed = sign_vote(
        ballot_text=ballot_text,
        voter_id=voter_id,
        voter_priv=voter_priv
    )

    # Перевіряємо наявність ключів
    assert "personalized_hash" in signed
    assert "signature" in signed

    # Перевіряємо тип підпису
    assert isinstance(signed["signature"], tuple)
    assert len(signed["signature"]) == 2

    # Валідуємо підпис
    valid = verify_vote_signature(
        ballot_text=ballot_text,
        voter_id=voter_id,
        signature=signed["signature"],
        voter_pub=voter_pub
    )

    assert valid is True

    print("+ test_sign_and_verify_vote пройдено")

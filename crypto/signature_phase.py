# crypto/signature_phase.py

from ecpy.curves import Curve, Point
from hashlib import sha3_256
import secrets
import json

# Крива Ed25519
curve = Curve.get_curve("Ed25519")
G = curve.generator
q = curve.order

# Фіксований текст рішення
BALLOT_TEXT = "Затвердити звіт за 2024 рік"

# Генерація ключів виборця
def generate_voter_keypair():
    priv = secrets.randbelow(q)
    pub = priv * G
    return priv, pub

# Хешування бюлетеня + ID
def hash_personalized(text: str, voter_id: str) -> int:
    digest = sha3_256((text + voter_id).encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big") % q

# Підпис: h * (priv * G)
def sign_hash(hash_scalar: int, private_key: int) -> Point:
    public_key = private_key * G
    return hash_scalar * public_key

# Перевірка: h * P == S
def verify_signature(hash_scalar: int, signature: Point, public_key: Point) -> bool:
    expected = hash_scalar * public_key
    return signature == expected

# Демонстрація підпису та перевірки
def demo_sign_and_verify(voter_id: str):
    priv, pub = generate_voter_keypair()
    h = hash_personalized(BALLOT_TEXT, voter_id)
    S = sign_hash(h, priv)
    valid = verify_signature(h, S, pub)

    return {
        "voter_id": voter_id,
        "hash_scalar": h,
        "signature": {"x": S.x, "y": S.y},
        "public_key": {"x": pub.x, "y": pub.y},
        "valid_signature": valid
    }

# При запуску напряму
if __name__ == "__main__":
    result = demo_sign_and_verify("demo-voter")
    print(json.dumps(result, indent=2))

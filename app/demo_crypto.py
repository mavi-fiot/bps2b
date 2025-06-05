# app/demo_crypto.py 

from fastapi import APIRouter
from ecpy.curves import Curve, Point
from pydantic import BaseModel
import secrets

from crypto.hash_util import hash_ballot, hash_to_point
from crypto.encryption import elgamal_encrypt_point, decrypt_ciphertext
from kzp.crypto_logic import get_server_keys, get_secretary_keys

router = APIRouter(prefix="/demo", tags=["Crypto Demo"])

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 📥 Вхідна модель
class DemoEncryptRequest(BaseModel):
    voter_id: str = "demo-voter"
    choice: str = "За"
    decision_text: str = "Затвердити річний звіт Товариства за 2024 рік"

# Класичне послідовне шифрування точки (сервер → секретар)
@router.post("/encrypt_step", summary="Хеш → Точка → Подвійне ElGamal")
def encrypt_step(data: DemoEncryptRequest):
    server_priv, server_pub = get_server_keys()
    secretary_priv, secretary_pub = get_secretary_keys()
    voter_priv = secrets.randbelow(q)
    voter_pub = voter_priv * G

    ballot_text = f"З питання порядку денного за проектом рішення: {data.decision_text} - голосую {data.choice}"
    hash_scalar = hash_ballot(ballot_text + data.voter_id)
    point_M = hash_scalar * G

    # Спочатку шифрує точку M ключом серверу
    C1_srv, C2_srv = elgamal_encrypt_point(point_M, server_pub)

    # Потім шифрує результат C2_srv ключом секретаря
    C1_sec, C2_sec = elgamal_encrypt_point(C2_srv, secretary_pub)

    # Дешифрування в зворотному порядку
    decrypted_after_sec = decrypt_ciphertext(C1_sec, C2_sec, secretary_priv)
    decrypted_after_srv = decrypt_ciphertext(C1_srv, decrypted_after_sec, server_priv)

    match = decrypted_after_srv == point_M

    return {
    "voter": {
        "private": str(voter_priv),
        "public": {"x": str(voter_pub.x), "y": str(voter_pub.y)}
    },
    "server_pub": {"x": str(server_pub.x), "y": str(server_pub.y)},
    "secretary_pub": {"x": str(secretary_pub.x), "y": str(secretary_pub.y)},
    "ballot_text": ballot_text,
    "hash_scalar": str(hash_scalar),
    "point_M": {"x": str(point_M.x), "y": str(point_M.y)},
    "C1_srv": {"x": str(C1_srv.x), "y": str(C1_srv.y)},
    "C2_srv": {"x": str(C2_srv.x), "y": str(C2_srv.y)},
    "C1_sec": {"x": str(C1_sec.x), "y": str(C1_sec.y)},
    "C2_sec": {"x": str(C2_sec.x), "y": str(C2_sec.y)},
    "decrypted_point": {"x": str(decrypted_after_srv.x), "y": str(decrypted_after_srv.y)},
    "match_original": match,
    "server_keys": {
        "private": str(server_priv),
        "public": {"x": str(server_pub.x), "y": str(server_pub.y)}
    },
    "secretary_keys": {
        "private": str(secretary_priv),
        "public": {"x": str(secretary_pub.x), "y": str(secretary_pub.y)}
    },
}


# Альтернативне незалежне шифрування для демонстрації
class EncryptStepRequest(BaseModel):
    voter_id: str
    choice: str
    decision_text: str

@router.post("/encrypt_step_alt", summary="Повідомлення → Точка → Паралельне ElGamal")
def encrypt_step_alt(data: EncryptStepRequest):
    server_priv = secrets.randbelow(q)
    server_pub = server_priv * G

    secretary_priv = secrets.randbelow(q)
    secretary_pub = secretary_priv * G

    voter_priv = secrets.randbelow(q)
    voter_pub = voter_priv * G

    message = f"{data.decision_text} - голосую {data.choice} (ID: {data.voter_id})"
    point_M = hash_to_point(message)

    # Відкритими ключами серверу та секретаря незалежно шифрується точка M
    C1_srv, C2_srv = elgamal_encrypt_point(point_M, server_pub)
    C1_sec, C2_sec = elgamal_encrypt_point(point_M, secretary_pub)

    # Перевірка: кожна сторона розшифровує самостійно
    decrypted_srv = decrypt_ciphertext(C1_srv, C2_srv, server_priv)
    decrypted_sec = decrypt_ciphertext(C1_sec, C2_sec, secretary_priv)

    return {
    "server_keys": {
        "private": str(server_priv),
        "public": {
            "x": str(server_pub.x),
            "y": str(server_pub.y)
        }
    },
    "secretary_keys": {
        "private": str(secretary_priv),
        "public": {
            "x": str(secretary_pub.x),
            "y": str(secretary_pub.y)
        }
    },
    "voter_keys": {
        "private": str(voter_priv),
        "public": {
            "x": str(voter_pub.x),
            "y": str(voter_pub.y)
        }
    },
    "message": message,
    "hash_point": {
        "x": str(point_M.x),
        "y": str(point_M.y)
    },
    "elgamal_server": {
        "C1": {"x": str(C1_srv.x), "y": str(C1_srv.y)},
        "C2": {"x": str(C2_srv.x), "y": str(C2_srv.y)},
        "decrypted": {"x": str(decrypted_srv.x), "y": str(decrypted_srv.y)},
        "match": decrypted_srv == point_M
    },
    "elgamal_secretary": {
        "C1": {"x": str(C1_sec.x), "y": str(C1_sec.y)},
        "C2": {"x": str(C2_sec.x), "y": str(C2_sec.y)},
        "decrypted": {"x": str(decrypted_sec.x), "y": str(decrypted_sec.y)},
        "match": decrypted_sec == point_M
    }
}


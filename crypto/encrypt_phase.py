# crypto/encrypt_phase.py

from ecpy.curves import Curve, Point
from hashlib import sha3_512
import secrets
import json

# Отримання кривої Ed25519
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Текст рішення
BALLOT_TEXT = "Затвердити звіт за 2024 рік"

# Генерація ключів серверу та секретаря
def generate_keypair():
    priv = secrets.randbelow(q)
    pub = priv * G
    return priv, pub

server_priv, server_pub = generate_keypair()
secretary_priv, secretary_pub = generate_keypair()

# Хешування персоналізованого повідомлення
def hash_personalized(ballot_text: str, voter_id: str) -> int:
    msg = ballot_text + voter_id
    digest = sha3_512(msg.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big") % q

# ElGamal шифрування для точки M = h * G
def encrypt_point(hash_scalar: int, pub_key: Point):
    r = secrets.randbelow(q)
    M = hash_scalar * G
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2, M

# Демонстраційна функція
def demo_encrypt(voter_id: str):
    h = hash_personalized(BALLOT_TEXT, voter_id)

    C1_srv, C2_srv, M1 = encrypt_point(h, server_pub)
    C1_sec, C2_sec, _ = encrypt_point(h, secretary_pub)

    return {
        "voter_id": voter_id,
        "hash_scalar": h,
        "original_point": {"x": M1.x, "y": M1.y},
        "server_encryption": {
            "C1": {"x": C1_srv.x, "y": C1_srv.y},
            "C2": {"x": C2_srv.x, "y": C2_srv.y}
        },
        "secretary_encryption": {
            "C1": {"x": C1_sec.x, "y": C1_sec.y},
            "C2": {"x": C2_sec.x, "y": C2_sec.y}
        },
        "public_keys": {
            "server": {"x": server_pub.x, "y": server_pub.y},
            "secretary": {"x": secretary_pub.x, "y": secretary_pub.y}
        }
    }

# Якщо виконується напряму
if __name__ == "__main__":
    import time

    #  Вимірювання часу генерації ключів
    t0 = time.time()
    server_priv, server_pub = generate_keypair()
    secretary_priv, secretary_pub = generate_keypair()
    t1 = time.time()

    keygen_time_ms = (t1 - t0) * 1000
    print(f"time Час генерації ключів (ElGamal, Ed25519): {keygen_time_ms:.2f} ms")

    # Демонстрація шифрування
    result = demo_encrypt("demo-voter")
    print(json.dumps(result, indent=2))

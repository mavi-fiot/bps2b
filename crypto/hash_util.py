# crypto/hash_util.py

from ecpy.curves import Curve, Point
import secrets
import hashlib

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

print(f"_/ Крива: {curve.name}")
print(f"+ Порядок q = {q}")

# Генерація ключів для демонстрації
priv_key = secrets.randbelow(q)
pub_key = priv_key * G

print(f"Приватний ключ: {priv_key}")
print(f"Публічний ключ: ({pub_key.x}, {pub_key.y})")

# Повідомлення для демонстрації
message = 'З питання першого порядку денного за проектом рішення: Затвердити річний звіт Товариства за 2024 рік - голосую За (демонстрація)'
print(f"\n Повідомлення: {message}")

# Хешування
hash_scalar = int.from_bytes(hashlib.sha3_512(message.encode()).digest(), 'big') % q
M = hash_scalar * G
print(f"Хеш як скаляр: {hash_scalar}")
print(f"Повідомлення як точка M: ({M.x}, {M.y})")

# Шифрування (ElGamal)
r = secrets.randbelow(q)
C1 = r * G
C2 = M + r * pub_key

print(f"\n Шифрування ElGamal:")
print(f"• C1 = r * G = ({C1.x}, {C1.y})")
print(f"• C2 = M + r * B = ({C2.x}, {C2.y})")

# Розшифрування
S = priv_key * C1
M_decrypted = C2 - S

print(f"\nРозшифровано точку M: ({M_decrypted.x}, {M_decrypted.y})")

# Перевірка відповідності
M_check = hash_scalar * G
is_valid = M_check == M_decrypted
print(f"\n Перевірка відповідності: {'успішна' if is_valid else 'ХХХ неуспішна'}")

# === Утиліти ===

def hash_ballot(ballot_text: str) -> int:
    h = hashlib.sha3_512(ballot_text.encode()).digest()
    return int.from_bytes(h, 'big') % q

def hash_to_point(message: str) -> Point:
    hash_scalar = int.from_bytes(hashlib.sha3_512(message.encode()).digest(), 'big') % q
    return hash_scalar * G

def safe_point(x: str | int, y: str | int, label: str = "") -> Point:
    curve = Curve.get_curve("Ed25519")
    try:
        px = int(x)
        py = int(y)
        point = Point(px, py, curve)
        print(f"  {label or 'Точка'}: ({point.x}, {point.y})")
        return point
    except Exception as e:
        raise ValueError(f"Х Помилка при створенні точки {label}: {e}")

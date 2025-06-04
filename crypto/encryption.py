# crypto/encryption.py
# Реалізація шифрування та розшифрування хешу бюлетеня на кривій Едвардса (Ed25519)

from ecpy.curves import Curve, Point
import secrets

# Ініціалізація кривої
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

def encrypt_hash(hash_scalar: int, pub_key: Point) -> tuple[Point, Point]:
    """
    ElGamal-шифрування хешу: M = hash_scalar * G
    Повертає пару (C1, C2)
    """
    M = hash_scalar * G
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

def decrypt_ciphertext(C1: Point, C2: Point, priv_key: int) -> Point:
    """
    Розшифровує зашифровану точку ElGamal
    """
    S = priv_key * C1
    M_decrypted = C2 - S
    return M_decrypted

def verify_decrypted_point(M_decrypted: Point, hash_scalar: int) -> bool:
    """
    Порівнює розшифровану точку з очікуваним результатом
    """
    M_expected = hash_scalar * G
    return M_decrypted == M_expected

elgamal_encrypt = encrypt_hash
elgamal_decrypt = decrypt_ciphertext

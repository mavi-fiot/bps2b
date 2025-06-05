# crypto/encryption.py
# Реалізація шифрування та розшифрування точки (Point) на кривій Едвардса (Ed25519)

from ecpy.curves import Curve, Point
import secrets

# Ініціалізація кривої
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

def elgamal_encrypt_point(M: Point, pub_key: Point) -> tuple[Point, Point]:
    """
    ElGamal-шифрування точки M
    Повертає пару (C1, C2), де:
    - C1 = r * G
    - C2 = M + r * pub_key
    """
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

def decrypt_ciphertext(C1: Point, C2: Point, priv_key: int) -> Point:
    """
    Розшифровує зашифровану точку ElGamal
    M = C2 - priv * C1
    """
    S = priv_key * C1
    M_decrypted = C2 - S
    return M_decrypted

def verify_decrypted_point(M_decrypted: Point, original_point: Point) -> bool:
    """
    Порівнює розшифровану точку з очікуваною (оригінальною)
    """
    return M_decrypted == original_point

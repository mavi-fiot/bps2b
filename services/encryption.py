from ecpy.curves import Curve, Point
import secrets

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# ElGamal шифрування точки

def elgamal_encrypt(M: Point, pub_key: Point) -> tuple[Point, Point]:
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

# ElGamal розшифрування точки

def elgamal_decrypt(C1: Point, C2: Point, priv_key: int) -> Point:
    S = priv_key * C1
    M = C2 - S
    return M

# crypto/curves.py

from ecpy.curves import Curve, Point
import secrets

# Отримуємо криву Ed25519
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

def generate_private_key() -> int:
    """Генерує випадковий приватний ключ (скаляр)"""
    return secrets.randbelow(q)

def generate_keypair():
    """Генерує пару (private, public) ключів"""
    priv = generate_private_key()
    pub = priv * G
    return priv, pub

def get_curve():
    """Повертає об'єкт кривої"""
    return curve

def get_generator():
    """Повертає базову точку кривої"""
    return G

def get_order():
    """Повертає порядок групи"""
    return q

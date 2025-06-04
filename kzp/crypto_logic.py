# kzp/crypto_logic.py

from ecpy.curves import Curve, Point
import secrets

# Ініціалізація кривої Ed25519
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 🔐 Приватні та публічні ключі сервера
_server_priv = secrets.randbelow(q)
_server_pub = _server_priv * G

# 🔐 Приватні та публічні ключі секретаря
_secretary_priv = secrets.randbelow(q)
_secretary_pub = _secretary_priv * G

# 📤 Доступ до параметрів кривої
def get_curve_params():
    return curve, G, q

# 📤 Ключі сервера
def get_server_keys():
    return _server_priv, _server_pub

# 📤 Ключі секретаря
def get_secretary_keys():
    return _secretary_priv, _secretary_pub



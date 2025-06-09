# sign_log.py

from ecpy.curves import Curve, Point
import hashlib, secrets

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Зчитування лог-файлу
with open("vote_verification.log", "rb") as f:
    log_content = f.read()

log_hash = hashlib.sha3_512(log_content).digest()
log_scalar = int.from_bytes(log_hash, byteorder='big') % q
log_point = log_scalar * G

# Генерація ключів
server_priv = secrets.randbelow(q)
secretary_priv = secrets.randbelow(q)

server_pub = server_priv * G
secretary_pub = secretary_priv * G

# Підписання
server_sig = server_priv * log_point
secretary_sig = secretary_priv * log_point

# Вивід
print("\nГеш лог-файлу:", log_scalar)
print("\nPoint Точка лог-файлу:", (log_point.x, log_point.y))
print("\nKey_serv Ключ серверу (публічний):", (server_pub.x, server_pub.y))
print("\nSign_serv Підпис серверу:", (server_sig.x, server_sig.y))
print("\nKey_Secretar Ключ секретаря (публічний):", (secretary_pub.x, secretary_pub.y))
print("\nSign_Secretar Підпис секретаря:", (secretary_sig.x, secretary_sig.y))

#sign_log_with_excel.py

import hashlib, secrets, re
from datetime import datetime
from ecpy.curves import Curve, Point
import pandas as pd
from app.utils.message_builder import base_text as for_voting

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# === Функція: отримати точку з повідомлення (виборець + текст голосу) ===
def hash_message_to_point(message: str) -> Point:
    digest = hashlib.sha3_512(message.encode()).digest()
    scalar = int.from_bytes(digest, byteorder='big') % q
    return scalar * G

# === Зчитування лог-файлу для хешування ===
with open("vote_verification.log", "rb") as f:
    log_content = f.read()

log_hash = hashlib.sha3_512(log_content).digest()
log_scalar = int.from_bytes(log_hash, byteorder='big') % q
log_point = log_scalar * G

# === Ключі ===
server_priv = secrets.randbelow(q)
secretary_priv = secrets.randbelow(q)
server_pub = server_priv * G
secretary_pub = secretary_priv * G
server_sig = server_priv * log_point
secretary_sig = secretary_priv * log_point

# === Поточна мітка часу ===
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

# === Додати новий заголовок ===
header = (
    "\n\n================= ПРОТОКОЛ ГОЛОСУВАННЯ =================\n"
    f"Питання, що розглянуто: {for_voting}\n"
    f"Мітка часу формування: {timestamp}\n"
    "========================================================\n"
)

with open("vote_verification.log", "a", encoding="utf-8") as f:
    f.write(header)

# === Додати підпис протоколу ===
with open("vote_verification.log", "a", encoding="utf-8") as f:
    f.write(f"\n\n==== ПІДПИС ПРОТОКОЛУ ({timestamp}) ====\n")
    f.write(f"  Хеш лог-файлу: {log_scalar}\n")
    f.write(f"  Підпис серверу: ({server_sig.x}, {server_sig.y})\n")
    f.write(f"  Підпис секретаря: ({secretary_sig.x}, {secretary_sig.y})\n")

# === Аналіз лог-файлу для точок і виборців ===
with open("vote_verification.log", "r", encoding="utf-8") as f:
    log_text = f.read()

# Регулярки для парсингу
entries = re.findall(
    r"ID учасника: (\w+)\s+.*?ballot_id\): (\d+).*?Відтворення точки: \(([\dNone]+), ([\dNone]+)\)",
    log_text,
    re.DOTALL
)

rows = []
for voter_id, ballot_hash, x_str, y_str in entries:
    message = f"{for_voting}_{voter_id}"
    point = hash_message_to_point(message)

    try:
        x_logged = int(x_str) if x_str != "None" else None
        y_logged = int(y_str) if y_str != "None" else None
        match = (x_logged == point.x and y_logged == point.y)
    except Exception:
        x_logged, y_logged, match = None, None, False

    rows.append({
        "voter_id": voter_id,
        "message": message,
        "hash_scalar": ballot_hash,
        "expected_x": point.x,
        "expected_y": point.y,
        "logged_x": x_logged,
        "logged_y": y_logged,
        "match": match
    })

# === Запис результатів у Excel ===
df = pd.DataFrame(rows)
with pd.ExcelWriter("votes_export.xlsx", mode='a', engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name=f"verify_{timestamp}", index=False)

print("✅ Протокол створено, підписано і проаналізовано.")


# import hashlib, secrets
# from datetime import datetime
# from ecpy.curves import Curve, Point
# import pandas as pd
# from app.utils.message_builder import base_text as for_voting

# curve = Curve.get_curve('Ed25519')
# G = curve.generator
# q = curve.order

# # === Зчитування лог-файлу ===
# with open("vote_verification.log", "rb") as f:
#     log_content = f.read()

# # === Хешування лог-файлу ===
# log_hash = hashlib.sha3_256(log_content).digest()
# log_scalar = int.from_bytes(log_hash, byteorder='big') % q
# log_point = log_scalar * G

# # === Ключі (імітовані) ===
# server_priv = secrets.randbelow(q)
# secretary_priv = secrets.randbelow(q)
# server_pub = server_priv * G
# secretary_pub = secretary_priv * G

# # === Підпис ===
# server_sig = server_priv * log_point
# secretary_sig = secretary_priv * log_point

# # === Мітка часу ===
# timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

# # === Додати заголовок протоколу ===
# header = (
#     "================= ПРОТОКОЛ ГОЛОСУВАННЯ =================\n"
#     f"Питання, що розглянуто: {for_voting}\n"
#     f"Мітка часу формування: {timestamp}\n"
#     "========================================================\n\n"
# )

# with open("vote_verification.log", "r", encoding="utf-8") as f:
#     old_content = f.read()

# with open("vote_verification.log", "w", encoding="utf-8") as f:
#     f.write(header + old_content)

# # === Додати до лог-файлу підпис ===
# with open("vote_verification.log", "a", encoding="utf-8") as f:
#     f.write(f"\n\n==== ПІДПИС ПРОТОКОЛУ ({timestamp}) ====\n")
#     f.write(f"  Хеш лог-файлу: {log_scalar}\n")
#     f.write(f"  Підпис серверу: ({server_sig.x}, {server_sig.y})\n")
#     f.write(f"  Підпис секретаря: ({secretary_sig.x}, {secretary_sig.y})\n")

# # === Експорт у новий аркуш Excel ===
# data = [
#     ["timestamp", timestamp],
#     ["log_hash", str(log_scalar)],
#     ["log_point_x", str(log_point.x)],
#     ["log_point_y", str(log_point.y)],
#     ["server_pub_x", str(server_pub.x)],
#     ["server_pub_y", str(server_pub.y)],
#     ["server_sig_x", str(server_sig.x)],
#     ["server_sig_y", str(server_sig.y)],
#     ["secretary_pub_x", str(secretary_pub.x)],
#     ["secretary_pub_y", str(secretary_pub.y)],
#     ["secretary_sig_x", str(secretary_sig.x)],
#     ["secretary_sig_y", str(secretary_sig.y)]
# ]

# df = pd.DataFrame(data, columns=["Field", "Value"])

# with pd.ExcelWriter("votes_export.xlsx", mode='a', engine='openpyxl') as writer:
#     df.to_excel(writer, sheet_name=f"sign_{timestamp}", index=False)

# print("Протокол голосування створено та підписано.")

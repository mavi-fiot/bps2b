# scripts/verify_and_sign_votes.py

import hashlib, secrets, logging, sys, warnings
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pandas as pd
from ecpy.curves import Curve, Point
from models.vote_record import VoteRecord
from crypto.hash_util import hash_ballot
from crypto.signature import verify_signature
from app.utils.message_builder import get_personalized_message
from app.utils.message_builder import base_text as for_voting
from hashlib import sha3_512 as HASH_FUNC


# Крива
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Генеруємо ключі
server_priv = secrets.randbelow(q)
secretary_priv = secrets.randbelow(q)
server_pub = server_priv * G
secretary_pub = secretary_priv * G

# Очистка попередніх логгерів
for h in logging.root.handlers[:]:
    logging.root.removeHandler(h)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler("vote_verification.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

warnings.filterwarnings("ignore")

# Підключення до БД
backup_db_path = "C:/Users/scrib/OneDrive/diplom/ptoject/iseg4.db"
engine = create_engine(f"sqlite:///{backup_db_path}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
session = Session()

votes = session.query(VoteRecord).all()

# === Заголовок лог-файлу ===
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
base_text = for_voting

header = (
    "================= ПРОТОКОЛ ГОЛОСУВАННЯ =================\n"
    f"Питання, що розглянуто: {base_text}\n"
    f"Мітка часу формування: {timestamp}\n"
    "========================================================\n"
)
logging.info(header)

data = []
summary = {"За": 0, "Проти": 0, "Утримався": 0}
verified_count = 0

for v in votes:
    # 1. Персоналізоване повідомлення
    personalized_message = f"{for_voting} - {v.choice} - {v.voter_id}"
    #За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік — За — voter
    # 2. Хеш з повідомлення → точка
    digest = HASH_FUNC(personalized_message.encode()).digest()
    hash_scalar_msg = int.from_bytes(digest, "big") % q
    point_from_msg = hash_scalar_msg * G

    # 3. Хеш, що був у базі
    recomputed_hash = hash_ballot(personalized_message)
    hash_match = (str(recomputed_hash) == v.hash_plain)

    try:
        sig_point = Point(int(v.sig_x), int(v.sig_y), curve)
        pub_point = Point(int(v.pub_x), int(v.pub_y), curve)

        # Точка з геша, що зберігалась до завершення голосування
        decrypted_point = recomputed_hash * G
        point_match = (sig_point.x == decrypted_point.x and sig_point.y == decrypted_point.y)
        signature_valid = verify_signature(recomputed_hash, sig_point, pub_point)

        # Додаткова перевірка підпису саме для точки з повідомлення
        alt_signature_valid = verify_signature(hash_scalar_msg, sig_point, pub_point)

    except Exception as e:
        decrypted_point = None
        signature_valid = False
        point_match = False
        alt_signature_valid = False

    if signature_valid:
        summary[v.choice] += 1
        verified_count += 1

    # === Вивід у лог ===
    logging.info(f"\n _________Контроль на сервері:")
    logging.info(f"  ID учасника: {v.voter_id}")
    logging.info(f"  Публічний ключ: ({v.pub_x}, {v.pub_y})")
    logging.info(f"  Геш (ballot_id): {recomputed_hash}")
    logging.info(f"  Очікувана точка (до голосування): ({decrypted_point.x if decrypted_point else 'н/д'}, {decrypted_point.y if decrypted_point else 'н/д'})")
    logging.info(f"  Відтворена точка з повідомлення: ({point_from_msg.x}, {point_from_msg.y})")
    logging.info(f"  Підписана точка: ({v.sig_x}, {v.sig_y})")
    logging.info(f"  Підпис валідний (по гешу з БД): {signature_valid}")
    logging.info(f"  Підпис валідний (по гешу з повідомлення): {alt_signature_valid}")

    data.append({
        "voter_id": v.voter_id,
        "choice": v.choice,
        "hash_plain": v.hash_plain,
        "sig_valid_dbhash": signature_valid,
        "sig_valid_msg": alt_signature_valid,
        "point_match": point_match
    })
# === Підпис протоколу ===
with open("vote_verification.log", "rb") as f:
    log_bytes = f.read()

log_hash = hashlib.sha3_512(log_bytes).digest()
log_scalar = int.from_bytes(log_hash, "big") % q
log_point = log_scalar * G
server_sig = server_priv * log_point
secretary_sig = secretary_priv * log_point

logging.info(f"\n\n==== ПІДПИС ПРОТОКОЛУ ({timestamp}) ====")
logging.info(f"  Геш лог-файлу: {log_scalar}")
logging.info(f"  Підпис серверу: ({server_sig.x}, {server_sig.y})")
logging.info(f"  Підпис секретаря: ({secretary_sig.x}, {secretary_sig.y})")

# === Підсумки голосування ===
total = len(votes)
real_votes = verified_count - summary["Утримався"]
decision = "ПРИЙНЯТО" if summary["За"] > real_votes / 2 else "НЕ ПРИЙНЯТО"

summary_data = [
    ["Отримано бюлетенів", total],
    ["Верифіковані бюлетені", verified_count],
    ["За", summary["За"]],
    ["Проти", summary["Проти"]],
    ["Утримались", summary["Утримався"]],
    ["Рішення", decision]
]

# === Збереження Excel ===
df_main = pd.DataFrame(data)
df_sign = pd.DataFrame([
    ["timestamp", timestamp],
    ["log_hash", str(log_scalar)],
    ["server_sig_x", str(server_sig.x)],
    ["server_sig_y", str(server_sig.y)],
    ["secretary_sig_x", str(secretary_sig.x)],
    ["secretary_sig_y", str(secretary_sig.y)],
], columns=["Field", "Value"])

df_summary = pd.DataFrame(summary_data, columns=["Параметр", "Значення"])

with pd.ExcelWriter("votes_export.xlsx", engine="openpyxl", mode="w") as writer:
    df_sign.to_excel(writer, sheet_name=f"sign_{timestamp}", index=False)
    df_summary.to_excel(writer, sheet_name=f"summary_{timestamp}", index=False)

print("\n\nПротокол створено, підписано, експортовано у 'votes_export.xlsx' і 'vote_verification.log'\n\n")

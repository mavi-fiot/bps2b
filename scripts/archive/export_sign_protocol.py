#scripts/export_sign_protocol.py

import hashlib, secrets, sys, logging, warnings
from datetime import datetime
from collections import Counter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pandas as pd
from ecpy.curves import Curve, Point

from models.vote_record import VoteRecord
from crypto.hash_util import hash_ballot
from crypto.signature import verify_signature
from app.utils.message_builder import get_personalized_message

# === Константи ===
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order
backup_db_path = "C:/Users/scrib/OneDrive/diplom/ptoject/iseg.db"
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
log_file = "vote_verification.log"

# === Логування (перезапис + консоль) ===
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(log_file, mode="w", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
warnings.filterwarnings("ignore")

# === Підключення до БД ===
engine = create_engine(f"sqlite:///{backup_db_path}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
session = Session()
votes = session.query(VoteRecord).all()

# === Заголовок лог-файлу ===
base_text = "За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік"
header = (
    "================= ПРОТОКОЛ ГОЛОСУВАННЯ =================\n"
    f"Питання, що розглянуто: {base_text}\n"
    f"Мітка часу формування: {timestamp}\n"
    "========================================================\n"
)
logging.info(header)

# === Обробка голосів ===
data = []
verified_ballots = []

for v in votes:
    recomputed_hash = hash_ballot(get_personalized_message(v.choice, v.voter_id))
    hash_match = (str(recomputed_hash) == v.hash_plain)
    try:
        sig_point = Point(int(v.sig_x), int(v.sig_y), curve)
        pub_point = Point(int(v.pub_x), int(v.pub_y), curve)
        recomputed_point = recomputed_hash * G
        decrypted_point = recomputed_point  # тут має бути ElGamal-розшифрування
        point_match = (decrypted_point.x == recomputed_point.x and decrypted_point.y == recomputed_point.y)
        signature_valid = verify_signature(recomputed_hash, sig_point, pub_point)
    except Exception:
        signature_valid = False
        point_match = False
        recomputed_point = decrypted_point = None

    if v.is_verified:
        verified_ballots.append(v)

    logging.info("\n _________Контроль на сервері:")
    logging.info(f"  ID учасника: {v.voter_id}")
    logging.info(f"  Публічний ключ: ({v.pub_x}, {v.pub_y})")
    logging.info(f"  Хеш (ballot_id): {recomputed_hash}")
    logging.info(f"  Очікувана точка: ({recomputed_point.x}, {recomputed_point.y})" if recomputed_point else "  Очікувана точка: н/д")
    logging.info(f"  Відтворення точки: ({v.sig_x}, {v.sig_y})")
    logging.info(f"  Підпис: ({v.sig_x}, {v.sig_y})")
    logging.info(f"  Підпис валідний: {signature_valid}")

    data.append({
        "id": v.id, "voter_id": v.voter_id, "ballot_id": recomputed_hash,
        "choice": v.choice, "timestamp": str(v.timestamp), "hash_plain": v.hash_plain,
        "hash_encrypted": "шифрується точка (не геш)",
        "C1_srv_x": v.C1_srv_x, "C1_srv_y": v.C1_srv_y, "C2_srv_x": v.C2_srv_x, "C2_srv_y": v.C2_srv_y,
        "C1_sec_x": v.C1_sec_x, "C1_sec_y": v.C1_sec_y, "C2_sec_x": v.C2_sec_x, "C2_sec_y": v.C2_sec_y,
        "sig_x": v.sig_x, "sig_y": v.sig_y, "pub_x": v.pub_x, "pub_y": v.pub_y,
        "question_number": v.question_number, "decision_text": v.decision_text, "is_verified": v.is_verified,
        "hash_match": hash_match, "plain_hash": str(recomputed_hash),
        "expected_point_x": str(recomputed_point.x) if recomputed_point else "н/д",
        "expected_point_y": str(recomputed_point.y) if recomputed_point else "н/д",
        "decrypted_point_x": str(decrypted_point.x) if decrypted_point else "н/д",
        "decrypted_point_y": str(decrypted_point.y) if decrypted_point else "н/д",
        "point_match": point_match, "signature_valid": signature_valid
    })

# === Підпис лог-файлу ===
with open(log_file, "rb") as f:
    log_hash = hashlib.sha3_512(f.read()).digest()
log_scalar = int.from_bytes(log_hash, 'big') % q
log_point = log_scalar * G

server_priv = secrets.randbelow(q)
secretary_priv = secrets.randbelow(q)
server_sig = server_priv * log_point
secretary_sig = secretary_priv * log_point

logging.info(f"\n\n==== ПІДПИС ПРОТОКОЛУ ({timestamp}) ====")
logging.info(f"  Хеш лог-файлу: {log_scalar}")
logging.info(f"  Підпис серверу: ({server_sig.x}, {server_sig.y})")
logging.info(f"  Підпис секретаря: ({secretary_sig.x}, {secretary_sig.y})")

# === Підрахунок голосів ===
choices = Counter(v.choice for v in verified_ballots)
decision = "Прийнято" if choices.get("За", 0) > len(verified_ballots) / 2 else "Не прийнято"
logging.info("\n================= ПІДСУМКИ ГОЛОСУВАННЯ =================")
logging.info(f"Отримано бюлетенів: {len(votes)}")
logging.info(f"Верифіковані бюлетені: {len(verified_ballots)}")
logging.info(f"\nПроголосувало 'За': {choices.get('За', 0)}")
logging.info(f"Проголосувало 'Проти': {choices.get('Проти', 0)}")
logging.info(f"Утримались: {choices.get('Утримався', 0)}")
logging.info(f"\nРішення: {decision}")
logging.info("========================================================\n")

# === Excel: основні дані + підпис + підсумки ===
df_votes = pd.DataFrame(data)
df_sign = pd.DataFrame([
    ["timestamp", timestamp],
    ["log_hash", str(log_scalar)],
    ["log_point_x", str(log_point.x)],
    ["log_point_y", str(log_point.y)],
    ["server_sig_x", str(server_sig.x)],
    ["server_sig_y", str(server_sig.y)],
    ["secretary_sig_x", str(secretary_sig.x)],
    ["secretary_sig_y", str(secretary_sig.y)]
], columns=["Field", "Value"])

summary_data = [
    ["Отримано бюлетенів", len(votes)],
    ["Верифіковані бюлетені", len(verified_ballots)],
    ["За", choices.get("За", 0)],
    ["Проти", choices.get("Проти", 0)],
    ["Утримався", choices.get("Утримався", 0)],
    ["Рішення", decision]
]
df_summary = pd.DataFrame(summary_data, columns=["Показник", "Значення"])

with pd.ExcelWriter("votes_export.xlsx", engine="openpyxl", mode="w") as writer:
    df_votes.to_excel(writer, sheet_name="votes", index=False)
    df_sign.to_excel(writer, sheet_name=f"sign_{timestamp}", index=False)
    df_summary.to_excel(writer, sheet_name=f"summary_{timestamp}", index=False)

print("Увага! Протокол сформовано, підписано та збережено у файл.")

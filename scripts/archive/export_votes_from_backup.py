#scripts/export_votes_from_backup.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.vote_record import VoteRecord
import pandas as pd
from ecpy.curves import Curve, Point
from crypto.hash_util import hash_ballot
from crypto.signature import verify_signature
from app.utils.message_builder import get_personalized_message
import logging
import warnings
import sys

# -- Скидання існуючих хендлерів
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# -- Нове логування: файл + консоль
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler("vote_verification.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

warnings.filterwarnings("ignore")


# -- Вимкнення Pydantic warning
warnings.filterwarnings("ignore")

# -- Логування
logging.basicConfig(
    filename="vote_verification.log",
    filemode="w",
    format="%(message)s",
    level=logging.INFO
)

# -- Підключення до резервної БД
backup_db_path = "C:/Users/scrib/OneDrive/diplom/ptoject/iseg.db"
engine = create_engine(f"sqlite:///{backup_db_path}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
session = Session()

votes = session.query(VoteRecord).all()
curve = Curve.get_curve('Ed25519')
G = curve.generator

data = []

for v in votes:
    recomputed_hash = hash_ballot(get_personalized_message(v.choice, v.voter_id))
    hash_match = (str(recomputed_hash) == v.hash_plain)

    try:
        sig_point = Point(int(v.sig_x), int(v.sig_y), curve)
        pub_point = Point(int(v.pub_x), int(v.pub_y), curve)
        expected_point = recomputed_hash * G
        recomputed_point = recomputed_hash * G
        decrypted_point = recomputed_point  # (заміни пізніше, коли читаєш ElGamal)
        point_match = (decrypted_point.x == recomputed_point.x and decrypted_point.y == recomputed_point.y)
        signature_valid = verify_signature(recomputed_hash, sig_point, pub_point)
    except Exception as e:
        expected_point = None
        signature_valid = False
        point_match = False

    # Лог у файл
    logging.info("\n _________Контроль на сервері:")
    logging.info(f"  ID учасника: {v.voter_id}")
    logging.info(f"  Публічний ключ: ({v.pub_x}, {v.pub_y})")
    logging.info(f"  Хеш (ballot_id): {recomputed_hash}")
    if expected_point:
        logging.info(f"  Очікувана точка: ({expected_point.x}, {expected_point.y})")
    else:
        logging.info("  Очікувана точка: н/д")
    logging.info(f"  Відтворення точки: ({v.sig_x}, {v.sig_y})")
    logging.info(f"  Підпис: ({v.sig_x}, {v.sig_y})")
    logging.info(f"  Підпис валідний: {signature_valid}")

    # Додати у Excel
    data.append({
        "id": v.id,
        "voter_id": v.voter_id,
        "ballot_id": recomputed_hash,  # = хеш бюлетеня з voter_id
        "choice": v.choice,
        "timestamp": str(v.timestamp),
        "hash_plain": v.hash_plain,
        "hash_encrypted": "шифрується точка (не геш)",
        "C1_srv_x": v.C1_srv_x,
        "C1_srv_y": v.C1_srv_y,
        "C2_srv_x": v.C2_srv_x,
        "C2_srv_y": v.C2_srv_y,
        "C1_sec_x": v.C1_sec_x,
        "C1_sec_y": v.C1_sec_y,
        "C2_sec_x": v.C2_sec_x,
        "C2_sec_y": v.C2_sec_y,
        "sig_x": v.sig_x,
        "sig_y": v.sig_y,
        "pub_x": v.pub_x,
        "pub_y": v.pub_y,
        "question_number": v.question_number,
        "decision_text": v.decision_text,
        "is_verified": v.is_verified,
        "hash_match": hash_match,
        "plain_hash": str(recomputed_hash),
        "expected_point_x": str(recomputed_point.x),
        "expected_point_y": str(recomputed_point.y),
        "decrypted_point_x": str(decrypted_point.x),
        "decrypted_point_y": str(decrypted_point.y),
        "point_match": point_match,
        "signature_valid": signature_valid
    })


df = pd.DataFrame(data)
df.to_excel("votes_export.xlsx", index=False)

logging.info("\nВерифікацію завершено. Усі дані збережено у 'votes_export.xlsx' та 'vote_verification.log'")
print("Дані експортовано в файл: votes_export.xlsx")


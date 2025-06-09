
import sqlite3
import os
from sqlalchemy.orm import Session
from tabulate import tabulate
from models.vote_record import VoteRecord
from db.database import SessionLocal

session = SessionLocal()
votes = session.query(VoteRecord).all()

table = []
for v in votes:
    table.append([
        v.id,
        v.voter_id,
        v.choice,
        v.timestamp,
        v.hash_plain,
        v.hash_encrypted,
        v.question_number,
        v.decision_text,
        v.C1_srv_x, v.C1_srv_y,
        v.C2_srv_x, v.C2_srv_y,
        v.C1_sec_x, v.C1_sec_y,
        v.C2_sec_x, v.C2_sec_y,
        v.sig_x, v.sig_y,
        v.pub_x, v.pub_y,
        v.is_verified
    ])

print(tabulate(
    table,
    headers=[
        "ID", "Voter ID", "Choice", "Timestamp", "Hash (plain)", "Hash (enc)", "Q#", "Decision",
        "C1_srv_x", "C1_srv_y", "C2_srv_x", "C2_srv_y",
        "C1_sec_x", "C1_sec_y", "C2_sec_x", "C2_sec_y",
        "Sig_x", "Sig_y", "Pub_x", "Pub_y", "Verified"
    ],
    tablefmt="github"
))





# import sqlite3
# import os

# db_path = "db/iseg.db"
# print("Шлях до БД:", os.path.abspath(db_path))

# conn = sqlite3.connect(db_path)
# cursor = conn.cursor()

# cursor.execute("SELECT * FROM vote_records")
# rows = cursor.fetchall()

# print(f"Всього записів: {len(rows)}")
# for row in rows:
#     print(row, "в БД db/iseg.db")

# conn.close()
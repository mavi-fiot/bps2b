#scripts/show_votes_from_backup.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.vote_record import VoteRecord
from tabulate import tabulate

# збережений файл
backup_db_path = "C:/Users/scrib/OneDrive/diplom/ptoject/iseg.db"
engine = create_engine(f"sqlite:///{backup_db_path}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
session = Session()

votes = session.query(VoteRecord).all()

fields = [
    ["id"] + [v.id for v in votes],
    ["voter_id"] + [v.voter_id for v in votes],
    ["choice"] + [v.choice for v in votes],
    ["timestamp"] + [str(v.timestamp) for v in votes],
    ["hash_plain"] + [v.hash_plain for v in votes],
    ["hash_encrypted"] + [v.hash_encrypted for v in votes],
    ["C1_srv_x"] + [v.C1_srv_x for v in votes],
    ["C1_srv_y"] + [v.C1_srv_y for v in votes],
    ["C2_srv_x"] + [v.C2_srv_x for v in votes],
    ["C2_srv_y"] + [v.C2_srv_y for v in votes],
    ["C1_sec_x"] + [v.C1_sec_x for v in votes],
    ["C1_sec_y"] + [v.C1_sec_y for v in votes],
    ["C2_sec_x"] + [v.C2_sec_x for v in votes],
    ["C2_sec_y"] + [v.C2_sec_y for v in votes],
    ["sig_x"] + [v.sig_x for v in votes],
    ["sig_y"] + [v.sig_y for v in votes],
    ["pub_x"] + [v.pub_x for v in votes],
    ["pub_y"] + [v.pub_y for v in votes],
    ["question_number"] + [v.question_number for v in votes],
    ["decision_text"] + [v.decision_text for v in votes],
    ["is_verified"] + [v.is_verified for v in votes],
]


print(tabulate(fields, headers=["Field"] + [f"Vote {i+1}" for i in range(len(votes))], tablefmt="grid"))
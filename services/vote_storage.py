# services/vote_storage.py

from models.vote_record import VoteRecord
from sqlalchemy.orm import Session
from db.database import SessionLocal
from ecpy.curves import Point
from datetime import timezone
import datetime

from typing import Optional

# Зберігання зашифрованого голосу разом із підписом і публічним ключем виборця
def store_encrypted_vote(
    voter_id: str,
    choice: str,
    hash_scalar: int,
    C1_srv: Point,
    C2_srv: Point,
    C1_sec: Point,
    C2_sec: Point,
    signature: Optional[Point] = None,
    pub_key: Optional[Point] = None
):
    db: Session = SessionLocal()
    vote = VoteRecord(
        voter_id=voter_id,
        choice=choice,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        hash_plain=str(hash_scalar),
        hash_encrypted="",  # за реалізованим варіантом не використовується
        question_number=1,
        decision_text="Затвердити звіт керівництва Товариства за 2024 рік",
        C1_srv_x=str(C1_srv.x), C1_srv_y=str(C1_srv.y),
        C2_srv_x=str(C2_srv.x), C2_srv_y=str(C2_srv.y),
        C1_sec_x=str(C1_sec.x), C1_sec_y=str(C1_sec.y),
        C2_sec_x=str(C2_sec.x), C2_sec_y=str(C2_sec.y),
        sig_x=str(signature.x) if signature else None,
        sig_y=str(signature.y) if signature else None,
        pub_x=str(pub_key.x) if pub_key else None,
        pub_y=str(pub_key.y) if pub_key else None
    )
    db.add(vote)
    db.commit()
    db.close()

# Завантаження голосу по ID
def load_vote_data(voter_id: str) -> VoteRecord:
    db: Session = SessionLocal()
    vote = db.query(VoteRecord).filter_by(voter_id=voter_id).first()
    db.close()
    return vote

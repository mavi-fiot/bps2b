from models.vote_record import VoteRecord
from sqlalchemy.orm import Session
from db.database import SessionLocal
from ecpy.curves import Point

# Зберігання зашифрованого голосу

def store_encrypted_vote(voter_id: str, choice: str, hash_scalar: int,
                          C1_srv: Point, C2_srv: Point, C1_sec: Point, C2_sec: Point,
                          signature: Point, pub_key: Point):
    db: Session = SessionLocal()
    vote = VoteRecord(
        voter_id=voter_id,
        choice=choice,
        hash_plain=str(hash_scalar),
        hash_encrypted="",  # для сумісності
        question_number=1,
        decision_text="Затвердити звіт керівництва Товариства за 2024 рік",
        C1_srv_x=C1_srv.x, C1_srv_y=C1_srv.y,
        C2_srv_x=C2_srv.x, C2_srv_y=C2_srv.y,
        C1_sec_x=C1_sec.x, C1_sec_y=C1_sec.y,
        C2_sec_x=C2_sec.x, C2_sec_y=C2_sec.y,
        sig_x=signature.x, sig_y=signature.y,
        pub_x=pub_key.x, pub_y=pub_key.y
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

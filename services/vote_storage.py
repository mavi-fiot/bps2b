# services/vote_storage.py
from sqlalchemy.orm import Session
from tests.vote_record import VoteRecord
from datetime import datetime

def save_vote(
    db: Session,
    voter_id: str,
    choice: str,
    hash_plain: str,
    hash_encrypted: str,
    question_number: int,
    decision_text: str
):
    record = VoteRecord(
        voter_id=voter_id,
        choice=choice,
        timestamp=datetime.utcnow(),
        hash_plain=hash_plain,
        hash_encrypted=hash_encrypted,
        question_number=question_number,
        decision_text=decision_text
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

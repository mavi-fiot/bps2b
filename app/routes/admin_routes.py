#app/routes/admin_routes.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import SessionLocal
from models.vote_record import VoteRecord, VoteRecordOut
import statistics

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/admin/votes", response_model=list[VoteRecordOut])
def get_all_votes(db: Session = Depends(get_db)):
    return db.query(VoteRecord).all()

@router.get("/admin/stats")
def get_stats(db: Session = Depends(get_db)):
    votes = db.query(VoteRecord).all()
    total = len(votes)
    valid = total  # тимчасово всі вважаються валідними
    return {
        "total_votes": total,
        "valid_votes": valid,
        "avg_encrypt_time_ms": 0.0,
        "avg_decrypt_time_ms": 0.0,
        "success_rate": round((valid / total * 100) if total else 0, 2)
    }

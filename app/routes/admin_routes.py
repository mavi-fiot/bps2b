#app/routes/admin_routes.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import SessionLocal
from models.vote_record import VoteRecord, VoteRecordOut

router = APIRouter()

# Підключення до бази даних
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/admin/votes", response_model=list[VoteRecordOut])
def get_all_votes(db: Session = Depends(get_db)):
    return db.query(VoteRecord).all()

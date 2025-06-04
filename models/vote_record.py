#models/vote_record.py

from sqlalchemy import Column, String, Integer, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from pydantic import BaseModel

Base = declarative_base()

class VoteRecord(Base):
    __tablename__ = "vote_records"

    id = Column(Integer, primary_key=True, index=True)

    #  Хто голосував
    voter_id = Column(String, nullable=False, index=True)

    # Вибір
    choice = Column(String, nullable=False)

    #  Час голосування
    timestamp = Column(DateTime, default=datetime.utcnow)

    #  Хеші
    hash_plain = Column(String, nullable=False)
    hash_encrypted = Column(String, nullable=False)

    #  Питання
    question_number = Column(Integer, nullable=False, index=True)
    decision_text = Column(String, nullable=False)

    #  Індекси (якщо потрібно об’єднано)
    __table_args__ = (
        Index("ix_voter_question", "voter_id", "question_number", unique=True),
    )

#  Вивід через API
class VoteRecordOut(BaseModel):
    voter_id: str
    choice: str
    timestamp: datetime
    hash_plain: str
    hash_encrypted: str
    question_number: int
    decision_text: str

    class Config:
        orm_mode = True


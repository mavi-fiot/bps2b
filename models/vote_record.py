#models/vote_record.py

from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from pydantic import BaseModel

Base = declarative_base()

class VoteRecord(Base):
    __tablename__ = "vote_records"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(String, nullable=False)
    choice = Column(String, nullable=False)
    timestamp = Column(String)
    hash_plain = Column(String, nullable=False)
    hash_encrypted = Column(String, nullable=True)
    question_number = Column(Integer, nullable=False)
    decision_text = Column(String, nullable=False)

    # Точки (ElGamal та підпис/ключ) як текст:
    C1_srv_x = Column(String)
    C1_srv_y = Column(String)
    C2_srv_x = Column(String)
    C2_srv_y = Column(String)
    C1_sec_x = Column(String)
    C1_sec_y = Column(String)
    C2_sec_x = Column(String)
    C2_sec_y = Column(String)
    sig_x = Column(String)
    sig_y = Column(String)
    pub_x = Column(String)
    pub_y = Column(String)

class VoteRecordOut(BaseModel):
    voter_id: str
    choice: str
    timestamp: datetime
    hash_plain: str
    hash_encrypted: str | None
    question_number: int
    decision_text: str

    class Config:
        orm_mode = True


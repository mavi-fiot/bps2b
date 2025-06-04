#models/vote_record.py

from sqlalchemy import Column, String, Integer, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from pydantic import BaseModel

Base = declarative_base()

class VoteRecord(Base):
    __tablename__ = "vote_records"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(String, nullable=False)
    choice = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    hash_plain = Column(String, nullable=False)
    hash_encrypted = Column(String, nullable=True)
    question_number = Column(Integer, nullable=False)
    decision_text = Column(String, nullable=False)

    # Координати шифрованих точок (ElGamal server)
    C1_srv_x = Column(Float, nullable=True)
    C1_srv_y = Column(Float, nullable=True)
    C2_srv_x = Column(Float, nullable=True)
    C2_srv_y = Column(Float, nullable=True)

    # Координати шифрованих точок (ElGamal secretary)
    C1_sec_x = Column(Float, nullable=True)
    C1_sec_y = Column(Float, nullable=True)
    C2_sec_x = Column(Float, nullable=True)
    C2_sec_y = Column(Float, nullable=True)

    # Підпис та публічний ключ
    sig_x = Column(Float, nullable=True)
    sig_y = Column(Float, nullable=True)
    pub_x = Column(Float, nullable=True)
    pub_y = Column(Float, nullable=True)

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



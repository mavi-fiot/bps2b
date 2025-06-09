# models/voter_key.py

from sqlalchemy import Column, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class VoterKey(Base):
    __tablename__ = "voter_keys"

    voter_id = Column(String, primary_key=True, index=True)
    pubkey_x = Column(String, nullable=False)
    pubkey_y = Column(String, nullable=False)

# db/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.vote_record import Base as VoteBase
from models.voter_key import Base as VoterBase

IS_PROD = os.getenv("IS_PROD", "False") == "True"
print(f"[init_db] IS_PROD = {IS_PROD}")

DATABASE_URL = "sqlite:///db/iseg.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    from sqlalchemy import inspect
    inspector = inspect(engine)

    print("[init_db] Ініціалізація бази...")

    # Під час розробки — видалення таблиць
    if 'vote_records' in inspector.get_table_names() or 'voter_keys' in inspector.get_table_names():
        VoteBase.metadata.drop_all(bind=engine)
        VoterBase.metadata.drop_all(bind=engine)

    # Створення таблиць
    VoteBase.metadata.create_all(bind=engine)
    VoterBase.metadata.create_all(bind=engine)

    print("[init_db] Таблиці створено")




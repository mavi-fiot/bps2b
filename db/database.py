# db/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.vote_record import Base

IS_PROD = os.getenv("IS_PROD", "False") == "True"
print(f"[init_db] IS_PROD = {IS_PROD}")

DATABASE_URL = "sqlite:///db/iseg.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    from models.vote_record import Base
    from sqlalchemy import inspect

    inspector = inspect(engine)
    if 'vote_records' in inspector.get_table_names():
        print("[init_db] Таблиця vote_records існує — очищення")
        Base.metadata.drop_all(bind=engine)
    else:
        print("[init_db] Таблиця vote_records ще не створена")

    Base.metadata.create_all(bind=engine)
    print("[init_db] Таблиця vote_records ініціалізована")




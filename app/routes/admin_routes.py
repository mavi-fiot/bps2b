#app/routes/admin_routes.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import SessionLocal
from models.vote_record import VoteRecord, VoteRecordOut
from app.utils.message_builder import get_personalized_message

import statistics
import time

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/votes", response_model=list[VoteRecordOut])
def get_all_votes(db: Session = Depends(get_db)):
    return db.query(VoteRecord).all()

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    from crypto.signature import verify_signature
    from crypto.hash_util import hash_ballot
    from ecpy.curves import Curve, Point

    votes = db.query(VoteRecord).all()
    total = len(votes)
    valid = 0
    curve = Curve.get_curve('Ed25519')

    timings = []

    for vote in votes:
        personalized = get_personalized_message(vote.choice, vote.voter_id)
        hash_scalar = hash_ballot(personalized)

        try:
            sig = Point(int(vote.sig_x), int(vote.sig_y), curve)
            pub = Point(int(vote.pub_x), int(vote.pub_y), curve)

            start = time.perf_counter()
            result = verify_signature(hash_scalar, sig, pub)
            duration = time.perf_counter() - start
            timings.append(duration)

            if result:
                valid += 1

        except Exception as e:
            print(f"[verify_signature] ХХХ Помилка: {e}")
            continue

    avg_verify_ms = statistics.mean(timings) * 1000 if timings else 0.0
    print(f"[stats] Середній час перевірки підпису: {avg_verify_ms:.2f} ms")

    return {
        "total_votes": total,
        "valid_votes": valid,
        "success_rate": round((valid / total * 100) if total else 0, 2),
        "avg_verify_time_ms": round(avg_verify_ms, 2)
    }

def get_ballot_text(choice: str) -> str:
    base = "За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік"
    return base if choice in ["За", "Проти", "Утримався"] else ""

@router.get("/admin/results")
def get_voting_results(db: Session = Depends(get_db)):
    from crypto.signature import verify_signature
    from crypto.hash_util import hash_ballot
    from crypto.encryption import decrypt_ciphertext
    from kzp.crypto_logic import get_curve_params, get_server_keys, get_secretary_keys
    from ecpy.curves import Point

    curve, G, q = get_curve_params()
    server_priv, _ = get_server_keys()
    secretary_priv, _ = get_secretary_keys()

    votes = db.query(VoteRecord).all()

    tally = {
        "За": 0,
        "Проти": 0,
        "Утримався": 0,
        "Невизначено": 0
    }

    for vote in votes:
        try:
            personalized = get_personalized_message(vote.choice, vote.voter_id)
            hash_scalar = hash_ballot(personalized)
            expected_point = hash_scalar * G

            sig = Point(int(vote.sig_x), int(vote.sig_y), curve)
            pub = Point(int(vote.pub_x), int(vote.pub_y), curve)

            if not verify_signature(hash_scalar, sig, pub):
                continue  # ххх підпис недійсний

            C1_srv = Point(int(vote.C1_srv_x), int(vote.C1_srv_y), curve)
            C2_srv = Point(int(vote.C2_srv_x), int(vote.C2_srv_y), curve)
            C1_sec = Point(int(vote.C1_sec_x), int(vote.C1_sec_y), curve)
            C2_sec = Point(int(vote.C2_sec_x), int(vote.C2_sec_y), curve)

            point_srv = decrypt_ciphertext(C1_srv, C2_srv, server_priv)
            point_sec = decrypt_ciphertext(C1_sec, C2_sec, secretary_priv)

            if point_srv != point_sec or point_srv != expected_point:
                continue  # ххх точка не відповідає

            # V Валідний голос
            if vote.choice in tally:
                tally[vote.choice] += 1
            else:
                tally["Невизначено"] += 1

        except Exception as e:
            print(f"[vote_check] stop Помилка: {e}")
            continue

    return {
        "results": tally,
        "total_counted": sum(tally.values())
    }




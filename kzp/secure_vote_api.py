# kzp/secure_vote_api.py

from hashlib import sha3_512 as HASH_FUNC


from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from ecpy.curves import Point, Curve
from kzp.crypto_logic import (
    get_curve_params, get_server_keys, get_secretary_keys
)
from crypto.hash_util import hash_ballot, safe_point  
from crypto.signature import sign_hash, verify_signature
from crypto.encryption import (
    elgamal_encrypt_point as elgamal_encrypt,
    decrypt_ciphertext as elgamal_decrypt
)
from models.crypto_schemas import (
    VoteIn, SignDemoResponse, PointData,
    EncryptVoteResponse, SubmitSignatureRequest, SubmitSignatureResponse,
    KeysResponse, PrivateKeysResponse, PrivateKeysResponseVoter
)
from services.vote_storage import store_encrypted_vote, load_vote_data
from models.vote_record import VoteRecord
from db.database import engine, SessionLocal
from app.utils.message_builder import get_personalized_message
from models.voter_key import VoterKey
from sqlalchemy.orm import Session
from models.voter_key import VoterKey
from db.database import SessionLocal


import time
import hashlib
import secrets

router = APIRouter()

# curve, G, q = get_curve_params()
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

from fastapi import Query, HTTPException

@router.get("/keys", response_model=PrivateKeysResponse)
def get_keys():
    server_priv, server_pub = get_server_keys()
    sec_priv, sec_pub = get_secretary_keys()
    return PrivateKeysResponse(
        server_public_key=PointData(x=str(server_pub.x), y=str(server_pub.y)),
        secretary_public_key=PointData(x=str(sec_pub.x), y=str(sec_pub.y)),
        server_private_key=str(server_priv),
        secretary_private_key=str(sec_priv)
    )

@router.get("/register", response_model=PrivateKeysResponseVoter)
def register_voter(
    voter_id: str = Query(..., enum=[
        "voter1", "voter2", "voter3", "voter4",
        "voter5", "voter6", "voter7"
    ])
):
    # Генерація ключів
    digest = HASH_FUNC(voter_id.encode()).digest()
    priv = int.from_bytes(digest, 'big') % q
    pub = priv * G

    # Збереження публічного ключа в БД
    session = SessionLocal()
    existing = session.query(VoterKey).filter_by(voter_id=voter_id).first()
    if existing:
        existing.pubkey_x = str(pub.x)
        existing.pubkey_y = str(pub.y)
    else:
        record = VoterKey(voter_id=voter_id, pubkey_x=str(pub.x), pubkey_y=str(pub.y))
        session.add(record)
    session.commit()
    session.close()

    # Повернення пари (тільки pub → БД, priv → тільки у відповідь)
    return PrivateKeysResponseVoter(
        voter_id=voter_id,
        priv=str(priv),
        pub=PointData(x=str(pub.x), y=str(pub.y))
    )


@router.get("/voting", response_model=SignDemoResponse)
def sign_demo(
    choice: str = Query(..., enum=["За", "Проти", "Утримався"]),
    voter_id: str = Query(..., enum=[
        "voter1", "voter2", "voter3", "voter4",
        "voter5", "voter6", "voter7"
    ])
):
    personalized = get_personalized_message(choice, voter_id)
    hash_scalar = hash_ballot(personalized)

    priv = vote_signature_key(voter_id)
    pub = priv * G
    signature = sign_hash(hash_scalar, priv)

    return SignDemoResponse(
        message=personalized,
        hash_scalar=str(hash_scalar),
        public_key=PointData(x=str(pub.x), y=str(pub.y)),
        signature=PointData(x=str(signature.x), y=str(signature.y)),
        private_key=str(priv)
    )


@router.post("/encrypt_point", response_model=EncryptVoteResponse)
def encrypt_point(vote: VoteIn):
    start = time.perf_counter()

    # 1. Побудова персоналізованого повідомлення (choice + voter_id)
    personalized = get_personalized_message(vote.choice, vote.voter_id)
    hash_scalar = hash_ballot(personalized)
    point = hash_scalar * G

    # 2. Отримання відкритих ключів (без приватних)
    _, server_pub = get_server_keys()
    _, sec_pub = get_secretary_keys()

    # 3. Шифрування точки ElGamal для серверу і секретаря
    t0 = time.perf_counter()
    C1_srv, C2_srv = elgamal_encrypt(point, server_pub)
    t1 = time.perf_counter()
    C1_sec, C2_sec = elgamal_encrypt(point, sec_pub)
    t2 = time.perf_counter()
    
    print(f"time Шифрування ключом сервера: {(t1 - t0) * 1000:.2f} ms")
    print(f"time Шифрування ключом секретаря: {(t2 - t1) * 1000:.2f} ms")

    # 4. Збереження результату (без підпису і публічного ключа)
    store_encrypted_vote(
        voter_id=vote.voter_id,
        choice=vote.choice,
        hash_scalar=hash_scalar,
        C1_srv=C1_srv,
        C2_srv=C2_srv,
        C1_sec=C1_sec,
        C2_sec=C2_sec,
        signature=None,
        pub_key=None
    )

    elapsed = time.perf_counter() - start
    print(f"[encrypt_point] Час обробки: {elapsed * 1000:.2f} ms")

    return EncryptVoteResponse(
        status="Голос зашифровано",
        voter_id=vote.voter_id,
        choice=vote.choice
    )

@router.post("/submit_signature", response_model=SubmitSignatureResponse)
def submit_signature(voter: SubmitSignatureRequest):
    try:
        start = time.perf_counter()
        voter_id = voter.voter_id
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"ххх Невірний формат тіла запиту: {str(e)}")

    try:
        record: VoteRecord = load_vote_data(voter_id)
        if not record:
            raise HTTPException(404, detail="ххх Запис не знайдено")

        personalized = get_personalized_message(record.choice, record.voter_id)
        expected_hash = hash_ballot(personalized)

        curve = Curve.get_curve('Ed25519')

        point_sig = Point(int(voter.signature.x), int(voter.signature.y), curve)
        pub_point = Point(int(voter.public_key.x), int(voter.public_key.y), curve)

        
        print(f"\n _________Контроль на сервері:")
        print(f"  Публічний ключ: ({pub_point.x}, {pub_point.y})")
        print(f"  Хеш: {expected_hash}")
        print(f"  Очікувана точка: ({point_sig.x}, {point_sig.y})")

        if not verify_signature(expected_hash, point_sig, pub_point):
            return SubmitSignatureResponse(valid=False, error="Недійсний підпис")
        
        # Позначити голос як перевірений
        session = SessionLocal()
        vote = session.query(VoteRecord).filter_by(voter_id=voter_id).first()
        if vote:
            vote.sig_x = str(voter.signature.x)
            vote.sig_y = str(voter.signature.y)
            vote.pub_x = str(voter.public_key.x)
            vote.pub_y = str(voter.public_key.y)
            vote.is_verified = True
            session.commit()
        session.close()

        server_priv, _ = get_server_keys()
        secretary_priv, _ = get_secretary_keys()

        C1_srv = safe_point(record.C1_srv_x, record.C1_srv_y, label="C1_srv")
        C2_srv = safe_point(record.C2_srv_x, record.C2_srv_y, label="C2_srv")
        C1_sec = safe_point(record.C1_sec_x, record.C1_sec_y, label="C1_sec")
        C2_sec = safe_point(record.C2_sec_x, record.C2_sec_y, label="C2_sec")

        t0 = time.perf_counter()
        point_srv = elgamal_decrypt(C1_srv, C2_srv, server_priv)
        t1 = time.perf_counter()
        point_sec = elgamal_decrypt(C1_sec, C2_sec, secretary_priv)
        t2 = time.perf_counter()

        print(f"time Розшифрування ключом сервера: {(t1 - t0) * 1000:.2f} ms")
        print(f"time Розшифрування ключом секретаря: {(t2 - t1) * 1000:.2f} ms")


        if point_srv != point_sec:
            return SubmitSignatureResponse(valid=False, error="Розшифровані точки не збігаються")

        expected_point = expected_hash * curve.generator
        if point_srv != expected_point:
            return SubmitSignatureResponse(valid=False, error="Точка не відповідає гешу")

        elapsed = time.perf_counter() - start
        print(f"[submit_signature] Час перевірки: {elapsed * 1000:.2f} ms")

        return SubmitSignatureResponse(valid=True, message="Голос підтверджено")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ххх Помилка сервера: {str(e)}")


def get_ballot_text(choice: str) -> str:
    base = "За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік"
    return base if choice in ["За", "Проти", "Утримався"] else ""

def vote_signature_key(voter_id: str) -> int:
    digest = HASH_FUNC(voter_id.encode()).digest()
    return int.from_bytes(digest, 'big') % q









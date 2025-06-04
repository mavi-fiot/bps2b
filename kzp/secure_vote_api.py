# kzp/secure_vote_api.py

#kzp/secure_vote_api.py

from fastapi import APIRouter, HTTPException
from ecpy.curves import Point
from kzp.crypto_logic import (
    get_curve_params, get_server_keys, get_secretary_keys
)
from crypto.hash_util import hash_ballot
from crypto.signature import sign_hash, verify_signature
from crypto.encryption import elgamal_encrypt, elgamal_decrypt
from models.crypto_schemas import (
    VoteIn, SignDemoResponse, PointData,
    EncryptVoteResponse, SubmitSignatureRequest, SubmitSignatureResponse,
    KeysResponse
)
from services.vote_storage import store_encrypted_vote, load_vote_data
from models.vote_record import VoteRecord
import time
import hashlib
import secrets

router = APIRouter()

curve, G, q = get_curve_params()

@router.get("/keys", response_model=KeysResponse)
def get_keys():
    _, server_pub = get_server_keys()
    _, sec_pub = get_secretary_keys()
    return KeysResponse(
        server_public_key=PointData(x=server_pub.x, y=server_pub.y),
        secretary_public_key=PointData(x=sec_pub.x, y=sec_pub.y)
    )

@router.post("/encrypt_vote", response_model=EncryptVoteResponse)
def encrypt_vote(vote: VoteIn):
    start = time.perf_counter()

    ballot_text = get_ballot_text(vote.choice)
    personalized = ballot_text + vote.voter_id
    hash_scalar = hash_ballot(personalized)
    point = hash_scalar * G

    _, server_pub = get_server_keys()
    _, sec_pub = get_secretary_keys()

    C1_srv, C2_srv = elgamal_encrypt(point, server_pub)
    C1_sec, C2_sec = elgamal_encrypt(point, sec_pub)

    priv = vote_signature_key(vote.voter_id)
    pub = priv * G
    signature = sign_hash(hash_scalar, priv)

    store_encrypted_vote(
        vote.voter_id, vote.choice, hash_scalar,
        C1_srv, C2_srv, C1_sec, C2_sec,
        signature, pub
    )

    elapsed = time.perf_counter() - start
    print(f"[encrypt_vote] Час обробки: {elapsed * 1000:.2f} ms")

    return EncryptVoteResponse(
        status="✅ Голос зашифровано",
        voter_id=vote.voter_id,
        choice=vote.choice
    )

@router.post("/submit_signature", response_model=SubmitSignatureResponse)
def submit_signature(voter: SubmitSignatureRequest):
    try:
        start = time.perf_counter()
        voter_id = voter.voter_id
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"❌ Невірний формат тіла запиту: {str(e)}")

    try:
        record: VoteRecord = load_vote_data(voter_id)
        if not record:
            raise HTTPException(404, detail="❌ Запис не знайдено")

        ballot_text = get_ballot_text(record.choice)
        personalized = ballot_text + record.voter_id
        expected_hash = hash_ballot(personalized)

        point_sig = Point(record.sig_x, record.sig_y)
        pub_point = Point(record.pub_x, record.pub_y)

        if not verify_signature(expected_hash, point_sig, pub_point):
            return SubmitSignatureResponse(valid=False, error="Недійсний підпис")

        srv_priv, _ = get_server_keys()
        sec_priv, _ = get_secretary_keys()

        C1_srv = Point(record.C1_srv_x, record.C1_srv_y)
        C2_srv = Point(record.C2_srv_x, record.C2_srv_y)
        C1_sec = Point(record.C1_sec_x, record.C1_sec_y)
        C2_sec = Point(record.C2_sec_x, record.C2_sec_y)

        point_srv = elgamal_decrypt(C1_srv, C2_srv, srv_priv)
        point_sec = elgamal_decrypt(C1_sec, C2_sec, sec_priv)

        if point_srv != point_sec:
            return SubmitSignatureResponse(valid=False, error="Розшифровані точки не збігаються")

        expected_point = expected_hash * get_curve_params()[1]
        if point_srv != expected_point:
            return SubmitSignatureResponse(valid=False, error="Точка не відповідає гешу")

        elapsed = time.perf_counter() - start
        print(f"[submit_signature] Час перевірки: {elapsed * 1000:.2f} ms")

        return SubmitSignatureResponse(valid=True, message="Голос підтверджено")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"❌ Помилка сервера: {str(e)}")


# Допоміжні функції

def get_ballot_text(choice: str) -> str:
    base = "За першим питанням порядку денного за проектом рішення: Затвердити звіт керівництва Товариства за 2024 рік"
    return base if choice in ["За", "Проти", "Утримався"] else ""

def vote_signature_key(voter_id: str) -> int:
    digest = hashlib.sha256(voter_id.encode()).hexdigest()
    return int(digest, 16) % q

@router.get("/sign_demo", response_model=SignDemoResponse)
def sign_demo():
    voter_id = "demo-voter"
    decision_text = "Затвердити звіт за 2024 рік"
    personalized = decision_text + voter_id
    hash_scalar = hash_ballot(personalized)

    priv = secrets.randbelow(q)
    pub = priv * G
    signature = sign_hash(hash_scalar, priv)

    return SignDemoResponse(
        message=personalized,
        hash_scalar=hash_scalar,
        public_key=PointData(x=pub.x, y=pub.y),
        signature=PointData(x=signature.x, y=signature.y)
    )



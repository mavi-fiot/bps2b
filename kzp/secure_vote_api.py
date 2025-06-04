#kzp/secure_vote_api.py

from fastapi import APIRouter
from ecpy.curves import Point
from kzp.crypto_logic import get_curve_params
from crypto.hash_util import hash_ballot
from crypto.signature import sign_hash
from models.crypto_schemas import SignDemoResponse
import secrets

router = APIRouter()

# Крива
curve, G, q = get_curve_params()

# Демонстрація підпису повідомлення
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
        public_key={"x": pub.x, "y": pub.y},
        signature={"x": signature.x, "y": signature.y}
    )


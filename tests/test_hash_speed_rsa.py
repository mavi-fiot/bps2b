#tests/test_hash_speed_rsa.py

import time
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

def benchmark_hashes(message: bytes, iterations: int = 1000):
    print(f"\n Benchmarking hash functions ({iterations} runs)")

    def time_hash(label, func):
        start = time.time()
        for _ in range(iterations):
            func()
        end = time.time()
        print(f"{label:<12}: {(end - start)*1000:.2f} ms")

    time_hash("SHA-256", lambda: hashlib.sha256(message).digest())
    time_hash("SHA-512", lambda: hashlib.sha512(message).digest())
    time_hash("SHA3-256", lambda: hashlib.sha3_256(message).digest())
    time_hash("SHA3-512", lambda: hashlib.sha3_512(message).digest())

def rsa_operations(message: bytes):
    print("\n Benchmarking RSA 2048-bit")

    # ⏱ Генерація ключів
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    end = time.time()
    print(f"Key generation : {(end - start)*1000:.2f} ms")

    public_key = private_key.public_key()
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, backend=default_backend())
    hasher.update(message)
    digest = hasher.finalize()

    #  Підпис
    start = time.time()
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(chosen_hash),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(chosen_hash)
    )
    end = time.time()
    print(f"Sign (SHA256)  : {(end - start)*1000:.2f} ms")

    #  Перевірка підпису
    start = time.time()
    public_key.verify(
        signature,
        digest,
        padding.PSS(
            mgf=padding.MGF1(chosen_hash),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(chosen_hash)
    )
    end = time.time()
    print(f"Verify (SHA256): {(end - start)*1000:.2f} ms")

if __name__ == "__main__":
    msg = "З питання першого порядку денного за проектом рішення: Затвердити звіт за 2024 рік".encode("utf-8")
    benchmark_hashes(msg, iterations=1000)
    rsa_operations(msg)

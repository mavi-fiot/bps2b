#models/crypto_schemas.py

from pydantic import BaseModel

# Точка на кривій
class PointData(BaseModel):
    x: str
    y: str

class PrivateKeysResponse(BaseModel):
    server_public_key: PointData
    secretary_public_key: PointData
    server_private_key: str
    secretary_private_key: str

# Вхідне повідомлення для підпису і шифрування голосу
class VoteIn(BaseModel):
    voter_id: str
    ballot_id: str
    choice: str
    signature: PointData
    public_key: PointData

# Структура для збереження результатів подвійного шифрування
class EncryptedData(BaseModel):
    C1_srv: tuple[int, int]
    C2_srv: tuple[int, int]
    C1_sec: tuple[int, int]
    C2_sec: tuple[int, int]
    expected_hash_scalar: int

# Демонстраційна відповідь із `/encrypt_demo`
class EncryptDemoResponse(BaseModel):
    message: str
    hash_scalar: int
    point_M: PointData
    server_public_key: PointData
    secretary_public_key: PointData
    C1_srv: PointData
    C2_srv: PointData
    C1_sec: PointData
    C2_sec: PointData

# Результат розшифрування з /decrypt_demo
class DecryptDemoResponse(BaseModel):
    decrypted_point: PointData
    expected_point: PointData
    valid: bool

# Демонстрація підпису
class SignDemoResponse(BaseModel):
    message: str
    hash_scalar: str
    public_key: PointData
    signature: PointData
    private_key: str

# Відповідь після шифрування голосу
class EncryptVoteResponse(BaseModel):
    status: str
    voter_id: str
    choice: str

# Запит на підтвердження підпису
class SubmitSignatureRequest(BaseModel):
    voter_id: str
    signature: PointData
    public_key: PointData

# Відповідь на підтвердження підпису
class SubmitSignatureResponse(BaseModel):
    valid: bool
    message: str | None = None
    error: str | None = None

# Відкриті ключі для перевірки
class KeysResponse(BaseModel):
    server_public_key: PointData
    secretary_public_key: PointData


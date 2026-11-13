import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sign(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def token() -> str:
    return secrets.token_hex(32)


def encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, aad)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key, nonce, plaintext, aad):
    return AESGCM(key).encrypt(nonce, plaintext, aad)

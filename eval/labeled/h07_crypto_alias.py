from Crypto.Cipher import DES as DataEncryptionStandard

BLOCK_SIZE = 8


def encrypt(key, data):
    cipher = DataEncryptionStandard.new(key)  # KLABEL CWE-327
    return cipher.encrypt(data)

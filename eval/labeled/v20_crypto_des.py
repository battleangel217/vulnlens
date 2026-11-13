from Crypto.Cipher import DES


def encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)  # KLABEL CWE-327
    return cipher.encrypt(data)

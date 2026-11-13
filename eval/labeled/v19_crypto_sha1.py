import hashlib


def sign(payload):
    return hashlib.sha1(payload).digest()  # KLABEL CWE-327

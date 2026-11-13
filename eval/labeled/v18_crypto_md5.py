import hashlib


def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # KLABEL CWE-327

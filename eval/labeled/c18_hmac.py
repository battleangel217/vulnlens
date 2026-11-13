import hashlib
import hmac


def verify(key, message, signature):
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)

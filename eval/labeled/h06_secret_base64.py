import base64

API_KEY = base64.b64decode("c2stcHJvZC1hYmMxMjM0NTY3ODkw")  # KLABEL CWE-798


def headers():
    return {"Authorization": API_KEY}

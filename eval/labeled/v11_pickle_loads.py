import pickle

from flask import request


def restore():
    payload = request.get_data()
    return pickle.loads(payload)  # KLABEL CWE-502

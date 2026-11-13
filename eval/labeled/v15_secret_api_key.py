import requests

API_KEY = "a8f5f167f44f4964e6c998dee827110c"  # KLABEL CWE-798


def call(endpoint):
    return requests.get(endpoint, headers={"Authorization": API_KEY})

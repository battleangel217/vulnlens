import secrets


def new_session_token():
    return secrets.token_urlsafe(32)

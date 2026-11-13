import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ.get("API_KEY")
SESSION_TIMEOUT_SECONDS = 3600
CLIENT_SECRET = os.environ["CLIENT_SECRET"]


def connect(password: str | None = None) -> str:
    return password or DB_PASSWORD

import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ.get("API_KEY", "")


def dsn():
    return f"postgres://app:{DB_PASSWORD}@db/app"

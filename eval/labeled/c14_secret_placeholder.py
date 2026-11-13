API_KEY = "your-api-key-here"
PASSWORD = "changeme"
TOKEN = "xxx"


def configured() -> bool:
    return bool(API_KEY and PASSWORD and TOKEN)

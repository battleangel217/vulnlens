import subprocess
from pathlib import Path

BASE_DIR = Path("/srv/app/data")


def list_files(directory: str) -> list[str]:
    result = subprocess.run(
        ["ls", "-1", directory], capture_output=True, text=True, check=True
    )
    return result.stdout.splitlines()


def read_config(name: str) -> str:
    path = BASE_DIR / name
    return path.read_text(encoding="utf-8")


def tail(path: str) -> str:
    completed = subprocess.run(["tail", "-n", "20", path], capture_output=True, text=True)
    return completed.stdout

import subprocess


def list_dir(path):
    completed = subprocess.run(["ls", "-la", path], capture_output=True, text=True, check=True)
    return completed.stdout

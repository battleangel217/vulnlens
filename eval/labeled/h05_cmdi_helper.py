import subprocess


def run(cmd):
    return subprocess.run(cmd, shell=True)  # KLABEL CWE-78


def ping(host):
    return run(f"ping -c 1 {host}")

import os


def tail(logfile):
    handle = os.popen(f"tail -n 50 {logfile}")  # KLABEL CWE-78
    return handle.read()

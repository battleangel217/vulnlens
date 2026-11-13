import json
import shlex
import subprocess


def run_report(path):
    command = ["python", "report.py", shlex.quote(path)]
    return subprocess.run(command, capture_output=True, text=True, check=False)


def parse(raw):
    return json.loads(raw)

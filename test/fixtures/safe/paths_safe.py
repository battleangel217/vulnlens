import os

from flask import request, send_from_directory

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def download():
    name = request.args["name"]
    safe_name = os.path.basename(name)
    return send_from_directory(BASE_DIR, safe_name)


def read_report(report_id: str) -> str:
    path = os.path.realpath(os.path.join(BASE_DIR, "reports", report_id))
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def read_static() -> str:
    with open(os.path.join(BASE_DIR, "static", "index.html"), "r", encoding="utf-8") as handle:
        return handle.read()

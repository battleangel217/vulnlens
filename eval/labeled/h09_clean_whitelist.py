from flask import request

ALLOWED = {"summary.txt", "detail.txt"}


def read_report():
    name = request.args["name"]
    if name not in ALLOWED:
        raise ValueError("not an allowed report")
    with open("/srv/reports/" + name) as handle:
        return handle.read()

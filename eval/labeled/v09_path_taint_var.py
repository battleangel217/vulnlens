import os

from flask import request


def read_report():
    report = request.args["report"]
    path = os.path.join("/srv/reports", report)
    with open(path) as handle:  # KLABEL CWE-22
        return handle.read()

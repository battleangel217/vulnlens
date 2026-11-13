from pathlib import Path as P

from flask import request


def read_upload():
    name = request.args["name"]
    return P("/srv/uploads", name).read_text()  # KLABEL CWE-22

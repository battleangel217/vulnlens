import os

from flask import request, send_from_directory

BASE = "/srv/public"


def download():
    name = request.args["file"]
    safe = os.path.basename(name)
    return send_from_directory(BASE, safe)

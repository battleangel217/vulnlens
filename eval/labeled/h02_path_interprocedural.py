from flask import request


def resolve_upload():
    name = request.args["name"]
    return "/srv/uploads/" + name


def read_upload():
    path = resolve_upload()
    with open(path) as handle:  # KLABEL CWE-22
        return handle.read()

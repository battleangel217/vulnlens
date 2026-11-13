from flask import request


def download():
    return open(request.args["name"]).read()  # KLABEL CWE-22

import os


def read_upload(filename):
    candidate = os.path.realpath(os.path.join("/srv/uploads", filename))
    with open(candidate, "r", encoding="utf-8") as handle:
        return handle.read()

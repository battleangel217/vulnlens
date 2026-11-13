import marshal


def load_cached(blob):
    return marshal.loads(blob)  # KLABEL CWE-502

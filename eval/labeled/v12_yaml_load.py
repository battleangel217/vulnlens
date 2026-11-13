import yaml


def load_config(stream):
    return yaml.load(stream)  # KLABEL CWE-502

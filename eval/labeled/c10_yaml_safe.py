import yaml


def load_settings(stream):
    return yaml.safe_load(stream)

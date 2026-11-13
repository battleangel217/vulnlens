import json
import yaml


def load_settings(raw: bytes) -> dict:
    return json.loads(raw)


def load_yaml(text: str) -> dict:
    return yaml.safe_load(text)


def load_yaml_explicit(text: str) -> dict:
    return yaml.load(text, Loader=yaml.SafeLoader)

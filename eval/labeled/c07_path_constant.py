import os

CONFIG_PATH = "/etc/vulnguard/config.json"


def read_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        return handle.read()

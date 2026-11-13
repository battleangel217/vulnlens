import os


def compress(target):
    os.system("tar czf /tmp/backup.tgz " + target)  # KLABEL CWE-78
    return "/tmp/backup.tgz"

import subprocess


def git_head(repo):
    return subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True)

PASSWORD = "prod-" + "hunter2-2024"  # KLABEL CWE-798


def dsn(user):
    return f"{user}:{PASSWORD}@db/app"

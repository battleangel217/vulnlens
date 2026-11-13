DATABASE_PASSWORD = "prod-hunter2-2024"  # KLABEL CWE-798


def connect(driver):
    return driver.connect(password=DATABASE_PASSWORD)

import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    query = (
        "SELECT id, email FROM users WHERE name = '"
        + name
        + "'"
    )
    cursor.execute(query)  # KLABEL CWE-89
    return cursor.fetchone()

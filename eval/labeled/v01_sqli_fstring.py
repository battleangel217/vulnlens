import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute(f"SELECT id, email FROM users WHERE name = '{name}'")  # KLABEL CWE-89
    return cursor.fetchone()

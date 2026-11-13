import sqlite3


def find_user(connection, name):
    cursor = connection.cursor()
    cursor.execute("SELECT id, email FROM users WHERE name = ?", (name,))
    return cursor.fetchone()

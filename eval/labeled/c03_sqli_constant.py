import sqlite3

ACTIVE_USERS = "SELECT id FROM users WHERE active = 1"


def active(connection):
    cursor = connection.cursor()
    cursor.execute(ACTIVE_USERS)
    return cursor.fetchall()

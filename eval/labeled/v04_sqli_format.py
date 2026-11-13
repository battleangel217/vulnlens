import sqlite3


def by_role(connection, role):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE role = '{}'".format(role))  # KLABEL CWE-89
    return cursor.fetchall()

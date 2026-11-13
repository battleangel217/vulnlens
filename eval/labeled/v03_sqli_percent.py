import sqlite3


def search(connection, term, limit):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM items WHERE name LIKE %s LIMIT %s" % (term, limit))  # KLABEL CWE-89
    return cursor.fetchall()

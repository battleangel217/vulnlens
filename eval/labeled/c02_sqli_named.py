import sqlite3


def find_order(connection, order_id):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = :id", {"id": order_id})
    return cursor.fetchone()

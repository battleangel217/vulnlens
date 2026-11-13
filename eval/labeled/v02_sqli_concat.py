import sqlite3


def orders_for(connection, customer):
    cursor = connection.cursor()
    query = "SELECT * FROM orders WHERE customer = '" + customer + "'"  # KLABEL CWE-89
    cursor.execute(query)
    return cursor.fetchall()

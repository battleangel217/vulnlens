import sqlite3

DB_PATH = "app.db"


def get_user(connection, user_id):
    cursor = connection.cursor()
    cursor.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def create_user(connection, email):
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users (email) VALUES (%s)",
        (email,),
    )
    connection.commit()


def connect():
    return sqlite3.connect(DB_PATH)

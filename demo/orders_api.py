"""Deliberately vulnerable Flask app used to demo VulnLens.

Do not deploy this. Open it in VS Code, save, and you should see exactly four
findings, each marked below, and nothing on the safe counterparts.
"""

import os
import pickle
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# Finding 1: hardcoded credential (CWE-798)
DATABASE_PASSWORD = "correct-horse-battery-staple"


def connect():
    # Safe: no user input, and the pragma is a constant statement.
    connection = sqlite3.connect("orders.db")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@app.route("/orders/<int:order_id>")
def get_order(order_id):
    # Safe: the converter guarantees an int and the query is parameterized.
    cursor = connect().cursor()
    cursor.execute("SELECT id, total FROM orders WHERE id = ?", (order_id,))
    return str(cursor.fetchone())


@app.route("/search")
def search():
    term = request.args["q"]
    cursor = connect().cursor()
    # Finding 2: SQL injection (CWE-89)
    cursor.execute(f"SELECT id, total FROM orders WHERE note LIKE '%{term}%'")
    return str(cursor.fetchall())


@app.route("/backup")
def backup():
    target = request.args["target"]
    # Finding 3: OS command injection (CWE-78)
    os.system("tar czf /tmp/backup.tgz " + target)
    return "ok"


@app.route("/restore", methods=["POST"])
def restore():
    blob = request.get_data()
    # Finding 4: insecure deserialization (CWE-502)
    state = pickle.loads(blob)
    return str(state)

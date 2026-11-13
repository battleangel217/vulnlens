import hashlib
import os
import pickle

from flask import Flask, request

app = Flask(__name__)
app.secret_key = "s3cr3t-key-should-not-be-here"
DB_PASSWORD = "hunter2-prod-password"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@app.route("/user")
def user():
    user_id = request.args["id"]
    with open(os.path.join("/srv/data", user_id), "rb") as handle:
        return handle.read()


@app.route("/search")
def search():
    term = request.args["q"]
    query = f"SELECT * FROM users WHERE name LIKE '%{term}%'"
    return str(query)


@app.route("/ping")
def ping():
    host = request.args["host"]
    return str(os.system("ping -c 1 " + host))


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.get_data()))


def digest(data):
    return hashlib.md5(data).hexdigest()

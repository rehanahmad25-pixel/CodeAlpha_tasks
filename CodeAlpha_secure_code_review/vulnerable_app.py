"""
Student Portal - VULNERABLE VERSION
Written on purpose with common security mistakes for a secure coding review.
DO NOT use this code in real projects or expose it to a network.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import yaml
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"              # hardcoded secret key
ADMIN_PASSWORD = "admin123"                    # hardcoded password
DB = "students.db"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT, course TEXT)")
    pw = hashlib.md5(b"student123").hexdigest()          # weak hash
    con.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'ali', ?)", (pw,))
    con.execute("INSERT OR IGNORE INTO students (id, name, course) VALUES (1, 'Ali', 'CS')")
    con.commit()
    con.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()   # weak hash, no salt
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password))
    con.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()
    con = sqlite3.connect(DB)
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    user = con.execute(query).fetchone()                  # SQL injection
    return "Welcome " + username if user else "Invalid login"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    con = sqlite3.connect(DB)
    rows = con.execute(f"SELECT name, course FROM students WHERE name LIKE '%{name}%'").fetchall()  # SQL injection
    return render_template_string("<h2>Results for " + name + "</h2>" + str(rows))   # XSS / template injection


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    flag = "-n" if os.name == "nt" else "-c"
    return subprocess.check_output("ping " + flag + " 1 " + host, shell=True)   # command injection


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("uploads", filename))                      # path traversal


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "1+1")))                        # code injection


@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = pickle.loads(request.data)                                        # insecure deserialization
    return str(data)


@app.route("/import_config", methods=["POST"])
def import_config():
    return str(yaml.load(request.data, Loader=yaml.Loader))                  # unsafe YAML loading


@app.route("/report")
def report():
    path = tempfile.mktemp()                                                 # insecure temp file
    with open(path, "w") as f:
        f.write("report")
    return send_file(path)


@app.route("/admin")
def admin():
    if request.args.get("password") == ADMIN_PASSWORD:                       # password in URL, no real auth
        return "Admin panel"
    return "Denied", 403


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)                           # debug mode + open to all

"""
Student Portal - SECURE VERSION
Every vulnerability found in vulnerable_app.py is fixed here.
Each fix has a comment starting with FIX.
"""
import ast
import ipaddress
import json
import operator
import os
import re
import sqlite3
# subprocess is used only with a fixed argument list and validated input (see /ping)
import subprocess  # nosec B404
import tempfile
from contextlib import closing

import yaml
from flask import Flask, abort, render_template_string, request, send_file, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# FIX: secrets come from environment variables, not from source code
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")   # create with generate_password_hash()
DB = os.environ.get("DB_PATH", "students.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

# FIX: safer session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",   # needs HTTPS when True
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,                          # FIX: limit request size to 1 MB
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def get_db():
    return closing(sqlite3.connect(DB))


def init_db():
    with get_db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT, course TEXT)")
        # FIX: strong salted password hash instead of MD5
        con.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'ali', ?)",
                    (generate_password_hash("student123"),))
        con.execute("INSERT OR IGNORE INTO students (id, name, course) VALUES (1, 'Ali', 'CS')")
        con.commit()


@app.after_request
def security_headers(resp):
    # FIX: add browser security headers
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # FIX: input validation
    if not USERNAME_RE.match(username) or len(password) < 8:
        return "Invalid username or password too short (min 8)", 400
    try:
        with get_db() as con:
            # FIX: parameterized query + salted hash
            con.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, generate_password_hash(password)))
            con.commit()
    except sqlite3.IntegrityError:
        return "Username already taken", 409
    return "Registered", 201


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    with get_db() as con:
        # FIX: parameterized query stops SQL injection
        row = con.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    if row and check_password_hash(row[0], password):
        session.clear()
        session["user"] = username
        return "Welcome"
    return "Invalid login", 401        # FIX: same message for wrong user or wrong password


@app.route("/search")
def search():
    name = request.args.get("name", "")[:50]
    with get_db() as con:
        rows = con.execute("SELECT name, course FROM students WHERE name LIKE ?",
                           (f"%{name}%",)).fetchall()      # FIX: parameterized query
    # FIX: user input passed as a template variable, so it is auto-escaped (stops XSS)
    return render_template_string("<h2>Results for {{ name }}</h2>{{ rows }}", name=name, rows=rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)             # FIX: only accept a real IP address
    except ValueError:
        return "Invalid IP address", 400
    flag = "-n" if os.name == "nt" else "-c"
    # FIX: argument list and no shell, so user input cannot run extra commands
    result = subprocess.run(["ping", flag, "1", host], capture_output=True,
                            text=True, timeout=5, check=False)  # nosec B603 B607
    return result.stdout or result.stderr


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # FIX: send_from_directory blocks "../" path traversal
    return send_from_directory(UPLOAD_DIR, filename)


# FIX: small safe calculator instead of eval()
OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
       ast.Div: operator.truediv, ast.USub: operator.neg}


def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.operand))
    raise ValueError("Not allowed")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")[:100]
    try:
        return str(safe_eval(ast.parse(expr, mode="eval")))
    except (ValueError, SyntaxError, ZeroDivisionError):
        return "Invalid expression", 400


@app.route("/load_profile", methods=["POST"])
def load_profile():
    try:
        return str(json.loads(request.data))       # FIX: JSON instead of pickle
    except ValueError:
        return "Invalid JSON", 400


@app.route("/import_config", methods=["POST"])
def import_config():
    try:
        return str(yaml.safe_load(request.data))   # FIX: safe_load only builds simple data types
    except yaml.YAMLError:
        return "Invalid YAML", 400


@app.route("/report")
def report():
    fd, path = tempfile.mkstemp()                  # FIX: mkstemp creates the file safely
    with os.fdopen(fd, "w") as f:
        f.write("report")
    return send_file(path)


@app.route("/admin/login", methods=["POST"])
def admin_login():
    # FIX: password sent in POST body (not the URL) and checked against a hash
    if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, request.form.get("password", "")):
        session["is_admin"] = True
        return "Logged in as admin"
    return "Denied", 403


@app.route("/admin")
def admin():
    if not session.get("is_admin"):                # FIX: real session-based access check
        abort(403)
    return "Admin panel"


if __name__ == "__main__":
    init_db()
    # FIX: debug off and listen on localhost only
    app.run(host="127.0.0.1", port=5000, debug=False)

"""
Amity — Flask security ladder with contiguous levels (amity0 .. amity24)
Each level demonstrates a single, specific vulnerability.
Pages show only: Vulnerability name and Hint.
All potentially dangerous actions are simulated (no real shell/network).
"""
import os
import secrets
import base64
import time
import sqlite3
import hashlib
import json
from functools import wraps
from flask import Flask, request, Response, render_template_string, make_response, redirect, abort, g

# ---------- Config ----------
APP = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PASSWORD_DIR = os.path.join(BASE_DIR, "passwords")
GLOBAL_UPLOADS = os.path.join(BASE_DIR, "uploads")
# After removing some original levels, the ladder has been renumbered
# to be contiguous from 0 to MAX_LEVEL (inclusive).
MAX_LEVEL = 24  # Levels amity0 .. amity24

os.makedirs(PASSWORD_DIR, exist_ok=True)
os.makedirs(GLOBAL_UPLOADS, exist_ok=True)

# ---------- Player handling ----------
PLAYER_COOKIE = "amity_player"
PLAYER_ID_BYTES = 12

def generate_player_id():
    return secrets.token_urlsafe(PLAYER_ID_BYTES)

def player_upload_dir(player_id):
    """Return and ensure the per-player uploads directory."""
    path = os.path.join(GLOBAL_UPLOADS, player_id)
    os.makedirs(path, exist_ok=True)
    return path

@APP.before_request
def ensure_player():
    """Ensure we have a per-player id (via cookie)."""
    player = request.cookies.get(PLAYER_COOKIE)
    if player:
        g.player_id = player
        g.new_player = False
    else:
        g.player_id = generate_player_id()
        g.new_player = True
    player_upload_dir(g.player_id)

@APP.after_request
def set_player_cookie(response):
    """If a new player was created, set the cookie."""
    try:
        if getattr(g, "new_player", False):
            response.set_cookie(PLAYER_COOKIE, g.player_id, max_age=30*24*3600, httponly=True)
    except Exception:
        pass
    return response

# ---------- Helpers ----------
def ensure_passwords(max_level=MAX_LEVEL):
    """Ensure password files exist for all levels 0..max_level."""
    for i in range(max_level + 1):
        pfile = os.path.join(PASSWORD_DIR, f"amity{i}.txt")
        if not os.path.exists(pfile):
            token = secrets.token_urlsafe(12)
            with open(pfile, "w", encoding="utf-8") as f:
                f.write(token)

def read_password(level):
    pfile = os.path.join(PASSWORD_DIR, f"amity{level}.txt")
    if not os.path.isfile(pfile):
        return None
    with open(pfile, "r", encoding="utf-8") as f:
        return f.read().strip()

def require_basic_auth(level):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.authorization
            expected_user = f"amity{level}"
            expected_pass = read_password(level)
            if not auth or auth.username != expected_user or auth.password != expected_pass:
                return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Amity Ladder"'})
            return f(*args, **kwargs)
        return wrapped
    return decorator

def safe_read_from_uploads(user_path):
    """Read files only from the current player's uploads directory."""
    if not user_path:
        raise FileNotFoundError("No filename provided")
    if os.path.isabs(user_path):
        user_path = user_path.lstrip(os.sep)
    udir = player_upload_dir(getattr(g, "player_id", ""))
    joined = os.path.join(udir, user_path)
    normalized = os.path.normpath(joined)
    abs_target = os.path.abspath(normalized)
    abs_base = os.path.abspath(udir)
    if not (abs_target == abs_base or abs_target.startswith(abs_base + os.sep)):
        raise ValueError("Access denied")
    if not os.path.isfile(abs_target):
        raise FileNotFoundError("File not found")
    with open(abs_target, "r", encoding="utf-8") as f:
        return f.read()

# Setup passwords at startup
ensure_passwords()

# ---------- Page Template (Vulnerability + Hint only) ----------
PAGE = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>amity{{level}}</title></head>
<body style="font-family:Arial,Helvetica,sans-serif;line-height:1.4;margin:40px;max-width:800px">
  <h1>amity{{level}}</h1>
  <p><strong>Vulnerability:</strong> {{vuln}}</p>
  <p><strong>Hint:</strong> {{hint}}</p>
  {{body}}
</body>
</html>"""

# ---------- Levels (renumbered, contiguous) ----------

# amity0: HTML comments in source
@APP.route("/amity0")
@require_basic_auth(0)
def amity0():
    nxt = read_password(1) or "[amity1 missing]"
    comment = f"<!-- next password for amity1: {nxt} -->"
    html = PAGE.replace("{{body}}", comment)
    return render_template_string(html, level=0, vuln="Information disclosure (HTML comments)", hint="View page source")

# amity1: Local file inclusion
@APP.route("/amity1")
@require_basic_auth(1)
def amity1():
    file = request.args.get("file", "")
    udir = player_upload_dir(g.player_id)
    hint_file = os.path.join(udir, "hint.txt")
    next_pass = read_password(2) or "[amity2 missing]"
    if not os.path.exists(hint_file):
        with open(hint_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity2: {next_pass}\n")
    
    content = ""
    if file:
        try:
            content = safe_read_from_uploads(file)
        except (FileNotFoundError, ValueError):
            content = "Error"
    body = f"<pre>{content}</pre>" if content else ""
    return render_template_string(PAGE, level=1, vuln="Local file inclusion", hint="Read files from uploads directory", body=body)

# amity2: Path traversal
@APP.route("/amity2")
@require_basic_auth(2)
def amity2():
    file = request.args.get("file", "")
    udir = player_upload_dir(g.player_id)
    secret_file = os.path.join(udir, "secret.txt")
    next_pass = read_password(3) or "[amity3 missing]"
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity3: {next_pass}\n")
    
    content = ""
    if file:
        # Vulnerable: only checks for literal ".." but not URL-encoded versions
        decoded_file = file
        try:
            # Flask automatically decodes once, but double encoding works
            if "%" in file:
                import urllib.parse
                decoded_file = urllib.parse.unquote(file)
        except:
            pass
        
        if ".." not in file:  # Only checks original, not decoded
            try:
                # Use decoded version if available
                content = safe_read_from_uploads(decoded_file if decoded_file != file else file)
            except (FileNotFoundError, ValueError):
                content = "Error"
        else:
            content = "Access denied"
    body = f"<pre>{content}</pre>" if content else ""
    return render_template_string(PAGE, level=2, vuln="Path traversal (incomplete validation)", hint="Bypass .. check using encoding", body=body)
    
# amity3: Weak input parsing
@APP.route("/amity3")
@require_basic_auth(3)
def amity3():
    q = request.args.get("q", "")
    users = [
        {"id": 1, "name": "alice", "secret": "none"},
        {"id": 2, "name": "bob", "secret": "none"},
        {"id": 3, "name": "admin", "secret": read_password(4) or "[amity4 missing]"},
    ]
    results = []
    if q:
        try:
            if "=" in q:
                left, right = q.split("=", 1)
                for u in users:
                    if str(u.get(left.strip(), "")) == right.strip():
                        results.append(u)
            else:
                for u in users:
                    if q in u.get("name", ""):
                        results.append(u)
        except Exception:
            pass
    body = f"<pre>{results}</pre>" if results else ""
    return render_template_string(PAGE, level=3, vuln="Weak input parsing", hint="Query users with structured input", body=body)

# amity4: Log file disclosure
@APP.route("/amity4")
@require_basic_auth(4)
def amity4():
    msg = request.args.get("msg", "")
    udir = player_upload_dir(g.player_id)
    logf = os.path.join(udir, "access.log")
    next_pass = read_password(5) or "[amity5 missing]"
    with open(logf, "a", encoding="utf-8") as f:
        if msg:
            f.write(f"LOG: {msg}\n")
        f.write(f"<!--amity5:{next_pass}-->\n")
    body = ""
    return render_template_string(PAGE, level=4, vuln="Log file disclosure", hint="Check log files for secrets", body=body)

# amity5: HTTP method-based logic
@APP.route("/amity5", methods=["GET", "POST"])
@require_basic_auth(5)
def amity5():
    next_pass = read_password(6) or "[amity6 missing]"
    if request.method == "POST":
        body = f"<pre>Password for amity6: {next_pass}</pre>"
        return render_template_string(PAGE, level=5, vuln="HTTP method-based logic", hint="Use POST method", body=body)
    body = ""
    return render_template_string(PAGE, level=5, vuln="HTTP method-based logic", hint="Use POST method", body=body)

# amity6: Client-side secret in cookie
@APP.route("/amity6")
@require_basic_auth(6)
def amity6():
    next_pass = read_password(7) or "[amity7 missing]"
    cookie_name = "secret_token"
    if cookie_name in request.cookies:
        val = request.cookies.get(cookie_name)
        if val == f"token_{next_pass}":
            body = f"<pre>Password for amity7: {next_pass}</pre>"
            return render_template_string(PAGE, level=6, vuln="Client-side secret (cookie)", hint="Inspect and modify cookies", body=body)
    resp = make_response(render_template_string(PAGE, level=6, vuln="Client-side secret (cookie)", hint="Inspect and modify cookies", body=""))
    resp.set_cookie(cookie_name, f"token_{next_pass}")
    return resp

# amity7: Referer header check
@APP.route("/amity7")
@require_basic_auth(7)
def amity7():
    referer = request.headers.get("Referer", "")
    next_pass = read_password(8) or "[amity8 missing]"
    if "amity6" in referer:
        body = f"<pre>Password for amity8: {next_pass}</pre>"
        return render_template_string(PAGE, level=7, vuln="Referer-based control", hint="Set Referer header", body=body)
    body = ""
    return render_template_string(PAGE, level=7, vuln="Referer-based control", hint="Set Referer header", body=body)

# amity8: Encoding bypass
@APP.route("/amity8")
@require_basic_auth(8)
def amity8():
    param = request.args.get("p", "")
    next_pass = read_password(9) or "[amity9 missing]"
    udir = player_upload_dir(g.player_id)
    target_file = os.path.join(udir, "target.txt")
    if not os.path.exists(target_file):
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity9: {next_pass}\n")
    
    # Only checks for literal ".." but allows encoded versions
    if ".." in param:
        body = "Access denied"
    else:
        try:
            import urllib.parse
            # Double decode to bypass
            decoded = urllib.parse.unquote(urllib.parse.unquote(param))
            content = safe_read_from_uploads(decoded)
            body = f"<pre>{content}</pre>"
        except:
            body = ""
    return render_template_string(PAGE, level=8, vuln="Encoding bypass", hint="Use double URL encoding to bypass checks", body=body)

# amity9: Base64 encoding
@APP.route("/amity9")
@require_basic_auth(9)
def amity9():
    next_pass = read_password(10) or "[amity10 missing]"
    udir = player_upload_dir(g.player_id)
    b64file = os.path.join(udir, "encoded.txt")
    if not os.path.exists(b64file):
        with open(b64file, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(next_pass.encode()).decode())
    body = ""
    return render_template_string(PAGE, level=9, vuln="Weak encoding (Base64)", hint="Decode base64-encoded data", body=body)

# amity10: Command injection (simulated)
@APP.route("/amity10")
@require_basic_auth(10)
def amity10():
    ip = request.args.get("ip", "")
    next_pass = read_password(11) or "[amity11 missing]"
    udir = player_upload_dir(g.player_id)
    hintfile = os.path.join(udir, "result.txt")
    
    suspicious = any(ch in ip for ch in [";", "&", "|", "$", "`", "("])
    if suspicious:
        if not os.path.exists(hintfile):
            with open(hintfile, "w", encoding="utf-8") as f:
                f.write(f"Password for amity11: {next_pass}\n")
        try:
            content = safe_read_from_uploads("result.txt")
            body = f"<pre>{content}</pre>"
        except:
            body = ""
        return render_template_string(PAGE, level=10, vuln="Command injection (simulated)", hint="Use shell metacharacters", body=body)
    body = ""
    return render_template_string(PAGE, level=10, vuln="Command injection (simulated)", hint="Use shell metacharacters", body=body)

# amity11: Reflected XSS
@APP.route("/amity11")
@require_basic_auth(11)
def amity11():
    q = request.args.get("q", "")
    next_pass = read_password(12) or "[amity12 missing]"
    udir = player_upload_dir(g.player_id)
    xss_file = os.path.join(udir, "xss_result.txt")
    
    # XSS vulnerability - password written to file when XSS executed
    if "<script>" in q.lower() or "javascript:" in q.lower() or "onerror=" in q.lower():
        if not os.path.exists(xss_file):
            with open(xss_file, "w", encoding="utf-8") as f:
                f.write(f"Password for amity12: {next_pass}\n")
        try:
            content = safe_read_from_uploads("xss_result.txt")
            body = f"<div>{q}</div><pre>{content}</pre>"
        except:
            body = f"<div>{q}</div>"
        return render_template_string(PAGE, level=11, vuln="Reflected XSS", hint="Inject JavaScript payload", body=body)
    body = f"<div>{q}</div>" if q else ""
    return render_template_string(PAGE, level=11, vuln="Reflected XSS", hint="Inject JavaScript payload", body=body)

# amity12: Server-side template injection
@APP.route("/amity12")
@require_basic_auth(12)
def amity12():
    payload = request.args.get("payload", "")
    next_pass = read_password(13) or "[amity13 missing]"
    udir = player_upload_dir(g.player_id)
    hintfile = os.path.join(udir, "template_result.txt")
    
    if "{{" in payload or "{%" in payload:
        if not os.path.exists(hintfile):
            with open(hintfile, "w", encoding="utf-8") as f:
                f.write(f"Password for amity13: {next_pass}\n")
        try:
            content = safe_read_from_uploads("template_result.txt")
            body = f"<pre>{content}</pre>"
        except:
            body = ""
        return render_template_string(PAGE, level=12, vuln="Server-side template injection", hint="Inject template syntax", body=body)
    body = ""
    return render_template_string(PAGE, level=12, vuln="Server-side template injection", hint="Inject template syntax", body=body)

# amity13: SQL injection
@APP.route("/amity13")
@require_basic_auth(13)
def amity13():
    q = request.args.get("q", "")
    udir = player_upload_dir(g.player_id)
    DB_PATH = os.path.join(udir, "amity.sqlite")
    next_pass = read_password(14) or "[amity14 missing]"
    
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, secret TEXT);")
        cur.execute("INSERT INTO users(username, secret) VALUES ('admin', '')")
        cur.execute("INSERT INTO users(username, secret) VALUES ('user', '')")
        conn.commit()
        conn.close()
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE users SET secret=? WHERE username='admin'", (next_pass,))
    conn.commit()
    
    rows = []
    if q:
        try:
            # Vulnerable: direct concatenation
            sql = "SELECT id, username, secret FROM users WHERE username='" + q + "'"
            cur.execute(sql)
            rows = cur.fetchall()
        except Exception as e:
            rows = [("error", str(e))]
    conn.close()
    
    body = f"<pre>{rows}</pre>" if rows else ""
    return render_template_string(PAGE, level=13, vuln="SQL injection", hint="Inject SQL to extract secrets", body=body)

# amity14: Race condition
@APP.route("/amity14")
@require_basic_auth(14)
def amity14():
    step = request.args.get("step", "")
    udir = player_upload_dir(g.player_id)
    lock = os.path.join(udir, "lock.txt")
    next_pass = read_password(15) or "[amity15 missing]"
    
    if step == "start":
        with open(lock, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
        body = "Started"
        return render_template_string(PAGE, level=14, vuln="Race condition", hint="Exploit time-of-check to time-of-use", body=body)
    
    if step == "finish":
        if os.path.exists(lock):
            mtime = os.path.getmtime(lock)
            if (time.time() - mtime) < 3:
                with open(os.path.join(udir, "race_result.txt"), "w", encoding="utf-8") as f:
                    f.write(f"Password for amity15: {next_pass}\n")
                body = "Race condition exploited"
                return render_template_string(PAGE, level=14, vuln="Race condition", hint="Exploit time-of-check to time-of-use", body=body)
        body = "Too slow"
        return render_template_string(PAGE, level=14, vuln="Race condition", hint="Exploit time-of-check to time-of-use", body=body)
    
    body = ""
    return render_template_string(PAGE, level=14, vuln="Race condition", hint="Exploit time-of-check to time-of-use", body=body)

# amity15: Session fixation
@APP.route("/amity15")
@require_basic_auth(15)
def amity15():
    token = request.args.get("token", "")
    next_pass = read_password(16) or "[amity16 missing]"
    udir = player_upload_dir(g.player_id)
    
    if token:
        session_file = os.path.join(udir, "session.txt")
        with open(session_file, "w", encoding="utf-8") as f:
            f.write(f"session={token}\npassword={next_pass}\n")
        body = "Session set"
        return render_template_string(PAGE, level=15, vuln="Session fixation", hint="Set predictable session token", body=body)
    
    body = ""
    return render_template_string(PAGE, level=15, vuln="Session fixation", hint="Set predictable session token", body=body)

# amity16: Sensitive file disclosure
@APP.route("/amity16")
@require_basic_auth(16)
def amity16():
    udir = player_upload_dir(g.player_id)
    secret_file = os.path.join(udir, ".secret")
    next_pass = read_password(17) or "[amity17 missing]"
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity17: {next_pass}\n")
    body = ""
    return render_template_string(PAGE, level=16, vuln="Sensitive file disclosure", hint="Find hidden files", body=body)

# amity17: SSRF
@APP.route("/amity17")
@require_basic_auth(17)
def amity17():
    url = request.args.get("url", "")
    next_pass = read_password(18) or "[amity18 missing]"
    
    if url.startswith("internal://"):
        path = url[len("internal://"):]
        if path == "secret/password.txt":
            body = f"<pre>Password for amity18: {next_pass}</pre>"
            return render_template_string(PAGE, level=17, vuln="Server-side request forgery", hint="Access internal resources", body=body)
        body = "Path not found"
        return render_template_string(PAGE, level=17, vuln="Server-side request forgery", hint="Access internal resources", body=body)
    
    body = ""
    return render_template_string(PAGE, level=17, vuln="Server-side request forgery", hint="Access internal resources", body=body)

# amity18: Backup file exposure
@APP.route("/amity18")
@require_basic_auth(18)
def amity18():
    next_pass = read_password(19) or "[amity19 missing]"
    udir = player_upload_dir(g.player_id)
    bak = os.path.join(udir, "config.php.bak")
    if not os.path.exists(bak):
        with open(bak, "w", encoding="utf-8") as f:
            f.write(f"<?php\n// Password for amity19: {next_pass}\n?>")
    body = ""
    return render_template_string(PAGE, level=18, vuln="Backup file exposure", hint="Find backup files", body=body)

# amity19: Clickjacking
@APP.route("/amity19")
@require_basic_auth(19)
def amity19():
    action = request.args.get("action", "")
    next_pass = read_password(20) or "[amity20 missing]"
    udir = player_upload_dir(g.player_id)
    
    if action == "click":
        flag_file = os.path.join(udir, "clicked.txt")
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity20: {next_pass}\n")
        body = "Action performed"
        return render_template_string(PAGE, level=19, vuln="Clickjacking", hint="Frame this page and trigger action", body=body)
    
    body = ""
    return render_template_string(PAGE, level=19, vuln="Clickjacking", hint="Frame this page and trigger action", body=body)

# amity20: Insecure direct object reference
@APP.route("/amity20")
@require_basic_auth(20)
def amity20():
    user_id = request.args.get("id", "")
    next_pass = read_password(21) or "[amity21 missing]"
    udir = player_upload_dir(g.player_id)
    
    # Simulated user files
    if user_id:
        user_file = os.path.join(udir, f"user_{user_id}.txt")
        if not os.path.exists(user_file) and user_id == "admin":
            with open(user_file, "w", encoding="utf-8") as f:
                f.write(f"Password for amity21: {next_pass}\n")
        try:
            content = safe_read_from_uploads(f"user_{user_id}.txt")
            body = f"<pre>{content}</pre>"
        except:
            body = "User not found"
        return render_template_string(PAGE, level=20, vuln="Insecure direct object reference", hint="Access other users' resources", body=body)
    
    body = ""
    return render_template_string(PAGE, level=20, vuln="Insecure direct object reference", hint="Access other users' resources", body=body)

# amity21: XXE (simulated)
@APP.route("/amity21", methods=["GET", "POST"])
@require_basic_auth(21)
def amity21():
    next_pass = read_password(22) or "[amity22 missing]"
    udir = player_upload_dir(g.player_id)
    
    if request.method == "POST":
        xml_data = request.form.get("xml", "")
        if "<?xml" in xml_data and "ENTITY" in xml_data:
            result_file = os.path.join(udir, "xxe_result.txt")
            with open(result_file, "w", encoding="utf-8") as f:
                f.write(f"Password for amity22: {next_pass}\n")
            try:
                content = safe_read_from_uploads("xxe_result.txt")
                body = f"<pre>{content}</pre>"
            except:
                body = ""
            return render_template_string(PAGE, level=21, vuln="XML external entity injection", hint="Inject XXE payload", body=body)
    
    body = ""
    return render_template_string(PAGE, level=21, vuln="XML external entity injection", hint="Inject XXE payload", body=body)

# amity22: SSRF to metadata
@APP.route("/amity22")
@require_basic_auth(22)
def amity22():
    url = request.args.get("url", "")
    next_pass = read_password(23) or "[amity23 missing]"
    
    if url:
        # Simulated metadata endpoint
        if "169.254.169.254" in url or "metadata" in url.lower():
            body = f"<pre>Password for amity23: {next_pass}</pre>"
            return render_template_string(PAGE, level=22, vuln="SSRF to metadata service", hint="Access cloud metadata endpoint", body=body)
    
    body = ""
    return render_template_string(PAGE, level=22, vuln="SSRF to metadata service", hint="Access cloud metadata endpoint", body=body)

# amity23: Password reset token reuse
@APP.route("/amity23", methods=["GET", "POST"])
@require_basic_auth(23)
def amity23():
    token = request.form.get("token", "") if request.method == "POST" else request.args.get("token", "")
    next_pass = read_password(24) or "[amity24 missing]"
    udir = player_upload_dir(g.player_id)
    
    # Weak: token doesn't expire and can be reused
    if token == "RESET123":
        result_file = os.path.join(udir, "reset_result.txt")
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(f"Password for amity24: {next_pass}\n")
        try:
            content = safe_read_from_uploads("reset_result.txt")
            body = f"<pre>{content}</pre>"
        except:
            body = ""
        return render_template_string(PAGE, level=23, vuln="Password reset token reuse", hint="Reuse reset token", body=body)
    
    body = ""
    return render_template_string(PAGE, level=23, vuln="Password reset token reuse", hint="Reuse reset token", body=body)

# amity24: JWT weak secret
@APP.route("/amity24")
@require_basic_auth(24)
def amity24():
    token = request.args.get("token", "")
    udir = player_upload_dir(g.player_id)
    secret_file = os.path.join(udir, "jwt_secret.txt")
    
    # Weak secret in file
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("JWT_SECRET=weak123\n")
    
    if token:
        # Simulated JWT validation
        if "admin" in token.lower() or "eyJ" in token:
            body = "<pre>Congratulations! You reached the last level.</pre>"
            return render_template_string(PAGE, level=24, vuln="JWT weak secret", hint="Crack JWT with weak secret", body=body)
    
    body = ""
    return render_template_string(PAGE, level=24, vuln="JWT weak secret", hint="Crack JWT with weak secret", body=body)

# Index
@APP.route("/")
def index():
    player = getattr(g, "player_id", "unknown")
    return f"""
    <h2>Amity Security Ladder (25 levels: amity0 .. amity24)</h2>
    <p>Start at <a href="/amity0">/amity0</a></p>
    <p>Each level requires HTTP Basic Auth: user=amityN, password from passwords/amityN.txt</p>
    <p>Player ID: {player}</p>
    """

if __name__ == "__main__":
    ensure_passwords()
    print(f"Starting Amity ladder (levels 0..{MAX_LEVEL}, with removals) on http://127.0.0.1:5000")
    APP.run(host="127.0.0.1", port=5000, debug=False)

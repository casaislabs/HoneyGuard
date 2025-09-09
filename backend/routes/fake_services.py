"""
This file centralizes the registration of fake service blueprints (honeypots).
Each fake service is implemented in a blueprint file and registered here.
"""
from flask import Blueprint, request, jsonify, redirect, url_for, make_response, Response
import time
import random
import hashlib
from services.redis_singleton import get_redis_client
import string
from utils.utils import get_ip, get_fail_count, inc_fail_count, adaptive_sleep, cache_response
from .fake_admin import fake_admin_bp
from .fake_wp import fake_wp_bp
import pickle
import xml.etree.ElementTree as ET
import jwt
import os
from core.logging import create_log
import mimetypes
from datetime import datetime, timezone

fake_services = Blueprint("fake_services", __name__)
# --- Utilities for realistic and adaptive responses ---
FTP_ERRORS = [
    "530 Login incorrect.",
    "421 Service not available.",
    "530 Not logged in.",
    "550 Permission denied.",
    "500 Syntax error, command unrecognized.",
    "425 Can't open data connection.",
    "530 User cannot log in.",
]
FTP_BANNERS = [
    "220 (vsFTPd 3.0.3)",
    "220 ProFTPD Server (Debian)",
    "220 Microsoft FTP Service",
    "220-FileZilla Server 0.9.60 beta",
]

SSH_BANNERS = [
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    "SSH-2.0-OpenSSH_5.3",
]
SSH_ERRORS = [
    "Permission denied, please try again.",
    "Connection closed by remote host.",
    "Too many authentication failures.",
    "Invalid authentication method.",
    "Received disconnect from 127.0.0.1: 2: Too many authentication failures",
]

MYSQL_ERRORS = [
    "ERROR 1045 (28000): Access denied for user '{}' (using password: {})",
    "ERROR 2003 (HY000): Can't connect to MySQL server on 'localhost' (10061)",
    "ERROR 1044 (42000): Access denied for user '{}' to database 'information_schema'",
    "ERROR 1130 (HY000): Host '{}' is not allowed to connect to this MySQL server",
    "ERROR 1040 (HY000): Too many connections",
    "ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '...';",
]
MYSQL_BANNERS = [
    "5.7.38-log MySQL Community Server (GPL)",
    "8.0.28-0ubuntu0.20.04.3 (Ubuntu)",
    "10.5.15-MariaDB-0+deb11u1 Debian 11",
]

ADMIN_ERRORS = [
    "Incorrect username or password.",
    "Access denied: user blocked.",
    "Too many failed attempts. Try again later.",
    "User does not have sufficient permissions.",
]
ADMIN_BANNERS = [
    "Administration Panel - v2.3.1",
    "Admin Console - Secure Login",
    "Enterprise Management System",
]

PMA_ERRORS = [
    "#1045 Access denied for user",
    "#2002 MySQL server is not responding",
    "#1044 User does not have permission to access the database",
    "#2003 Cannot connect to MySQL server",
]
PMA_BANNERS = [
    "phpMyAdmin 5.1.1",
    "phpMyAdmin 4.9.7",
    "phpMyAdmin 5.2.0-dev",
]

WP_ERRORS = [
    "Error: The password you entered is incorrect.",
    "Error: The user does not exist.",
    "Error: Access denied.",
    "Error: Too many failed attempts. Try again later.",
]
WP_BANNERS = [
    "WordPress 6.2.2",
    "WordPress 5.9.3",
    "WordPress 6.1.1",
]

UPLOAD_MESSAGES = [
    "File uploaded successfully.",
    "The file has been received and is being analyzed.",
    "Upload complete. The file will be reviewed by the administrator.",
]

# Register fake services blueprints
fake_services.register_blueprint(fake_admin_bp)
fake_services.register_blueprint(fake_wp_bp)

# --- Adaptive routes ---

@fake_services.route("/admin", methods=["GET", "POST"])
def fake_admin():
    ip = get_ip(request)
    fail_key = f"fail:admin:{ip}"
    adaptive_sleep(ip)
    username = request.form.get("username", "Unknown") if request.method == "POST" else None
    password = request.form.get("password", "Unknown") if request.method == "POST" else None
    extra = {
        "username": username,
        "password": password,
        "http_status": 200 if request.method == "GET" else 403,
        "request_size": len(request.get_data()),
        "response_size": 0,
    }
    banner = random.choice(ADMIN_BANNERS)
    fail_count = get_fail_count(fail_key)
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
        "query": request.args.get('query', '')
    })
    
    if request.method == "POST":
        inc_fail_count(fail_key)
        if fail_count >= 3:
            return f"<html><head><title>{banner}</title></head><body><h1>User blocked due to too many attempts</h1></body></html>", 403
        error = random.choice(ADMIN_ERRORS)
        response_html = f"""
            <html>
                <head><title>{banner}</title></head>
                <body>
                    <h1>Access error</h1>
                    <p>{error}</p>
                    <p>Attempt recorded: {fail_count+1} times</p>
                </body>
            </html>
        """
        return response_html, 403
    response_html = f"""
        <html>
            <head><title>{banner}</title></head>
            <body>
                <h1>{banner}</h1>
                <form method="POST">
                    <label for="username">User:</label>
                    <input type="text" id="username" name="username"><br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password"><br>
                    <button type="submit">Login</button>
                </form>
                <p>Status: {random.choice(['Available', 'Under maintenance'])}</p>
            </body>
        </html>
    """
    return response_html, 200

@fake_services.route("/wp-login.php", methods=["POST"])
def fake_wp_login():
    ip = get_ip(request)
    fail_key = f"fail:wp:{ip}"
    adaptive_sleep(ip)
    username = request.form.get("log", "Unknown")
    password = request.form.get("pwd", "Unknown")
    extra = {
        "username": username,
        "password": password,
        "http_status": 403,
        "request_size": len(request.get_data()),
        "response_size": 0,
    }
    banner = random.choice(WP_BANNERS)
    fail_count = get_fail_count(fail_key)
    inc_fail_count(fail_key)
    if fail_count >= 3:
        return f"<html><head><title>{banner}</title></head><body><h1>User blocked due to too many attempts</h1></body></html>", 403
    error = random.choice(WP_ERRORS)
    response_html = f"""
        <html>
            <head><title>{banner}</title></head>
            <body>
                <h1>{banner} - Login</h1>
                <p>{error}</p>
                <p>User: {username}</p>
            </body>
        </html>
    """
    return response_html, 403

# --- Dynamic trap routes ---
def random_string(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

@fake_services.route("/secret-<token>.zip", methods=["GET"])
def fake_secret_zip(token):
    ip = get_ip(request)
    extra = {
        "http_status": 200,
        "request_size": 0,
        "response_size": 0,
        "token": token
    }
    return (f"PK\x03\x04... (fake secret backup {token}) ...", 200, {"Content-Type": "application/zip", "Content-Disposition": f"attachment; filename=secret-{token}.zip"})

@fake_services.route("/generate-secret", methods=["GET"])
def generate_secret():
    ip = get_ip(request)
    token = random_string()
    redis_client.setex(f"secret:{ip}", 600, token)
    return jsonify({"secret_url": f"/secret-{token}.zip"})

# --- The rest of endpoints (ftp, ssh, database, etc.) use adaptive_sleep(ip) for adaptive latency and variable banners/errors per IP ---

@fake_services.route("/database", methods=["GET", "POST"])
@cache_response(timeout=30)
def fake_database():
    ip = get_ip(request)
    query = request.args.get('query') or request.form.get('query') or request.get_data(as_text=True)
    username = request.args.get('user') or request.form.get('user', 'root')
    password = request.args.get('password') or request.form.get('password', '')
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
        "query": query,
    })
    
    adaptive_sleep(ip)
    
    if request.method == "GET":
        banner = random.choice(MYSQL_BANNERS + ADMIN_BANNERS)
        if banner in ADMIN_BANNERS:
            response_text = f"""
<!DOCTYPE html>
<html>
<head><title>{banner}</title></head>
<body>
<h1>{banner}</h1>
<p>Database Management Interface</p>
</body>
</html>
            """
            return response_text, 200
        else:
            response_text = f"""
ERROR 1130 (HY000): Host '127.0.0.1' is not allowed to connect to this MySQL server\n
MySQL [{banner}]
Server socket: '/var/run/mysqld/mysqld.sock'
Server version: {banner}
            """
            return response_text, 403
    
    error = random.choice(MYSQL_ERRORS).format(username, "YES" if password else "NO")
    if query and any(word in query.upper() for word in ["SELECT", "DROP", "INSERT", "UPDATE", "DELETE"]):
        error = random.choice([e for e in MYSQL_ERRORS if "syntax" in e.lower()])
    response = {
        "error": error,
        "status": random.choice([400, 403, 404])
    }
    return jsonify(response), response["status"]

@fake_services.route("/ftp", methods=["GET", "POST"])
def fake_ftp():
    ip = get_ip(request)
    username = request.form.get("username", "Anonymous")
    password = request.form.get("password", "")
    command = request.form.get("command", "")
    if not command:
        if request.method == "POST":
            command = request.get_data(as_text=True)
        elif request.method == "GET":
            command = request.args.get("command", "")
    data = command if command else "FTP_CONNECTION_ATTEMPT"
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
        "command": command,
        "data": data
    })
    
    adaptive_sleep(ip)
    
    banner = random.choice(FTP_BANNERS)
    error = random.choice(FTP_ERRORS)
    if command.upper() == "LIST":
        files = "\n".join([f"-rw-r--r-- 1 user group {random.randint(100, 2048)} Jan 01 00:00 file{n}.txt" for n in range(1, random.randint(2, 6))])
        response = f"{banner}\n150 Here comes the directory listing.\n{files}\n226 Directory send OK."
        return response, 200
    if command.upper().startswith("USER") or command.upper().startswith("PASS"):
        response = f"{banner}\n{error}"
        return response, 530
    response = f"{banner}\n{error}"
    return response, 503

@fake_services.route("/ssh", methods=["GET", "POST"])
def fake_ssh():
    ip = get_ip(request)
    username = request.form.get("username", "Anonymous")
    password = request.form.get("password", "")
    auth_method = request.form.get("auth_method", "password")
    command = request.form.get("command", "")
    if not command:
        if request.method == "POST":
            command = request.get_data(as_text=True)
        elif request.method == "GET":
            command = request.args.get("command", "")
    data = command if command else "SSH_CONNECTION_ATTEMPT"
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
        "auth_method": auth_method,
        "command": command,
        "data": data
    })
    
    adaptive_sleep(ip)
    
    banner = random.choice(SSH_BANNERS)
    error = random.choice(SSH_ERRORS)
    if command:
        response = f"{banner}\n{command}\n{error}"
    else:
        response = f"{banner}\n{error}"
    return response, 503

# --- The rest of trap routes and simulated vulnerabilities (backup.zip, config.php, debug.log, lfi, xss, sql, upload) remain the same, but now use adaptive_sleep(ip) ---

@fake_services.route("/backup.zip", methods=["GET"])
def fake_backup_zip():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "file": "backup.zip",
        "data": "backup_file_request"
    })
    
    adaptive_sleep(ip)
    return ("PK\x03\x04... (fake backup file) ...", 200, {"Content-Type": "application/zip", "Content-Disposition": "attachment; filename=backup.zip"})

@fake_services.route("/config.php", methods=["GET"])
def fake_config_php():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "file": "config.php",
        "data": "config_file_request"
    })
    
    adaptive_sleep(ip)
    config = """
<?php
$host = 'localhost';
$user = 'root';
$pass = 'root';
$db = 'mydb';
// ...
?>
"""
    return (config, 200, {"Content-Type": "text/plain"})

@fake_services.route("/debug.log", methods=["GET"])
def fake_debug_log():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "file": "debug.log",
        "data": "debug_log_request"
    })
    
    adaptive_sleep(ip)
    log = "[01-Jun-2025 12:00:00 UTC] PHP Warning:  Invalid argument supplied for foreach() in /var/www/html/wp-content/plugins/example.php on line 42\n"
    return (log, 200, {"Content-Type": "text/plain"})

@fake_services.route("/lfi", methods=["GET"])
def fake_lfi():
    ip = get_ip(request)
    
    file = request.args.get('file', '')
    
    # Log the request
    create_log(request, {
        "file": file,
        "payload": file
    })
    
    adaptive_sleep(ip)
    if "passwd" in file:
        return ("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n", 200, {"Content-Type": "text/plain"})
    elif ".." in file:
        return ("Warning: include({}): failed to open stream: No such file or directory in /var/www/html/lfi.php on line 13".format(file), 200, {"Content-Type": "text/plain"})
    else:
        return ("", 200, {"Content-Type": "text/plain"})

@fake_services.route("/xss", methods=["GET", "POST"])
def fake_xss():
    ip = get_ip(request)
    
    param = request.args.get('q', '') or request.form.get('q', '')
    
    # Log the request
    create_log(request, {
        "parameter": param,
        "payload": param
    })
    
    adaptive_sleep(ip)
    if "document.cookie" in param or "alert(" in param:
        redis_client.setex(f"xss:cookie:{ip}", 600, 1)
    if param:
        return f'<html><body>You searched for: {param}</body></html>', 200
    return '<html><body>Enter a search parameter.</body></html>', 200

@fake_services.route("/sql", methods=["GET", "POST"])
def fake_sql():
    ip = get_ip(request)
    
    param = request.args.get('id', '') or request.form.get('id', '')
    
    # Log the request
    create_log(request, {
        "parameter": param,
        "payload": param
    })
    
    adaptive_sleep(ip)
    if param and ("'" in param or "--" in param or "1=1" in param):
        return "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{}' at line 1".format(param), 200
    return "No results found.", 200

@fake_services.route("/upload", methods=["POST"])
def simple_upload():
    """
    Simple file upload endpoint that saves files to /uploads and logs them in database.
    """
    ip = get_ip(request)
    adaptive_sleep(ip)
    
    if "file" not in request.files:
        return jsonify({"message": "No file found in the request", "status": 400}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "File name is empty", "status": 400}), 400
    
    try:
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Sanitizar el nombre de archivo para prevenir path traversal
        original_filename = file.filename
        sanitized_filename = sanitize_filename(original_filename)
        
        # Detectar si hubo un intento de path traversal
        if sanitized_filename == "blocked_traversal_attempt":
            # Log intento malicioso
            create_log(request, {
                "attack_type": "path_traversal_upload",
                "severity": "high",
                "payload": original_filename,
                "blocked": True,
                "description": "Path traversal attempt detected in file upload"
            })
            return jsonify({
                "message": "Invalid filename detected",
                "status": "error",
                "error": "Security violation: Path traversal attempt"
            }), 400
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{sanitized_filename}"
        file_path = os.path.join(uploads_dir, filename)
        
        # Verificación adicional: asegurar que el path final esté dentro de uploads_dir
        real_uploads_dir = os.path.realpath(uploads_dir)
        real_file_path = os.path.realpath(file_path)
        
        if not real_file_path.startswith(real_uploads_dir):
            create_log(request, {
                "attack_type": "path_traversal_upload",
                "severity": "critical",
                "payload": original_filename,
                "blocked": True,
                "description": "Path traversal attempt bypassed sanitization"
            })
            return jsonify({
                "message": "Security violation detected",
                "status": "error",
                "error": "Invalid file path"
            }), 400
        
        # Save the file
        file.save(file_path)
        
        # Calculate file hash
        file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Log the upload with file information
        create_log(request, {
            "attack_type": "file_upload",
            "severity": "medium",
            "payload": str(request.form.to_dict()),
            "file": {
                "original_filename": original_filename,
                "sanitized_filename": sanitized_filename,
                "final_filename": filename,
                "content_type": file.content_type or mimetypes.guess_type(file.filename)[0],
                "size": file_size
            },
            "file_hash": file_hash,
            "stored_path": file_path,
            "security_check": "passed"
        })
        
        return jsonify({
            "message": "File uploaded successfully",
            "status": "success",
            "original_filename": original_filename,
            "sanitized_filename": sanitized_filename,
            "saved_as": filename,
            "upload_time": datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            "message": "Upload failed",
            "status": "error",
            "error": str(e)
        }), 500

# --- Interactive administration panel and escalation ---
@fake_services.route("/admin/panel", methods=["GET"])
def fake_admin_panel():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    return '''
    <html><head><title>Administration Panel</title></head><body>
    <h1>Welcome, admin</h1>
    <ul>
        <li><a href="/admin/settings">Settings</a></li>
        <li><a href="/admin/backup">Download backup</a></li>
        <li><a href="/admin/users">User management</a></li>
    </ul>
    </body></html>
    ''', 200

@fake_services.route("/admin/settings", methods=["GET"])
def fake_admin_settings():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    return '''<html><body><h2>System Settings</h2><p>Option disabled.</p></body></html>''', 200

@fake_services.route("/admin/backup", methods=["GET"])
def fake_admin_backup():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    return ("PK\x03\x04... (fake admin backup) ...", 200, {"Content-Type": "application/zip", "Content-Disposition": "attachment; filename=admin-backup.zip"})

@fake_services.route("/admin/users", methods=["GET"])
def fake_admin_users():
    ip = get_ip(request)
    fake_users = [
        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
        {"id": 2, "username": "user1", "email": "user1@example.com", "role": "user"},
        {"id": 3, "username": "test", "email": "test@example.com", "role": "user"},
    ]
    return jsonify(fake_users), 200

# --- REST API trap ---
@fake_services.route("/api/v1/users", methods=["GET"])
def fake_api_users():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "user_list_request"
    })
    
    key = f"api:users:{ip}"
    count = get_fail_count(key)
    inc_fail_count(key)
    base_users = [
        {"id": 1, "username": "admin"},
        {"id": 2, "username": "user1"},
    ]
    if count > 3:
        base_users.append({"id": 3, "username": "test", "email": "test@example.com", "role": "user"})
    return jsonify(base_users), 200

@fake_services.route("/api/v1/settings", methods=["GET"])
def fake_api_settings():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "settings_request"
    })
    
    key = f"api:settings:{ip}"
    count = get_fail_count(key)
    inc_fail_count(key)
    settings = {"maintenance": False, "version": "1.2.3"}
    if count > 2:
        settings["db_password"] = "root"
    return jsonify(settings), 200

# --- Advanced deception: personalized responses by User-Agent ---
@fake_services.before_request
def advanced_deception():
    ua = request.headers.get("User-Agent", "").lower()
    ip = get_ip(request)
    # If the IP is very insistent, simulate firewall
    if get_fail_count(f"fail:admin:{ip}") > 10 or get_fail_count(f"fail:wp:{ip}") > 10:
        return "<h1>403 Forbidden - Your IP has been blocked by the firewall</h1>", 403
    if "sqlmap" in ua:
        time.sleep(2)
        return "<h1>Access denied for automated tools</h1>", 403
    if "nmap" in ua or "nikto" in ua:
        time.sleep(1)
        return "Service temporarily unavailable", 503
    # Only respond with fake banner if the route is /ftp or /telnet
    if "curl" in ua and request.path in ["/ftp", "/telnet"]:
        return "220 Welcome to FTP Service\r\n", 200, {"Content-Type": "text/plain"}

# --- Dynamic trap files with personalized content ---
@fake_services.route("/leak-<name>.sql", methods=["GET"])
def fake_leak_sql(name):
    sql = f"""
-- phpMyAdmin SQL Dump
-- version 5.1.1
-- Host: localhost    Database: {name}
-- --------------------------------------------------------
--
-- Table structure for table `users`
--
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL
);

--
-- Dumping data for table `users`
--
INSERT INTO `users` VALUES (1,'admin','21232f297a57a5a743894a0e4a801fc3'),(2,'user1','ee11cbb19052e40b07aac0ca060c23ee');
"""
    return (sql, 200, {"Content-Type": "application/sql", "Content-Disposition": f"attachment; filename={name}.sql"})

# --- Vulnerabilidades encadenadas ---

# After successful SSRF, expose a new internal route for that IP
@fake_services.route("/ssrf", methods=["GET"])
def fake_ssrf():
    ip = get_ip(request)
    url = request.args.get('url', '')
    
    # Log the request
    create_log(request, {
        "target_url": url,
    })
    
    adaptive_sleep(ip)
    if "localhost" in url or "127.0.0.1" in url or "admin" in url:
        # Mark in Redis that the IP can access /internal-panel
        redis_client.setex(f"ssrf:internal:{ip}", 600, 1)
        return "<pre>Admin panel found: /internal-panel (access denied)</pre>", 200
    elif "169.254." in url or "metadata" in url:
        return "<pre>Metadata service: Access denied</pre>", 200
    elif url:
        return f"<pre>Fetched resource: {url} (simulado)</pre>", 200
    return "<pre>No URL provided</pre>", 200

@fake_services.route("/internal-panel", methods=["GET"])
def fake_internal_panel():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    allowed = redis_client.get(f"ssrf:internal:{ip}")
    if allowed:
        return "<html><body><h1>Internal Admin Panel</h1><p>Access granted via SSRF!</p><p>Secret: FLAG{ssrf_chain_flag}</p></body></html>", 200
    return "<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>", 403

# After XSS, simulate cookie theft and access to a secret route

@fake_services.route("/stolen-cookie", methods=["GET"])
def fake_stolen_cookie():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    allowed = redis_client.get(f"xss:cookie:{ip}")
    if allowed:
        return "<html><body><h1>Cookie stolen</h1><p>Flag: FLAG{xss_chain_flag}</p></body></html>", 200
    return "<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>", 403

# After RCE, expose a special flag if executing a specific command
@fake_services.route("/rce", methods=["GET", "POST"])
def fake_rce():
    ip = get_ip(request)
    cmd = request.args.get('cmd', '') or request.form.get('cmd', '')
    
    # Log the request
    create_log(request, {
        "command": cmd,
    })
    
    adaptive_sleep(ip)
    # If it executes cat /flag, mark in Redis
    if "cat /flag" in cmd or "type flag.txt" in cmd:
        redis_client.setex(f"rce:flag:{ip}", 600, 1)
        return "FLAG{fake_flag_for_honeypot}", 200
    elif "ls" in cmd or "dir" in cmd:
        return "uploads/\nconfig.php\ndebug.log\nbackup.zip\n", 200
    elif "whoami" in cmd:
        return "www-data", 200
    elif cmd:
        return f"Command '{cmd}' executed (simulated)", 200
    return "No command provided", 200

@fake_services.route("/flag-access", methods=["GET"])
def fake_flag_access():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "flag_access_attempt"
    })
    
    allowed = redis_client.get(f"rce:flag:{ip}")
    if allowed:
        return "<html><body><h1>Special flag</h1><p>Flag: FLAG{rce_chain_flag}</p></body></html>", 200
    return "<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>", 403

# --- Open Redirect ---
@fake_services.route("/redirect", methods=["GET"])
def fake_redirect():
    ip = get_ip(request)
    
    # Log the request
    target = request.args.get('url', '')
    create_log(request, {
        "target_url": target,
        "data": f"redirect_attempt_to_{target}"
    })
    
    adaptive_sleep(ip)
    if target:
        return redirect(target)
    return "No URL provided", 400

# --- Realism improvements: sessions, cookies, interactive panels, trap files and flags ---
@fake_services.route("/login", methods=["GET", "POST"])
def fake_login():
    ip = get_ip(request)
    
    username = request.form.get("username", "") if request.method == "POST" else None
    password = request.form.get("password", "") if request.method == "POST" else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    if request.method == "POST":
        resp = make_response(redirect(url_for('fake_services.fake_dashboard')))
        resp.set_cookie("sessionid", hashlib.md5(f"{username}{password}".encode()).hexdigest())
        return resp
    return '''<form method="POST"><input name="username"><input name="password" type="password"><button>Login</button></form>''', 200

@fake_services.route("/home", methods=["GET"])
def fake_home():
    """Endpoint for logging access to the main page"""
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "home_page_request"
    })
    
    adaptive_sleep(ip)
    
    # Simulate a simple response for logging
    return jsonify({
        "message": "Home page accessed",
        "timestamp": datetime.now().isoformat(),
        "ip": ip
    }), 200

@fake_services.route("/dashboard", methods=["GET"])
def fake_dashboard():
    """JSON endpoint to get dashboard data"""
    ip = get_ip(request)
    sessionid = request.cookies.get("sessionid", "")
    
    # Log the request
    create_log(request, {
        "sessionid": sessionid,
        "data": "dashboard_access_attempt"
    })
    
    # Generate dynamic data
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uptime = f"{random.randint(15, 30)} days, {random.randint(1, 23)} hours, {random.randint(1, 59)} minutes"
    active_users = random.randint(1200, 1500)
    total_requests = random.randint(50000, 100000)
    
    data = {
        "stats": {
            "users": active_users,
            "sessions": total_requests,
            "uptime": uptime,
            "alerts": random.randint(8, 15)
        },
        "systemStatus": {
            "authentication": "online",
            "database": "online",
            "api_gateway": "online",
            "file_storage": "online"
        },
        "recentActivity": [
            {
                "id": 1,
                "type": "login",
                "user": "admin",
                "message": f"User admin logged in successfully from IP {ip}",
                "time": "2 minutes ago",
                "status": "success"
            },
            {
                "id": 2,
                "type": "file",
                "user": "system",
                "message": "Backup completed successfully",
                "time": "5 minutes ago",
                "status": "success"
            },
            {
                "id": 3,
                "type": "alert",
                "user": "security",
                "message": f"Suspicious activity detected from IP {ip}",
                "time": "10 minutes ago",
                "status": "warning"
            }
        ],
        "lastUpdate": current_time,
        "flag": "FLAG{dashboard_fake_flag}" if sessionid else None
    }
    
    return jsonify(data), 200

@fake_services.route("/dashboard/files", methods=["GET"])
def fake_dashboard_files():
    """JSON endpoint to get file data"""
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "Dashboard files access"
    })
    
    adaptive_sleep(ip)
    
    files = [
        {"name": "leak-users.sql", "size": "2.3 MB", "date": "2024-01-15", "type": "Database dump"},
        {"name": "backup.zip", "size": "45.7 MB", "date": "2024-01-14", "type": "System backup"},
        {"name": "config.php", "size": "1.2 KB", "date": "2024-01-13", "type": "Configuration"},
        {"name": "debug.log", "size": "8.9 MB", "date": "2024-01-15", "type": "Debug log"},
        {"name": "error.log", "size": "3.1 MB", "date": "2024-01-15", "type": "Error log"},
        {"name": "access.log", "size": "12.4 MB", "date": "2024-01-15", "type": "Access log"}
    ]
    
    return jsonify({"files": files}), 200

@fake_services.route("/dashboard/settings", methods=["GET"])
def fake_dashboard_settings():
    """JSON endpoint to get configuration data"""
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "Dashboard settings access"
    })
    
    adaptive_sleep(ip)
    
    settings = {
        "security_mode": "High",
        "api_key": "sk-1234567890abcdef1234567890abcdef",
        "database_url": "mysql://admin:password@localhost:3306/enterprise_db",
        "redis_url": "redis://localhost:6379",
        "backup_frequency": "Daily",
        "log_level": "INFO",
        "max_connections": "1000",
        "session_timeout": "30 minutes"
    }
    
    return jsonify({"settings": settings}), 200

# --- ADVANCED HONEYPOT ENDPOINTS ---

# 1. Modern API endpoints
@fake_services.route('/api/v2/graphql', methods=['POST'])
def fake_graphql():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": request.get_data(as_text=True)[:500] if request.get_data() else None
    })
    
    adaptive_sleep(ip)
    if 'Authorization' not in request.headers:
        return jsonify({'error': 'Missing Authorization header', 'code': 'UNAUTHORIZED'}), 401
    token = request.headers.get('Authorization').replace('Bearer ', '')
    try:
        jwt.decode(token, 'fake_secret', algorithms=['HS256'])
    except Exception:
        return jsonify({'error': 'JWT expired or invalid', 'code': 'JWT_EXPIRED'}), 403
    if 'mutation' in request.get_data(as_text=True):
        return jsonify({'errors': [{'message': 'CSRF token invalid', 'code': 'CSRF_INVALID'}]}), 403
    return jsonify({'data': {'user': {'id': 1, 'username': 'admin'}}})

@fake_services.route('/api/v1/auth/refresh', methods=['POST'])
def fake_auth_refresh():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
    })
    
    adaptive_sleep(ip)
    return jsonify({'error': 'Refresh token invalid', 'code': 'INVALID_REFRESH_TOKEN'}), 401

@fake_services.route('/api/v1/payments', methods=['POST'])
def fake_payments():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "payment_request"
    })
    
    adaptive_sleep(ip)
    return jsonify({'error': 'Payment declined', 'code': 'PAYMENT_DECLINED'}), 402

# 2. Additional Web vulnerabilities
@fake_services.route('/xxe', methods=['POST'])
def fake_xxe():
    ip = get_ip(request)
    xml_data = request.get_data(as_text=True)
    
    # Log the request
    create_log(request, {
        "xml_data": xml_data[:500],  # Limit data size
    })
    
    adaptive_sleep(ip)
    if '<!ENTITY' in xml_data:
        return Response('<result>root:x:0:0:root:/root:/bin/bash</result>', mimetype='application/xml')
    try:
        ET.fromstring(xml_data)
        return Response('<result>OK</result>', mimetype='application/xml')
    except Exception as e:
        return Response(f'<error>{str(e)}</error>', mimetype='application/xml')

@fake_services.route('/deserialize', methods=['POST'])
def fake_deserialize():
    ip = get_ip(request)
    data = request.get_data()
    
    # Log the request
    create_log(request, {
        "data_size": len(data),
    })
    
    adaptive_sleep(ip)
    try:
        obj = pickle.loads(data)
        return jsonify({'result': 'Object deserialized', 'type': str(type(obj))})
    except Exception as e:
        return jsonify({'error': 'Deserialization failed', 'detail': str(e)}), 400

@fake_services.route('/traversal', methods=['GET'])
def fake_traversal():
    ip = get_ip(request)
    file_param = request.args.get('file', '')
    adaptive_sleep(ip)
    path = file_param
    if '../../' in path or '..\\' in path:
        if 'shadow' in path:
            return Response('root:$6$saltsalt$hashhash:18295:0:99999:7:::', mimetype='text/plain')
        return Response(f'No such file or directory: {path}', mimetype='text/plain')
    return Response('File not found', mimetype='text/plain')

# 3. Simulation of popular panels and services
@fake_services.route('/joomla/administrator', methods=['GET', 'POST'])
def fake_joomla_admin():
    ip = get_ip(request)
    username = request.form.get('username', '') if request.method == 'POST' else None
    password = request.form.get('password', '') if request.method == 'POST' else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    if request.method == 'POST':
        return '<h1>Joomla Admin - Access denied</h1>', 403
    return '<h1>Joomla! Administrator Login</h1>', 200

@fake_services.route('/drupal/user/login', methods=['GET', 'POST'])
def fake_drupal_login():
    ip = get_ip(request)
    username = request.form.get('username', '') if request.method == 'POST' else None
    password = request.form.get('password', '') if request.method == 'POST' else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    if request.method == 'POST':
        return '<h1>Drupal Login - Access denied</h1>', 403
    return '<h1>Drupal User Login</h1>', 200

@fake_services.route('/magento/admin', methods=['GET', 'POST'])
def fake_magento_admin():
    ip = get_ip(request)
    username = request.form.get('username', '') if request.method == 'POST' else None
    password = request.form.get('password', '') if request.method == 'POST' else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    if request.method == 'POST':
        return '<h1>Magento Admin - Access denied</h1>', 403
    return '<h1>Magento Admin Login</h1>', 200

@fake_services.route('/smtp/login', methods=['POST'])
def fake_smtp_login():
    ip = get_ip(request)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    return '535 5.7.8 Authentication credentials invalid', 535

@fake_services.route('/webmail', methods=['GET', 'POST'])
def fake_webmail():
    ip = get_ip(request)
    username = request.form.get('username', '') if request.method == 'POST' else None
    password = request.form.get('password', '') if request.method == 'POST' else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    adaptive_sleep(ip)
    if request.method == 'POST':
        return '<h1>Webmail - Access denied</h1>', 403
    return '<h1>Webmail Login</h1>', 200

@fake_services.route('/router/login', methods=['GET', 'POST'])
def fake_router_login():
    ip = get_ip(request)
    username = request.form.get('username', '') if request.method == 'POST' else None
    password = request.form.get('password', '') if request.method == 'POST' else None
    
    # Log the request
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    adaptive_sleep(ip)
    if request.method == 'POST':
        return '<h1>Router Login - Access denied</h1>', 403
    return '<h1>Router Login</h1>', 200

@fake_services.route('/iot/status', methods=['GET'])
def fake_iot_status():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "IoT device status request"
    })
    
    adaptive_sleep(ip)
    return jsonify({'status': 'online', 'firmware': 'v1.2.3', 'flag': 'FLAG{iot_fake_flag}'}), 200

# 4. Interaction and persistence
@fake_services.route('/api/v1/session', methods=['GET'])
def fake_session():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "Session token request"
    })
    
    adaptive_sleep(ip)
    token = jwt.encode({'ip': ip, 'user': 'admin'}, 'fake_secret', algorithm='HS256')
    resp = jsonify({'session': token})
    resp.set_cookie('jwt', token)
    return resp

@fake_services.route('/logs/access.log', methods=['GET'])
def fake_access_log():
    log = '127.0.0.1 - - [01/Jun/2025:12:00:00 +0000] "GET /admin HTTP/1.1" 403 -\n192.168.1.1 - - [01/Jun/2025:12:01:00 +0000] "POST /wp-login.php HTTP/1.1" 403 -'
    return Response(log, mimetype='text/plain')

@fake_services.route('/logs/error.log', methods=['GET'])
def fake_error_log():
    log = '[01-Jun-2025 12:00:00 UTC] PHP Fatal error:  Uncaught Exception: Simulated stack trace...\n  thrown in /var/www/html/index.php on line 42'
    return Response(log, mimetype='text/plain')

# 5. Adaptive and deceptive responses (there's already before_request, but we add explicit WAF)
@fake_services.route('/waf', methods=['GET', 'POST'])
def fake_waf():
    ip = get_ip(request)
    user_agent = request.headers.get('User-Agent', '')
    query = request.args.get('q', '')
    
    # Log the request
    create_log(request, {
        "user_agent": user_agent,
        "query": query,
    })
    
    adaptive_sleep(ip)
    if 'sqlmap' in request.headers.get('User-Agent', '').lower():
        return '<h1>403 Forbidden - WAF detected SQLi tool</h1>', 403
    if 'payload' in request.args.get('q', ''):
        return '<h1>403 Forbidden - WAF detected malicious payload</h1>', 403
    return '<h1>WAF: Request allowed</h1>', 200

# 6. Integration with external systems
@fake_services.route('/webhook/github', methods=['POST'])
def fake_github_webhook():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "GitHub webhook request"
    })
    
    adaptive_sleep(ip)
    return jsonify({'message': 'GitHub webhook received', 'status': 'ok'}), 200

@fake_services.route('/webhook/stripe', methods=['POST'])
def fake_stripe_webhook():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "data": "Stripe webhook request"
    })
    
    adaptive_sleep(ip)
    return jsonify({'message': 'Stripe webhook received', 'status': 'ok'}), 200

@fake_services.route('/api/v1/keys', methods=['GET'])
def fake_api_keys():
    return jsonify({'api_key': 'sk_test_FAKEKEY123456', 'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE.PAYLOAD'}), 200

# 7. Simulation of system failures and errors
@fake_services.route('/unstable', methods=['GET'])
def fake_unstable():
    code = random.choice([500, 502, 504])
    if code == 500:
        return '<h1>500 Internal Server Error</h1><pre>Traceback (most recent call last):\n  File "/app/app.py", line 42, in main\n    raise Exception("Simulated error")\nException: Simulated error</pre>', 500
    elif code == 502:
        return '<h1>502 Bad Gateway</h1>', 502
    else:
        return '<h1>504 Gateway Timeout</h1>', 504

# 8. File upload simulation
# Simple file upload without analysis

# 9. Simulation of network services (banners)
@fake_services.route('/telnet', methods=['GET', 'POST'])
def fake_telnet():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "service": "telnet",
    })
    
    adaptive_sleep(ip)
    return Response('Welcome to Fake Telnet Service\r\nlogin: ', mimetype='text/plain')

@fake_services.route('/pop3', methods=['GET', 'POST'])
def fake_pop3():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "service": "pop3",
    })
    
    adaptive_sleep(ip)
    return Response('+OK POP3 server ready <1234.5678@fakepop3>\r\n', mimetype='text/plain')

@fake_services.route('/imap', methods=['GET', 'POST'])
def fake_imap():
    ip = get_ip(request)
    
    # Log the request
    create_log(request, {
        "service": "imap",
    })
    
    adaptive_sleep(ip)
    return Response('* OK IMAP4rev1 Fake IMAP Service Ready\r\n', mimetype='text/plain')



redis_client = get_redis_client()

def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.
    Implements multiple layers of security.
    """
    if not filename or not isinstance(filename, str):
        return "unknown_file"
    
    # 1. Detect path traversal attempts
    dangerous_patterns = [
        '../', '..\\', '..%2f', '..%5c', '..%252f', '..%255c',
        '%2e%2e%2f', '%2e%2e%5c', '%2e%2e/', '%2e%2e\\',
        '..\u002f', '..\u005c', '\u002e\u002e\u002f', '\u002e\u002e\u005c'
    ]
    
    filename_lower = filename.lower()
    for pattern in dangerous_patterns:
        if pattern in filename_lower:
            # Log path traversal attempt
            return "blocked_traversal_attempt"
    
    # 2. Use os.path.basename to remove any path
    filename = os.path.basename(filename)
    
    # 3. Remove dangerous and control characters
    # Keep only: letters, numbers, dots, hyphens, underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # 4. Prevent special Windows/Unix filename
    reserved_names = {
        'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5',
        'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5',
        'lpt6', 'lpt7', 'lpt8', 'lpt9'
    }
    
    name_without_ext = filename.split('.')[0].lower()
    if name_without_ext in reserved_names:
        filename = f"safe_{filename}"
    
    # 5. Limit filename length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    
    # 6. Ensure it's not empty after sanitization
    if not filename or filename == '.' or filename == '..':
        filename = "sanitized_file"
    
    # 7. Ensure it doesn't start with dot (hidden files)
    if filename.startswith('.'):
        filename = 'file_' + filename[1:]
    
    return filename

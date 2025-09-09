import sqlite3
from datetime import datetime, timezone, timedelta
from patterns import get_payload_patterns, get_headers_patterns, get_ftp_patterns, get_ssh_patterns
from services.redis_singleton import get_redis_client
import re
from collections import Counter
import ast
import json
from config import Config
from utils.logger import get_logger
import numpy as np
from collections import defaultdict
import requests

redis_client = get_redis_client()
logger = get_logger(__name__)

def add_column_if_not_exists(cursor, table, column, coltype):
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [info[1] for info in cursor.fetchall()]
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

def init_db():
    """Initializes the database and creates necessary tables."""
    conn = sqlite3.connect(Config.SQLITE_DB_PATH)
    cursor = conn.cursor()

    # Create table for IP profiles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            first_seen TEXT,
            last_seen TEXT,
            total_requests INTEGER DEFAULT 0,
            suspicious_requests INTEGER DEFAULT 0,
            database_attempts INTEGER DEFAULT 0,
            sql_injection_attempts INTEGER DEFAULT 0,
            admin_attempts INTEGER DEFAULT 0,
            phpmyadmin_attempts INTEGER DEFAULT 0,
            wordpress_attempts INTEGER DEFAULT 0,
            ftp_attempts INTEGER DEFAULT 0,
            ssh_attempts INTEGER DEFAULT 0,
            file_upload_attempts INTEGER DEFAULT 0
        )
    """)

    # Create table for general logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ip_id INTEGER,
            timestamp TEXT,
            path TEXT,
            data TEXT,
            suspicious BOOLEAN,
            method TEXT,
            user_agent TEXT,
            headers TEXT,
            response_time REAL,
            server_execution_time REAL,
            dns TEXT,
            device TEXT,
            os TEXT,
            browser TEXT,
            attack_type TEXT,
            referer TEXT,
            http_status INTEGER,
            request_size INTEGER,
            response_size INTEGER,
            accept_language TEXT,
            request_frequency INTEGER,
            payload_hash TEXT,
            malicious_details TEXT,
            username TEXT,
            password TEXT,
            patterns_detected TEXT,
            is_bot BOOLEAN,
            is_scanner BOOLEAN,
            tool TEXT,
            attack_category TEXT,
            attack_subcategory TEXT,
            attack_matches TEXT,
            abuse_confidence_score INTEGER,
            abuse_country_code TEXT,
            abuse_usage_type TEXT,
            abuse_domain TEXT,
            abuse_total_reports INTEGER,
            abuse_last_reported_at TEXT,
            fingerprint TEXT,
            cve TEXT,
            FOREIGN KEY (ip_id) REFERENCES ip_profiles (id)
        )
    """)

    # Create table for database access attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS database_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            username TEXT,
            password TEXT,
            query TEXT,
            sql_injection BOOLEAN DEFAULT FALSE,
            patterns_detected TEXT,
            success BOOLEAN DEFAULT FALSE,
            response_code INTEGER,
            log_id INTEGER,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # Create table for admin access attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            username TEXT,
            password TEXT,
            success BOOLEAN DEFAULT FALSE,
            response_code INTEGER,
            admin_panel_type TEXT,
            log_id INTEGER,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # Create table for FTP access attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ftp_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            username TEXT,
            password TEXT,
            command TEXT,
            success BOOLEAN DEFAULT FALSE,
            response_code INTEGER,
            log_id INTEGER,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # Create table for SSH access attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssh_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            username TEXT,
            password TEXT,
            auth_method TEXT,
            success BOOLEAN DEFAULT FALSE,
            response_code INTEGER,
            log_id INTEGER,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # Create table for suspicious file uploads
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            filename TEXT,
            file_type TEXT,
            file_size INTEGER,
            file_hash TEXT,
            malware_score REAL DEFAULT 0,
            is_suspicious BOOLEAN DEFAULT FALSE,
            stored_path TEXT,
            log_id INTEGER,
            analysis_report TEXT,
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # If the analysis_report column does not exist, add it
    add_column_if_not_exists(cursor, "file_uploads", "analysis_report", "TEXT")
    add_column_if_not_exists(cursor, "file_uploads", "upload_time", "TEXT")

    # Ensure new columns are added to logs
    add_column_if_not_exists(cursor, "logs", "attack_category", "TEXT")
    add_column_if_not_exists(cursor, "logs", "attack_subcategory", "TEXT")
    add_column_if_not_exists(cursor, "logs", "attack_matches", "TEXT")
    # Threat intelligence fields
    add_column_if_not_exists(cursor, "logs", "abuse_confidence_score", "INTEGER")
    add_column_if_not_exists(cursor, "logs", "abuse_country_code", "TEXT")
    add_column_if_not_exists(cursor, "logs", "abuse_usage_type", "TEXT")
    add_column_if_not_exists(cursor, "logs", "abuse_domain", "TEXT")
    add_column_if_not_exists(cursor, "logs", "abuse_total_reports", "INTEGER")
    add_column_if_not_exists(cursor, "logs", "abuse_last_reported_at", "TEXT")
    add_column_if_not_exists(cursor, "logs", "fingerprint", "TEXT")
    add_column_if_not_exists(cursor, "logs", "cve", "TEXT")

    # Database tables created successfully - no sample data inserted

    # Always insert some additional sample data to ensure there is data
    today = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    additional_logs = [
        ("192.168.1.101", today, "/admin/login", "POST", "Mozilla/5.0", "admin_login", "cms", True),
        ("10.0.0.51", today, "/phpmyadmin", "GET", "curl/7.68.0", "phpmyadmin_probe", "database", False),
        ("172.16.0.26", today, "/ssh", "POST", "ssh-client", "ssh_probe", "ssh", False),
    ]
    
    for ip, timestamp, path, method, user_agent, attack_type, attack_category, suspicious in additional_logs:
        cursor.execute("""
            INSERT OR IGNORE INTO logs (ip, timestamp, path, method, user_agent, attack_type, attack_category, suspicious, http_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, timestamp, path, method, user_agent, attack_type, attack_category, suspicious, 403))

    conn.commit()
    conn.close()

def save_request_to_history(ip):
    """Saves a request to the temporary history in Redis."""
    timestamp = datetime.now(timezone.utc).isoformat()
    key = f"request_history:{ip}"
    redis_client.lpush(key, timestamp)
    redis_client.expire(key, 300)  # Expire after 5 minutes

def calculate_request_frequency(ip):
    """Calculates the request frequency for an IP in the last minutes using Redis."""
    key = f"request_history:{ip}"
    current_time = datetime.now(timezone.utc)
    five_minutes_ago = (current_time - timedelta(minutes=5)).isoformat()
    
    # Get all requests and filter by time
    requests = redis_client.lrange(key, 0, -1)
    recent_requests = [r for r in requests if r >= five_minutes_ago]
    
    return len(recent_requests)

def detect_patterns(log_entry):
    """Detects suspicious patterns in the log data."""
    patrones_payload = get_payload_patterns()
    patrones_payload.extend(get_ftp_patterns())
    patrones_payload.extend(get_ssh_patterns())
    
    patrones_headers = get_headers_patterns()
    patrones_headers.extend(get_ftp_patterns())
    patrones_headers.extend(get_ssh_patterns())
    
    detected_patterns = []
    
    # Analyze payload
    if log_entry.get("data"):
        for patron in patrones_payload:
            if re.search(patron, log_entry["data"], re.IGNORECASE):
                detected_patterns.append(f"payload:{patron}")
    
    # Analyze headers
    if log_entry.get("headers"):
        headers_str = str(log_entry["headers"])
        for patron in patrones_headers:
            if re.search(patron, headers_str, re.IGNORECASE):
                detected_patterns.append(f"header:{patron}")
    
    return detected_patterns

def map_to_general_category(attack_type, attack_category, path):
    """
    Returns a dict with general flags (is_admin, is_database, etc.)
    based on the attack type/category or path.
    """
    is_admin = False
    is_database = False
    is_phpmyadmin = False
    is_wordpress = False
    is_ftp = False
    is_ssh = False
    is_file_upload = False
    # Mapping by attack type
    admin_types = ["admin_settings_access", "admin_users_access", "admin_backup_access", "admin_panel_probe", "cms", "fake_login", "mail"]
    database_types = ["config_leak", "database_probe", "sqli_attempt", "sql_injection"]
    phpmyadmin_types = ["phpmyadmin_probe", "phpmyadmin_attacks"]
    wordpress_types = ["wordpress_probe", "wp_login", "wp-login.php"]
    ftp_types = ["ftp_probe"]
    ssh_types = ["ssh_probe"]
    file_upload_types = ["file_upload", "upload_attempt"]

    # By type
    if attack_type in admin_types or attack_category in admin_types:
        is_admin = True
    if attack_type in database_types or attack_category in database_types:
        is_database = True
    if attack_type in phpmyadmin_types or attack_category in phpmyadmin_types:
        is_phpmyadmin = True
    if attack_type in wordpress_types or attack_category in wordpress_types:
        is_wordpress = True
    if attack_type in ftp_types or attack_category in ftp_types:
        is_ftp = True
    if attack_type in ssh_types or attack_category in ssh_types:
        is_ssh = True
    if attack_type in file_upload_types or attack_category in file_upload_types:
        is_file_upload = True

    # By path (maintain compatibility)
    if path == "/admin":
        is_admin = True
    if path == "/database":
        is_database = True
    if path == "/phpmyadmin":
        is_phpmyadmin = True
    if path == "/wp-login.php":
        is_wordpress = True
    if path == "/ftp":
        is_ftp = True
    if path == "/ssh":
        is_ssh = True
    if path == "/upload":
        is_file_upload = True

    # Also by partial matches in the path
    if path and path.lower().startswith("/admin"):
        is_admin = True
    if path and "phpmyadmin" in path.lower():
        is_phpmyadmin = True
    if path and "wp-login" in path.lower():
        is_wordpress = True
    if path and "ftp" in path.lower():
        is_ftp = True
    if path and "ssh" in path.lower():
        is_ssh = True
    if path and "upload" in path.lower():
        is_file_upload = True
    if path and "config.php" in path.lower():
        is_database = True
    # NEW: Advanced fake panels/login
    if path and any(p in path.lower() for p in ["/joomla/administrator", "/drupal/user/login", "/magento/admin", "/router/login", "/webmail"]):
        is_admin = True

    return {
        "is_admin": is_admin,
        "is_database": is_database,
        "is_phpmyadmin": is_phpmyadmin,
        "is_wordpress": is_wordpress,
        "is_ftp": is_ftp,
        "is_ssh": is_ssh,
        "is_file_upload": is_file_upload
    }

def send_telegram_alert(message):
    """
    Sends an alert message to Telegram using the bot and chat_id defined in Config.
    """
    if not Config.TELEGRAM_BOT_TOKEN or not Config.TELEGRAM_CHAT_ID:
        logger.warning("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured. No alert will be sent.")
        return
    url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": Config.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, data=data, timeout=10)
        if response.status_code != 200:
            logger.error(f"Error sending alert to Telegram: {response.text}")
    except Exception as e:
        logger.error(f"Exception sending alert to Telegram: {e}")

def save_log_to_db(log_entry):
    """Saves a log to the database and updates the IP profile."""
    logger.info(f"Saving log: {log_entry}")  # Debug
    excluded_routes = ["/logs/analysis", "/logs"]

    # Do not register the log if the path is included in excluded_routes
    if log_entry["path"] in excluded_routes:
        logger.info(f"Excluded path: {log_entry['path']}. Log will not be registered.")
        return

    # Save the request to the temporary history
    save_request_to_history(log_entry["ip"])

    # Detect suspicious patterns
    detected_patterns = detect_patterns(log_entry)
    log_entry["patterns_detected"] = detected_patterns

    conn = None
    try:
        conn = sqlite3.connect(Config.SQLITE_DB_PATH)
        cursor = conn.cursor()

        # Check if the IP already has a profile
        cursor.execute("SELECT id FROM ip_profiles WHERE ip = ?", (log_entry["ip"],))
        ip_profile = cursor.fetchone()

        # --- NEW: use flexible mapping ---
        attack_type = log_entry.get("attack_type")
        attack_category = log_entry.get("attack_category")
        path = log_entry.get("path")
        general_flags = map_to_general_category(attack_type, attack_category, path)
        is_database = general_flags["is_database"]
        is_admin = general_flags["is_admin"]
        is_phpmyadmin = general_flags["is_phpmyadmin"]
        is_wordpress = general_flags["is_wordpress"]
        is_ftp = general_flags["is_ftp"]
        is_ssh = general_flags["is_ssh"]
        is_file_upload = general_flags["is_file_upload"]

        if ip_profile is None:
            logger.info(f"Creating new profile for IP: {log_entry['ip']}")
            cursor.execute("""
                INSERT INTO ip_profiles (
                    ip, first_seen, last_seen, total_requests, suspicious_requests,
                    database_attempts, sql_injection_attempts, admin_attempts,
                    phpmyadmin_attempts, wordpress_attempts, ftp_attempts,
                    ssh_attempts, file_upload_attempts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"],
                log_entry["timestamp"],
                log_entry["timestamp"],
                1,
                1 if log_entry["suspicious"] else 0,
                1 if is_database else 0,
                1 if log_entry.get("attack_type") == "sql_injection" else 0,
                1 if is_admin else 0,
                1 if is_phpmyadmin else 0,
                1 if is_wordpress else 0,
                1 if is_ftp else 0,
                1 if is_ssh else 0,
                1 if is_file_upload else 0
            ))
            ip_id = cursor.lastrowid
        else:
            ip_id = ip_profile[0]
            cursor.execute("""
                UPDATE ip_profiles
                SET last_seen = ?,
                    total_requests = total_requests + 1,
                    suspicious_requests = suspicious_requests + ?,
                    database_attempts = database_attempts + ?,
                    sql_injection_attempts = sql_injection_attempts + ?,
                    admin_attempts = admin_attempts + ?,
                    phpmyadmin_attempts = phpmyadmin_attempts + ?,
                    wordpress_attempts = wordpress_attempts + ?,
                    ftp_attempts = ftp_attempts + ?,
                    ssh_attempts = ssh_attempts + ?,
                    file_upload_attempts = file_upload_attempts + ?
                WHERE id = ?
            """, (
                log_entry["timestamp"],
                1 if log_entry["suspicious"] else 0,
                1 if is_database else 0,
                1 if log_entry.get("attack_type") == "sql_injection" else 0,
                1 if is_admin else 0,
                1 if is_phpmyadmin else 0,
                1 if is_wordpress else 0,
                1 if is_ftp else 0,
                1 if is_ssh else 0,
                1 if is_file_upload else 0,
                ip_id
            ))

        # Save the general log
        def safe_value(val):
            if isinstance(val, (dict, list)):
                return json.dumps(val, ensure_ascii=False)
            return val
        log_columns = [
            "ip", "ip_id", "timestamp", "path", "data", "suspicious", "method", "user_agent", "headers",
            "response_time", "server_execution_time",
            "dns", "device", "os", "browser", "attack_type", "referer", "http_status", "request_size",
            "response_size", "accept_language", "request_frequency", "payload_hash",
            "username", "password", "patterns_detected", "is_bot", "is_scanner", "tool", "attack_category", "attack_subcategory", "attack_matches",
            "abuse_confidence_score", "abuse_country_code", "abuse_usage_type", "abuse_domain", "abuse_total_reports", "abuse_last_reported_at",
            "fingerprint", "cve"
        ]
        log_values = tuple(safe_value(log_entry.get(col, None)) for col in log_columns)
        cursor.execute(f"""
            INSERT INTO logs (
                {', '.join(log_columns)}
            )
            VALUES ({', '.join(['?' for _ in log_columns])})
        """, log_values)
        log_id = cursor.lastrowid

        # Register in specific tables based on attempt type
        if is_database:
            cursor.execute("""
                INSERT INTO database_attempts (
                    ip, timestamp, username, password, query, sql_injection,
                    patterns_detected, success, response_code, log_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"], log_entry["timestamp"],
                log_entry.get("username"), log_entry.get("password"),
                log_entry.get("data"), log_entry.get("attack_type") == "sql_injection",
                str(log_entry.get("patterns_detected", [])), False,
                log_entry.get("http_status", 403), log_id
            ))

        elif is_admin or is_phpmyadmin or is_wordpress:
            cursor.execute("""
                INSERT INTO admin_attempts (
                    ip, timestamp, username, password, success,
                    response_code, admin_panel_type, log_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"], log_entry["timestamp"],
                log_entry.get("username"), log_entry.get("password"),
                False, log_entry.get("http_status", 403),
                "admin" if is_admin else ("phpmyadmin" if is_phpmyadmin else "wordpress"),
                log_id
            ))

        elif is_ftp:
            cursor.execute("""
                INSERT INTO ftp_attempts (
                    ip, timestamp, username, password, command,
                    success, response_code, log_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"], log_entry["timestamp"],
                log_entry.get("username"), log_entry.get("password"),
                log_entry.get("data"), False,
                log_entry.get("http_status", 403), log_id
            ))

        elif is_ssh:
            cursor.execute("""
                INSERT INTO ssh_attempts (
                    ip, timestamp, username, password, auth_method,
                    success, response_code, log_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"], log_entry["timestamp"],
                log_entry.get("username"), log_entry.get("password"),
                log_entry.get("auth_method", "password"),
                False, log_entry.get("http_status", 403), log_id
            ))

        elif is_file_upload and "file" in log_entry:
            cursor.execute("""
                INSERT INTO file_uploads (
                    ip, timestamp, filename, file_type, file_size,
                    file_hash, is_suspicious, stored_path, log_id, analysis_report
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_entry["ip"], log_entry["timestamp"],
                log_entry["file"].get("filename"),
                log_entry["file"].get("content_type"),
                log_entry["file"].get("size", 0),
                log_entry.get("file_hash"),
                True, log_entry.get("stored_path"),
                log_id, log_entry.get("analysis_report", "")
            ))

        conn.commit()
        # --- TELEGRAM ALERT IF SUSPICIOUS ---
        if log_entry.get("suspicious"):
            def val(key, default=None):
                v = log_entry.get(key)
                if v is None or v == "" or v == []:
                    return default
                if isinstance(v, list):
                    return ", ".join(map(str, v))
                return str(v)
            # Professional and readable construction
            lines = [
                "🚨 *Honeypot Alert* 🚨",
                f"*IP:* `{val('ip', 'N/A')}`  |  *Path:* `{val('path', 'N/A')}`",
                f"*Type:* `{val('attack_type', 'N/A')}`  |  *Category:* `{val('attack_category', 'N/A')}`  |  *Subcat:* `{val('attack_subcategory', 'N/A')}`",
                f"*Date:* `{val('timestamp', 'N/A')}`",
                f"*User-Agent:* `{val('user_agent', 'N/A')}`",
            ]
            # Group of indicators
            indicators = []
            if val('is_bot') == 'True' or log_entry.get('is_bot'):
                indicators.append('🤖 Bot')
            if val('is_scanner') == 'True' or log_entry.get('is_scanner'):
                indicators.append('🔎 Scanner')
            if val('tool'):
                indicators.append(f"🛠 {val('tool')}")
            if indicators:
                lines.append("*Indicators:* " + ", ".join(indicators))
            # Patterns
            patterns = val('patterns_detected')
            if patterns:
                lines.append(f"*Patterns:* `{patterns}`")
            # Fingerprint
            if val('fingerprint'):
                lines.append(f"*Fingerprint:* `{val('fingerprint')}`")
            # Threat Intelligence
            abuse_score = val('abuse_confidence_score')
            abuse_country = val('abuse_country_code')
            abuse_reports = val('abuse_total_reports')
            if abuse_score or abuse_country or abuse_reports:
                ti = []
                if abuse_score: ti.append(f"Score: {abuse_score}")
                if abuse_country: ti.append(f"Country: {abuse_country}")
                if abuse_reports: ti.append(f"Reports: {abuse_reports}")
                lines.append("*AbuseIPDB:* " + ", ".join(ti))

            # HTTP and technical
            if val('http_status') or val('response_size') or val('request_frequency'):
                http = []
                if val('http_status'): http.append(f"Status: {val('http_status')}")
                if val('response_size'): http.append(f"Resp: {val('response_size')}B")
                if val('request_frequency'): http.append(f"Freq: {val('request_frequency')}/5min")
                lines.append("*HTTP:* " + ", ".join(http))
            # Payload/Query
            if val('data') and val('data') != 'N/A':
                lines.append(f"*Payload:* `{val('data')}`")
            # Referer
            if val('referer'):
                lines.append(f"*Referer:* `{val('referer')}`")
            # Payload hash
            if val('payload_hash'):
                lines.append(f"*Payload Hash:* `{val('payload_hash')}`")
            # Final line
            lines.append("\n_Automatically generated alert by HoneyGuard_")
            msg = "\n".join(lines)
            send_telegram_alert(msg)
    except sqlite3.Error as e:
        logger.error(f"Error saving log: {e}")
    finally:
        if conn:
            conn.close()

def get_logs():
    """Gets all stored logs."""
    conn = sqlite3.connect(Config.SQLITE_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    columns = [description[0] for description in cursor.description]
    logs = []
    for row in cursor.fetchall():
        log = dict(zip(columns, row))
        # Convert patterns_detected to a real list if possible
        if "patterns_detected" in log and isinstance(log["patterns_detected"], str):
            try:
                log["patterns_detected"] = json.loads(log["patterns_detected"])
            except Exception:
                log["patterns_detected"] = []
        # Convert attack_matches to a real list if possible
        if "attack_matches" in log and isinstance(log["attack_matches"], str):
            try:
                log["attack_matches"] = json.loads(log["attack_matches"])
            except Exception:
                log["attack_matches"] = []
        logs.append(log)
    
    conn.close()
    return logs

def analyze_logs():
    """Performs ultra-advanced analysis of stored logs."""
    conn = sqlite3.connect(Config.SQLITE_DB_PATH)
    cursor = conn.cursor()
    analysis = {
        "general_stats": {},
        "attack_distribution": {},
        "database_attacks": {},
        "admin_panel_attacks": {},
        "file_uploads": {},
        "ssh_ftp_attacks": {},
        "top_attackers": {},
        "temporal_analysis": {},
        "top_tools": [],
        "top_patterns": [],
        "pattern_type_breakdown": {},
        "attack_category_breakdown": {},
        "attack_subcategory_breakdown": {},
        # Advanced:
        "attack_trends": {},
        "coordinated_campaigns": [],
        "outliers": {},
        "attack_sequences": [],
        "correlations": {},
        "top_combinations": {},
        "success_analysis": {},
        "fingerprint_analysis": {},
        "new_attackers": [],
        "persistent_attackers": [],
        "mutating_attackers": [],
        "alerts": [],
        "visualization_data": {},
        "first_last_seen": {},
        "attack_windows": [],
        "top_paths": [],
        "suspicious_user_agents": [],
        "new_user_agents": [],
        "top_payloads": [],
        "retry_persistence": {},
        "emerging_tools_techniques": {},
        "multi_stage_chains": [],
        "attacker_relationships": {},
        "impact_analysis": {},
        "noise_false_positives": {},
        "cve_breakdown": {},
    }
    try:
        # General statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_logs,
                SUM(CASE WHEN suspicious = 1 THEN 1 ELSE 0 END) as suspicious_logs,
                COUNT(DISTINCT ip) as unique_ips,
                COUNT(DISTINCT user_agent) as unique_user_agents,
                SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) as bot_logs,
                SUM(CASE WHEN is_scanner = 1 THEN 1 ELSE 0 END) as scanner_logs
            FROM logs
        """)
        row = cursor.fetchone()
        
        # Get logs for today
        cursor.execute("""
            SELECT COUNT(*) as today_logs
            FROM logs
            WHERE date(timestamp) = date('now')
        """)
        today_row = cursor.fetchone()
        
        analysis["general_stats"] = {
            "total_logs": row[0],
            "suspicious_logs": row[1],
            "unique_ips": row[2],
            "unique_user_agents": row[3],
            "bot_logs": row[4],
            "scanner_logs": row[5],
            "today_logs": today_row[0] if today_row else 0
        }

        # --- NEW: granular and real attack_distribution ---
        cursor.execute("SELECT attack_type, attack_category, attack_subcategory, path FROM logs")
        attack_dist = {
            "admin_attacks": 0,
            "cms_attacks": 0,
            "mail_attacks": 0,
            "api_attacks": 0,
            "system_attacks": 0,
            "database_attacks": 0,
            "file_upload_attacks": 0,
            "ftp_attacks": 0,
            "phpmyadmin_attacks": 0,
            "ssh_attacks": 0,
            "wordpress_attacks": 0,
            "iot_attacks": 0
        }
        for attack_type, attack_category, attack_subcategory, path in cursor.fetchall():
            # Admin: panels, CMS, mail, fake_login
            if attack_category in ["cms", "mail", "fake_login"] or attack_type in ["fake_login"]:
                attack_dist["admin_attacks"] += 1
            if attack_category == "cms":
                attack_dist["cms_attacks"] += 1
            if attack_category == "mail":
                attack_dist["mail_attacks"] += 1
            if attack_category == "api":
                attack_dist["api_attacks"] += 1
            if attack_category == "system":
                attack_dist["system_attacks"] += 1
            if attack_category == "database" or attack_type in ["sql_injection", "sqli_attempt", "database_probe"]:
                attack_dist["database_attacks"] += 1

            if attack_category == "iot" or attack_type in ["iot_probe"]:
                attack_dist["iot_attacks"] += 1
            if attack_category == "file_upload" or attack_type in ["file_upload", "upload_attempt"]:
                attack_dist["file_upload_attacks"] += 1
            if attack_category == "ftp" or attack_type in ["ftp_probe"] or (path and "ftp" in path.lower()):
                attack_dist["ftp_attacks"] += 1
            if attack_category == "phpmyadmin" or attack_type in ["phpmyadmin_probe"] or (path and "phpmyadmin" in path.lower()):
                attack_dist["phpmyadmin_attacks"] += 1
            if attack_category == "ssh" or attack_type in ["ssh_probe"] or (path and "ssh" in path.lower()):
                attack_dist["ssh_attacks"] += 1
            if attack_category == "wordpress" or attack_type in ["wordpress_probe"] or (path and "wp-login" in path.lower()):
                attack_dist["wordpress_attacks"] += 1
        analysis["attack_distribution"] = attack_dist

        # Database attack analysis
        cursor.execute("""
            SELECT 
                COUNT(*) as total_attempts,
                COUNT(DISTINCT ip) as unique_attackers,
                COUNT(CASE WHEN sql_injection = 1 THEN 1 END) as sql_injection_attempts,
                COUNT(DISTINCT username) as unique_usernames
            FROM database_attempts
        """)
        row = cursor.fetchone()
        analysis["database_attacks"] = {
            "total_attempts": row[0],
            "unique_attackers": row[1],
            "sql_injection_attempts": row[2],
            "unique_usernames": row[3]
        }

        # Admin panel attack analysis
        cursor.execute("""
            SELECT 
                admin_panel_type,
                COUNT(*) as attempts,
                COUNT(DISTINCT ip) as unique_ips,
                COUNT(DISTINCT username) as unique_usernames
            FROM admin_attempts
            GROUP BY admin_panel_type
        """)
        analysis["admin_panel_attacks"] = {
            row[0]: {
                "total_attempts": row[1],
                "unique_attackers": row[2],
                "unique_usernames": row[3]
            }
            for row in cursor.fetchall()
        }

        # File upload analysis
        cursor.execute("""
            SELECT 
                COUNT(*) as total_uploads,
                COUNT(DISTINCT ip) as unique_uploaders,
                SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious_files,
                AVG(file_size) as avg_file_size
            FROM file_uploads
        """)
        row = cursor.fetchone()
        analysis["file_uploads"] = {
            "total_uploads": row[0],
            "unique_uploaders": row[1],
            "suspicious_files": row[2],
            "average_file_size": row[3]
        }

        # SSH/FTP attack analysis
        cursor.execute("""
            SELECT 
                'ssh' as type,
                COUNT(*) as attempts,
                COUNT(DISTINCT ip) as unique_ips,
                COUNT(DISTINCT username) as unique_usernames
            FROM ssh_attempts
            UNION ALL
            SELECT 
                'ftp' as type,
                COUNT(*) as attempts,
                COUNT(DISTINCT ip) as unique_ips,
                COUNT(DISTINCT username) as unique_usernames
            FROM ftp_attempts
        """)
        analysis["ssh_ftp_attacks"] = {
            row[0]: {
                "total_attempts": row[1],
                "unique_attackers": row[2],
                "unique_usernames": row[3]
            }
            for row in cursor.fetchall()
        }

        # Top 10 attackers
        cursor.execute("""
            SELECT 
                ip_profiles.ip,
                ip_profiles.total_requests,
                ip_profiles.suspicious_requests,
                ip_profiles.database_attempts,
                ip_profiles.admin_attempts + ip_profiles.phpmyadmin_attempts + ip_profiles.wordpress_attempts as cms_attempts,
                ip_profiles.ftp_attempts + ip_profiles.ssh_attempts as service_attempts
            FROM ip_profiles
            GROUP BY ip_profiles.ip
            ORDER BY ip_profiles.total_requests DESC
            LIMIT 10
        """)
        analysis["top_attackers"] = [
            {
                "ip": row[0],
                "total_requests": row[1],
                "suspicious_requests": row[2],
                "database_attempts": row[3],
                "cms_attempts": row[4],
                "service_attempts": row[5]
            }
            for row in cursor.fetchall()
        ]

        # Geographic distribution removed

        # Temporal analysis (last 24 hours)
        cursor.execute("""
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM logs
            WHERE timestamp >= datetime('now', '-1 day')
            GROUP BY hour
            ORDER BY hour
        """)
        analysis["temporal_analysis"] = {
            f"{int(row[0]):02d}:00": row[1]
            for row in cursor.fetchall()
        }

        # Top tools
        cursor.execute("""
            SELECT tool, COUNT(*) as count FROM logs WHERE tool IS NOT NULL GROUP BY tool ORDER BY count DESC LIMIT 10
        """)
        analysis["top_tools"] = [
            {"tool": row[0], "count": row[1]} for row in cursor.fetchall() if row[0]
        ]

        # Top detected patterns
        cursor.execute("""
            SELECT patterns_detected FROM logs WHERE patterns_detected IS NOT NULL AND patterns_detected != '[]'
        """)
        all_patterns = []
        for row in cursor.fetchall():
            try:
                patterns = ast.literal_eval(row[0])
                all_patterns.extend(patterns)
            except Exception:
                continue
        pattern_counter = Counter(all_patterns)
        analysis["top_patterns"] = pattern_counter.most_common(10)

        # Breakdown by type
        type_counter = Counter()
        for p in all_patterns:
            if p.startswith("payload:"):
                type_counter["payload"] += 1
            elif p.startswith("header:"):
                type_counter["header"] += 1
        analysis["pattern_type_breakdown"] = dict(type_counter)

        # Breakdown by attack category and subcategory
        cursor.execute("SELECT attack_category FROM logs WHERE attack_category IS NOT NULL")
        cat_counter = Counter(row[0] for row in cursor.fetchall() if row[0])
        analysis["attack_category_breakdown"] = dict(cat_counter)
        cursor.execute("SELECT attack_subcategory FROM logs WHERE attack_subcategory IS NOT NULL")
        subcat_counter = Counter(row[0] for row in cursor.fetchall() if row[0])
        analysis["attack_subcategory_breakdown"] = dict(subcat_counter)

        # --- ADVANCED ---
        # 1. Temporal trends (by hour, day, week)
        cursor.execute("""
            SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(*) FROM logs GROUP BY day ORDER BY day
        """)
        by_day = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) FROM logs WHERE timestamp >= datetime('now', '-1 day') GROUP BY hour ORDER BY hour
        """)
        by_hour = {f"{int(row[0]):02d}:00": row[1] for row in cursor.fetchall()}
        # Trend (slope) using real dates
        if len(by_day) > 1:
            days = list(by_day.keys())
            counts = list(by_day.values())
            # Convert days to differences from the first day
            base = datetime.fromisoformat(days[0])
            x = [(datetime.fromisoformat(d) - base).days for d in days]
            slope = float(np.polyfit(x, counts, 1)[0])
        else:
            slope = 0.0
        analysis["attack_trends"] = {"by_day": by_day, "by_hour": by_hour, "trend_slope": slope}
        # 2. Coordinated campaigns (by fingerprint, IP, UA, path, 10min window)
        cursor.execute("SELECT fingerprint, ip, user_agent, path, timestamp FROM logs WHERE fingerprint IS NOT NULL")
        logs = cursor.fetchall()
        campaigns = []
        grouped = defaultdict(list)
        for f, ip, ua, path, ts in logs:
            key = (f, ip, ua, path)
            grouped[key].append(ts)
        for key, times in grouped.items():
            # Fix timestamp parsing
            parsed_times = []
            for t in times:
                try:
                    # Handle different date formats
                    if t.endswith('Z'):
                        # ISO format with Z
                        parsed_times.append(datetime.fromisoformat(t.replace('Z', '+00:00')))
                    elif '+' in t:
                        # ISO format with timezone
                        parsed_times.append(datetime.fromisoformat(t))
                    else:
                        # ISO format without timezone
                        parsed_times.append(datetime.fromisoformat(t + '+00:00'))
                except Exception as e:
                    logger.warning(f"Error parsing timestamp {t}: {e}")
                    continue
            
            if not parsed_times:
                continue
                
            parsed_times = sorted(parsed_times)
            window = timedelta(minutes=10)
            start = 0
            for i in range(1, len(parsed_times)):
                if (parsed_times[i] - parsed_times[start]) > window:
                    if i - start >= 5:
                        campaigns.append({
                            "start": parsed_times[start].isoformat(),
                            "end": parsed_times[i-1].isoformat(),
                            "fingerprint": key[0], "ip": key[1], "user_agent": key[2], "path": key[3], "count": i-start
                        })
                    start = i
            if len(parsed_times) - start >= 5:
                campaigns.append({
                    "start": parsed_times[start].isoformat(),
                    "end": parsed_times[-1].isoformat(),
                    "fingerprint": key[0], "ip": key[1], "user_agent": key[2], "path": key[3], "count": len(parsed_times)-start
                })
        analysis["coordinated_campaigns"] = campaigns
        # 3. Outliers (IPs, fingerprints, UAs, paths)
        cursor.execute("SELECT ip, COUNT(*) FROM logs GROUP BY ip")
        ip_counts = [row[1] for row in cursor.fetchall()]
        if ip_counts:
            mean = np.mean(ip_counts)
            std = np.std(ip_counts)
            cursor.execute("SELECT ip, COUNT(*) FROM logs GROUP BY ip HAVING COUNT(*) > ?", (mean+3*std,))
            outlier_ips = [row[0] for row in cursor.fetchall()]
        else:
            outlier_ips = []
        cursor.execute("SELECT fingerprint, COUNT(*) FROM logs WHERE fingerprint IS NOT NULL GROUP BY fingerprint")
        fp_counts = [row[1] for row in cursor.fetchall()]
        if fp_counts:
            mean_fp = np.mean(fp_counts)
            std_fp = np.std(fp_counts)
            cursor.execute("SELECT fingerprint FROM logs WHERE fingerprint IS NOT NULL GROUP BY fingerprint HAVING COUNT(*) > ?", (mean_fp+3*std_fp,))
            outlier_fps = [row[0] for row in cursor.fetchall()]
        else:
            outlier_fps = []
        cursor.execute("SELECT user_agent, COUNT(*) FROM logs GROUP BY user_agent")
        ua_counts = [row[1] for row in cursor.fetchall()]
        if ua_counts:
            mean_ua = np.mean(ua_counts)
            std_ua = np.std(ua_counts)
            cursor.execute("SELECT user_agent FROM logs GROUP BY user_agent HAVING COUNT(*) > ?", (mean_ua+3*std_ua,))
            outlier_uas = [row[0] for row in cursor.fetchall()]
        else:
            outlier_uas = []
        analysis["outliers"] = {"ips": outlier_ips, "fingerprints": outlier_fps, "user_agents": outlier_uas}
        # 4. Attack sequences (by fingerprint)
        cursor.execute("SELECT fingerprint, path, timestamp FROM logs WHERE fingerprint IS NOT NULL ORDER BY fingerprint, timestamp")
        seq_logs = cursor.fetchall()
        from itertools import groupby
        for fp, group in groupby(seq_logs, lambda x: x[0]):
            events = list(group)
            sequence = [e[1] for e in events]
            timestamps = [e[2] for e in events]
            if len(sequence) > 1:
                analysis["attack_sequences"].append({"fingerprint": fp, "sequence": sequence, "timestamps": timestamps})
        # 5. Correlations (tool vs pattern, path vs pattern)
        cursor.execute("SELECT tool, patterns_detected FROM logs WHERE tool IS NOT NULL AND patterns_detected IS NOT NULL")
        tool_pattern = defaultdict(list)
        for tool, patterns in cursor.fetchall():
            try:
                pats = ast.literal_eval(patterns) if isinstance(patterns, str) else patterns
                for p in pats:
                    tool_pattern[tool].append(p)
            except Exception:
                continue
        tool_vs_pattern = {k: list(set(v)) for k, v in tool_pattern.items()}
        analysis["correlations"]["tool_vs_pattern"] = tool_vs_pattern
        # 6. Top combinations
        cursor.execute("SELECT ip, user_agent, COUNT(*) as c FROM logs GROUP BY ip, user_agent ORDER BY c DESC LIMIT 10")
        analysis["top_combinations"]["ip_user_agent"] = [{"ip": row[0], "user_agent": row[1], "count": row[2]} for row in cursor.fetchall()]
        cursor.execute("SELECT ip, path, COUNT(*) as c FROM logs GROUP BY ip, path ORDER BY c DESC LIMIT 10")
        analysis["top_combinations"]["ip_path"] = [{"ip": row[0], "path": row[1], "count": row[2]} for row in cursor.fetchall()]
        # 7. Success analysis
        cursor.execute("SELECT COUNT(*) FROM logs WHERE http_status BETWEEN 200 AND 399")
        total_success = cursor.fetchone()[0]
        cursor.execute("SELECT attack_type, COUNT(*) FROM logs WHERE http_status BETWEEN 200 AND 399 GROUP BY attack_type")
        by_type = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
        analysis["success_analysis"] = {"successful_attacks": total_success, "by_type": by_type}
        # 8. Advanced fingerprint analysis
        cursor.execute("SELECT fingerprint, COUNT(*) as c FROM logs WHERE fingerprint IS NOT NULL GROUP BY fingerprint ORDER BY c DESC LIMIT 10")
        top_fps = [{"fingerprint": row[0], "count": row[1]} for row in cursor.fetchall()]
        cursor.execute("SELECT fingerprint, COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as days_active FROM logs WHERE fingerprint IS NOT NULL GROUP BY fingerprint HAVING days_active > 1 ORDER BY days_active DESC LIMIT 10")
        persistent = [{"fingerprint": row[0], "days_active": row[1]} for row in cursor.fetchall()]
        analysis["fingerprint_analysis"] = {"top_fingerprints": top_fps, "persistent": persistent}
        # 9. New attackers (last 24 hours)
        cursor.execute("SELECT ip, MIN(timestamp) as first_seen, fingerprint FROM logs WHERE timestamp >= datetime('now', '-1 day') GROUP BY ip, fingerprint")
        for row in cursor.fetchall():
            ip, first_seen, fp = row
            cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ? AND timestamp < ?", (ip, first_seen))
            if cursor.fetchone()[0] == 0:
                analysis["new_attackers"].append({"ip": ip, "first_seen": first_seen, "fingerprint": fp})
        # 10. Persistent attackers (more than 3 days active)
        cursor.execute("SELECT ip, COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as days_active FROM logs GROUP BY ip HAVING days_active > 3 ORDER BY days_active DESC LIMIT 10")
        analysis["persistent_attackers"] = [{"ip": row[0], "days_active": row[1]} for row in cursor.fetchall()]
        # 11. Mutants (IPs with >1 fingerprint, fingerprints with >1 IP)
        cursor.execute("SELECT ip, GROUP_CONCAT(DISTINCT fingerprint), COUNT(DISTINCT fingerprint) FROM logs WHERE fingerprint IS NOT NULL GROUP BY ip HAVING COUNT(DISTINCT fingerprint) > 1")
        mut_ip = [{"ip": row[0], "fingerprints": row[1].split(",")} for row in cursor.fetchall()]
        cursor.execute("SELECT fingerprint, GROUP_CONCAT(DISTINCT ip), COUNT(DISTINCT ip) FROM logs WHERE fingerprint IS NOT NULL GROUP BY fingerprint HAVING COUNT(DISTINCT ip) > 1")
        mut_fp = [{"fingerprint": row[0], "ips": row[1].split(",")} for row in cursor.fetchall()]
        analysis["mutating_attackers"] = mut_ip + mut_fp
        # 12. Alerts (spikes, campaigns, new patterns)
        alerts = []
        if slope > 2:
            alerts.append({"type": "spike", "metric": "requests", "value": slope, "threshold": 2, "timestamp": list(by_day.keys())[-1]})
        if len(campaigns) > 0:
            alerts.append({"type": "coordinated_campaign", "count": len(campaigns)})
        analysis["alerts"] = alerts
        # 13. Data for visualization
        analysis["visualization_data"] = {
            "series_by_day": [[k, v] for k, v in by_day.items()],
            "series_by_hour": [[k, v] for k, v in by_hour.items()],
            "top_attackers": analysis.get("top_attackers", []),
            "top_tools": analysis.get("top_tools", []),
            "top_patterns": analysis.get("top_patterns", [])
        }
        # --- EXTENDED ULTRA ADVANCED ---
        # 1. First/Last seen for IP, fingerprint, user-agent, path
        for entity in ["ip", "fingerprint", "user_agent", "path"]:
            cursor.execute(f"SELECT {entity}, MIN(timestamp), MAX(timestamp) FROM logs GROUP BY {entity}")
            analysis["first_last_seen"][entity] = [
                {entity: row[0], "first_seen": row[1], "last_seen": row[2]} for row in cursor.fetchall() if row[0]
            ]
        # 2. Attack windows (bursts)
        cursor.execute("SELECT timestamp FROM logs ORDER BY timestamp")
        times = []
        for row in cursor.fetchall():
            try:
                ts = row[0]
                if ts.endswith('Z'):
                    times.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
                elif '+' in ts:
                    times.append(datetime.fromisoformat(ts))
                else:
                    times.append(datetime.fromisoformat(ts + '+00:00'))
            except Exception as e:
                logger.warning(f"Error parsing timestamp {ts}: {e}")
                continue
                
        if len(times) > 10:
            window = timedelta(minutes=10)
            i = 0
            while i < len(times):
                j = i+1
                while j < len(times) and (times[j] - times[i]) <= window:
                    j += 1
                if j-i >= 10:
                    analysis["attack_windows"].append({
                        "start": times[i].isoformat(), "end": times[j-1].isoformat(), "count": j-i
                    })
                i = j
        # 3. Top paths and breakdown
        cursor.execute("SELECT path, COUNT(*) as c FROM logs GROUP BY path ORDER BY c DESC LIMIT 10")
        top_paths = [{"path": row[0], "count": row[1]} for row in cursor.fetchall()]
        for p in top_paths:
            cursor.execute("SELECT attack_type, COUNT(*) FROM logs WHERE path = ? GROUP BY attack_type", (p["path"],))
            p["by_attack_type"] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}
        analysis["top_paths"] = top_paths
        # 4. Suspicious user-agents and new ones
        cursor.execute("SELECT user_agent, MIN(timestamp) FROM logs GROUP BY user_agent")
        all_uas = cursor.fetchall()
        now = datetime.now(timezone.utc)
        analysis["new_user_agents"] = []
        for row in all_uas:
            try:
                ua, first_seen = row[0], row[1]
                if first_seen:
                    if first_seen.endswith('Z'):
                        first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    elif '+' in first_seen:
                        first_seen_dt = datetime.fromisoformat(first_seen)
                    else:
                        first_seen_dt = datetime.fromisoformat(first_seen + '+00:00')
                    
                    if (now - first_seen_dt).days < 2:
                        analysis["new_user_agents"].append(ua)
            except Exception as e:
                logger.warning(f"Error parsing timestamp for user agent {ua}: {e}")
                continue
        # Suspicious: the least frequent and most used in successful attacks
        cursor.execute("SELECT user_agent, COUNT(*) as c FROM logs GROUP BY user_agent ORDER BY c ASC LIMIT 10")
        analysis["suspicious_user_agents"] = [row[0] for row in cursor.fetchall() if row[0]]
        # 5. Top payloads/queries
        cursor.execute("SELECT data FROM logs WHERE data IS NOT NULL AND data != ''")
        payloads = [row[0] for row in cursor.fetchall()]
        payload_counter = Counter(payloads)
        analysis["top_payloads"] = payload_counter.most_common(10)
        # Section 6 removed - country/ISP breakdown
        # 7. Retries and persistence
        cursor.execute("SELECT ip, COUNT(*) as c, COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as days FROM logs GROUP BY ip")
        retry = [{"ip": row[0], "total": row[1], "days_active": row[2]} for row in cursor.fetchall()]
        analysis["retry_persistence"] = retry
        # 8. Emerging tools/techniques
        cursor.execute("SELECT tool, MIN(timestamp) FROM logs WHERE tool IS NOT NULL GROUP BY tool")
        emergentes = []
        for row in cursor.fetchall():
            try:
                tool, first_seen = row[0], row[1]
                if first_seen:
                    if first_seen.endswith('Z'):
                        first_seen_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    elif '+' in first_seen:
                        first_seen_dt = datetime.fromisoformat(first_seen)
                    else:
                        first_seen_dt = datetime.fromisoformat(first_seen + '+00:00')
                    
                    if (now - first_seen_dt).days < 2:
                        emergentes.append(tool)
            except Exception as e:
                logger.warning(f"Error parsing timestamp for tool {tool}: {e}")
                continue
        analysis["emerging_tools_techniques"] = {"tools": emergentes}
        # 9. Multi-stage chains
        cursor.execute("SELECT fingerprint, path, timestamp FROM logs WHERE fingerprint IS NOT NULL ORDER BY fingerprint, timestamp")
        seq_logs = cursor.fetchall()
        from itertools import groupby
        for fp, group in groupby(seq_logs, lambda x: x[0]):
            events = list(group)
            sequence = [e[1] for e in events]
            timestamps = [e[2] for e in events]
            if len(sequence) > 3:
                analysis["multi_stage_chains"].append({"fingerprint": fp, "sequence": sequence, "timestamps": timestamps})
        # 10. Attacker relationships
        cursor.execute("SELECT ip, fingerprint, user_agent, path FROM logs WHERE fingerprint IS NOT NULL")
        rels = {"ip_fingerprint": defaultdict(set), "fingerprint_ip": defaultdict(set), "fingerprint_ua": defaultdict(set), "ua_fingerprint": defaultdict(set), "fingerprint_path": defaultdict(set)}
        for row in cursor.fetchall():
            ip, fp, ua, path = row
            rels["ip_fingerprint"][ip].add(fp)
            rels["fingerprint_ip"][fp].add(ip)
            rels["fingerprint_ua"][fp].add(ua)
            rels["ua_fingerprint"][ua].add(fp)
            rels["fingerprint_path"][fp].add(path)
        # Convert sets to lists
        for k in rels:
            rels[k] = {kk: list(vv) for kk, vv in rels[k].items()}
        analysis["attacker_relationships"] = rels
        # 11. Impact
        cursor.execute("SELECT ip, SUM(response_size), SUM(server_execution_time), COUNT(*) FROM logs GROUP BY ip ORDER BY SUM(response_size) DESC LIMIT 10")
        impact = [{"ip": row[0], "total_bytes": row[1], "total_cpu": row[2], "requests": row[3]} for row in cursor.fetchall()]
        analysis["impact_analysis"] = impact
        # 12. Noise/false positives
        cursor.execute("SELECT ip, COUNT(*) FROM logs WHERE suspicious = 0 GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 10")
        noise = [{"ip": row[0], "benign_requests": row[1]} for row in cursor.fetchall()]
        analysis["noise_false_positives"] = noise
        # --- CVE exploitation analysis ---
        cursor.execute("SELECT cve FROM logs WHERE cve IS NOT NULL AND cve != ''")
        cve_counter = Counter(row[0] for row in cursor.fetchall() if row[0])
        analysis["cve_breakdown"] = dict(cve_counter.most_common(10))
        # --- END EXTENSIONS ---
    except sqlite3.Error as e:
        logger.error(f"Error in analysis: {e}")
        analysis["error"] = str(e)
    finally:
        conn.close()
    # --- POST-PROCESSING FOR COMPLETENESS AND CONSISTENCY ---
    # List of all expected keys and their default values
    expected_fields = {
        "admin_panel_attacks": {},
        "alerts": [],
        "attack_category_breakdown": {},
        "attack_distribution": {},
        "attack_sequences": [],
        "attack_subcategory_breakdown": {},
        "attack_trends": {},
        "attack_windows": [],
        "attacker_relationships": {},
        "coordinated_campaigns": [],
        "correlations": {},
        "database_attacks": {},
        "emerging_tools_techniques": {},
        "file_uploads": {},
        "fingerprint_analysis": {},
        "first_last_seen": {},
        "general_stats": {},
        "impact_analysis": [],
        "multi_stage_chains": [],
        "mutating_attackers": [],
        "new_attackers": [],
        "new_user_agents": [],
        "noise_false_positives": [],
        "outliers": {},
        "pattern_type_breakdown": {},
        "persistent_attackers": [],
        "retry_persistence": [],
        "ssh_ftp_attacks": {},
        "success_analysis": {},
        "suspicious_user_agents": [],
        "temporal_analysis": {},
        "top_attackers": [],
        "top_combinations": {},
        "top_paths": [],
        "top_patterns": [],
        "top_payloads": [],
        "top_tools": [],
        "visualization_data": {},
        "cve_breakdown": {},
    }
    for k, v in expected_fields.items():
        if k not in analysis or analysis[k] is None:
            analysis[k] = v

    # Normalize types: None -> null, empty lists/dicts if appropriate
    for k, v in analysis.items():
        if v is None:
            if isinstance(expected_fields[k], list):
                analysis[k] = []
            elif isinstance(expected_fields[k], dict):
                analysis[k] = {}
            else:
                analysis[k] = None

    # Optional: sort keys for the frontend
    analysis = {k: analysis[k] for k in expected_fields.keys()}
    return analysis

# --- FUNCTION TO VALIDATE ANALYTICS JSON ---
def validate_analytics_json(analysis):
    """
    Validates that the generated analytics JSON meets the expected schema.
    Returns a list of errors found (empty if everything is correct).
    """
    expected_fields = {
        "admin_panel_attacks": dict,
        "alerts": list,
        "attack_category_breakdown": dict,
        "attack_distribution": dict,
        "attack_sequences": list,
        "attack_subcategory_breakdown": dict,
        "attack_trends": dict,
        "attack_windows": list,
        "attacker_relationships": dict,
        "coordinated_campaigns": list,
        "correlations": dict,
        "database_attacks": dict,
        "emerging_tools_techniques": dict,
        "file_uploads": dict,
        "fingerprint_analysis": dict,
        "first_last_seen": dict,
        "general_stats": dict,
        "impact_analysis": list,
        "multi_stage_chains": list,
        "mutating_attackers": list,
        "new_attackers": list,
        "new_user_agents": list,
        "noise_false_positives": list,
        "outliers": dict,
        "pattern_type_breakdown": dict,
        "persistent_attackers": list,
        "retry_persistence": list,
        "ssh_ftp_attacks": dict,
        "success_analysis": dict,
        "suspicious_user_agents": list,
        "temporal_analysis": dict,
        "top_attackers": list,
        "top_combinations": dict,
        "top_paths": list,
        "top_patterns": list,
        "top_payloads": list,
        "top_tools": list,
        "visualization_data": dict,
        "cve_breakdown": dict,
    }
    errors = []
    # Check if all keys are present and of the correct type
    for k, typ in expected_fields.items():
        if k not in analysis:
            errors.append(f"Missing key '{k}' in analytics JSON.")
        elif not isinstance(analysis[k], typ):
            # Allows None only for dict or list
            if analysis[k] is not None or typ not in (dict, list):
                errors.append(f"Key '{k}' should be of type {typ.__name__}, but is {type(analysis[k]).__name__}.")
    # Check for extra keys
    for k in analysis.keys():
        if k not in expected_fields:
            errors.append(f"Unexpected key in analytics JSON: '{k}'")
    return errors
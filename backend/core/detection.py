import re
from patterns import (
    get_payload_patterns, get_headers_patterns,
    get_sql_injection_patterns, get_xss_patterns, get_lfi_patterns,
    get_rce_patterns, get_ssrf_patterns, get_open_redirect_patterns,
    get_sql_injection_mapping, get_xss_mapping, get_lfi_mapping,
    get_rce_mapping, get_ssrf_mapping, get_open_redirect_mapping,
    get_payload_mapping,
    get_patterns_by_context,
    get_ftp_mapping,
    get_ssh_mapping,
    get_ftp_patterns,
    get_ssh_patterns,
    get_admin_panel_mapping
)
from services.redis_singleton import get_redis_client
from utils.logger import get_logger
from config import Config

logger = get_logger(__name__)

# Attacker fingerprinting
def fingerprint_request(request):
    headers = dict(request.headers)
    user_agent = headers.get("User-Agent", "").lower()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    fingerprint = {
        "ip": ip,
        "user_agent": user_agent,
        "accept": headers.get("Accept", ""),
        "accept_language": headers.get("Accept-Language", ""),
        "referer": headers.get("Referer", ""),
        "cookies": headers.get("Cookie", ""),
        "is_bot": any(bot in user_agent for bot in ["sqlmap", "nmap", "nikto", "curl", "bot", "scanner"]),
        "is_scanner": False,
        "tool": None
    }
    # Tool detection
    for tool in ["sqlmap", "nmap", "nikto", "curl", "wpscan", "fuzz", "hydra", "acunetix", "zaproxy"]:
        if tool in user_agent:
            fingerprint["tool"] = tool
            fingerprint["is_scanner"] = True
    return fingerprint

# Automatic attack classification using patterns.py
def classify_attack(data, headers, path=None, original_attack_type=None, original_attack_category=None, original_attack_subcategory=None):
    """
    Returns:
    - attack_type (principal)
    - attack_category (principal)
    - attack_subcategory (principal)
    - matches: list of all matches (type, category, subcategory, regex)
    """
    logger.debug("original_attack_type: %s", original_attack_type)
    logger.debug("get_sql_injection_mapping(): %s", get_sql_injection_mapping())
    
    # --- EXCEPTIONS FOR LEGITIMATE ENDPOINTS (before collecting matches) ---
    if path:
        path_lower = path.lower()
        if path_lower == "/home":
            return "home_access", "home_access", "generic", []
        if path_lower == "/dashboard":
            return "dashboard_access", "dashboard_access", "generic", []
    
    matches = []
    payload_matches = []
    header_matches = []

    def match_category(mapeo, value, tipo, origen):
        for regex, cat, subcat in mapeo:
            if re.search(regex, value, re.IGNORECASE):
                match = (tipo, cat, subcat, regex, origen)
                matches.append(match)
                if origen == "payload":
                    payload_matches.append(match)
                else:
                    header_matches.append(match)

    # Collect matches
    if data:
        match_category(get_sql_injection_mapping(), data, "sql_injection", "payload")
        match_category(get_xss_mapping(), data, "xss", "payload")
        match_category(get_lfi_mapping(), data, "lfi", "payload")
        match_category(get_rce_mapping(), data, "rce", "payload")
        match_category(get_ssrf_mapping(), data, "ssrf", "payload")
        match_category(get_open_redirect_mapping(), data, "open_redirect", "payload")
        match_category(get_payload_mapping(), data, "payload", "payload")
        match_category(get_ftp_mapping(), data, "ftp", "payload")
        match_category(get_ssh_mapping(), data, "ssh", "payload")
        match_category(get_admin_panel_mapping(), data, "admin_panel_probe", "payload")

    if headers:
        headers_str = str(headers)
        
        # Exception: ignore Referer with localhost to avoid SSRF false positives
        if 'Referer' in headers_str and 'localhost' in headers_str:
            # Remove Referer from analysis to avoid false positives
            headers_str_clean = re.sub(r'Referer[^,]*localhost[^,]*', '', headers_str)
        else:
            headers_str_clean = headers_str
            
        match_category(get_sql_injection_mapping(), headers_str_clean, "sql_injection", "header")
        match_category(get_xss_mapping(), headers_str_clean, "xss", "header")
        match_category(get_lfi_mapping(), headers_str_clean, "lfi", "header")
        match_category(get_rce_mapping(), headers_str_clean, "rce", "header")
        match_category(get_ssrf_mapping(), headers_str_clean, "ssrf", "header")
        match_category(get_open_redirect_mapping(), headers_str_clean, "open_redirect", "header")
        match_category(get_payload_mapping(), headers_str_clean, "payload", "header")
        match_category(get_ftp_mapping(), headers_str_clean, "ftp", "header")
        match_category(get_ssh_mapping(), headers_str_clean, "ssh", "header")
        match_category(get_admin_panel_mapping(), headers_str_clean, "admin_panel_probe", "header")

    # If there's an original attack type, use it but keep all matches
    if original_attack_type:
        # For SSH and FTP probes, ensure they have at least one generic match
        if original_attack_type == "ssh_probe" and not any(m[0] == "ssh" for m in matches):
            matches.append(("ssh", "ssh_probe", "generic", "(?i)SSH_CONNECTION_ATTEMPT", "payload"))
        elif original_attack_type == "ftp_probe" and not any(m[0] == "ftp" for m in matches):
            matches.append(("ftp", "ftp_probe", "generic", "(?i)FTP_CONNECTION_ATTEMPT", "payload"))
        
        # Find the match that corresponds to the original type
        for m in matches:
            if m[0] == original_attack_type or m[1] == original_attack_type:
                return original_attack_type, m[1], m[2], matches
        
        # If there's no specific match but it's a known type
        if original_attack_type in ["ssh_probe", "ftp_probe", "admin_panel_probe"]:
            return original_attack_type, original_attack_type, "generic", matches
        # NEW: for custom types
        if original_attack_type.endswith(("_leak", "_access", "_generation", "_settings", "_files", "_probe", "_attempt")):
            return original_attack_type, original_attack_type, "generic", matches
        # NEW: if original_attack_category or subcategory is passed, respect them
        if original_attack_category or original_attack_subcategory:
            return original_attack_type, original_attack_category, original_attack_subcategory, matches
        return original_attack_type, original_attack_type, "generic", matches

    # If there's no original type, use priority
    prioridad = ["rce", "admin_panel_probe", "ftp", "ssh", "sql_injection", "xss", "lfi", "ssrf", "open_redirect", "payload"]
    
    # 1. Prioritize payload matches
    for tipo in prioridad:
        for m in payload_matches:
            if m[0] == tipo:
                return m[0], m[1], m[2], matches
    
    # 2. If none in payload, prioritize header matches
    for tipo in prioridad:
        for m in header_matches:
            if m[0] == tipo:
                return m[0], m[1], m[2], matches
    
    # If no matches
    # --- NEW: Heuristics for known trap routes, advanced and CVEs ---
    if path:
        path_lower = path.lower()
        
        # Authentication API routes - legitimate backend routes
        auth_prefix = f"/api/{Config.AUTH_ROUTE_PREFIX}"
        if path_lower.startswith(auth_prefix.lower()):
            return "auth_access", "legitimate", "authentication", matches
        
        # Legitimate log access routes
        legitimate_log_routes = [
            "/logs", "/logs/analysis", "/logs/by_fingerprint",
            "/logs/fingerprint_info", "/logs/fingerprints_unicos",
            "/logs/debug", "/logs/debug/stats", "/logs/debug/fingerprints"
        ]
        if path_lower in legitimate_log_routes:
            return "log_access_legitimate", "legitimate", "log_management", matches
        
        # --- CVE HTTP honeypot endpoints ---
        if path_lower == "/struts2":
            return "struts2_exploit", "cve", "apache_struts2", [("struts2_exploit", "cve", "apache_struts2", "path:/struts2", "path", "CVE-2017-5638")]
        if path_lower == "/spring":
            return "spring4shell_exploit", "cve", "spring4shell", [("spring4shell_exploit", "cve", "spring4shell", "path:/spring", "path", "CVE-2022-22965")]
        if path_lower == "/drupal":
            return "drupalgeddon2_exploit", "cve", "drupalgeddon2", [("drupalgeddon2_exploit", "cve", "drupalgeddon2", "path:/drupal", "path", "CVE-2018-7600")]
        if path_lower == "/cgi-bin/bash":
            return "shellshock_exploit", "cve", "shellshock", [("shellshock_exploit", "cve", "shellshock", "path:/cgi-bin/bash", "path", "CVE-2014-6271")]
        if path_lower == "/wls-wsat/coordinatorporttype":
            return "weblogic_exploit", "cve", "weblogic", [("weblogic_exploit", "cve", "weblogic", "path:/wls-wsat/CoordinatorPortType", "path", "CVE-2019-2725")]
        if path_lower.startswith("/cgi-bin/") and ("..%2f" in path_lower or "../" in path_lower):
            return "apache_path_traversal", "cve", "apache_path_traversal", [("apache_path_traversal", "cve", "apache_path_traversal", "path:/cgi-bin/", "path", "CVE-2021-41773")]
        if path_lower.endswith("config.php"):
            return "config_leak", "config_leak", "generic", matches
        if path_lower.endswith("backup.zip"):
            return "backup_leak", "backup_leak", "generic", matches
        if path_lower.endswith("debug.log"):
            return "debug_log_leak", "debug_log_leak", "generic", matches
        if path_lower.endswith("admin/backup"):
            return "admin_backup_access", "admin_backup_access", "generic", matches
        if path_lower.endswith("admin/settings"):
            return "admin_settings_access", "admin_settings_access", "generic", matches
        if path_lower.endswith("admin/users"):
            return "admin_users_access", "admin_users_access", "generic", matches
        if path_lower.endswith("leak-users.sql"):
            return "user_leak", "user_leak", "generic", matches
        if path_lower.endswith("database"):
            return "database_probe", "database_probe", "generic", matches
        if path_lower.endswith("ftp"):
            return "ftp_probe", "ftp_probe", "generic", matches
        if path_lower.endswith("ssh"):
            return "ssh_probe", "ssh_probe", "generic", matches
        if path_lower.endswith("wp-login.php"):
            return "wordpress_probe", "wordpress_probe", "generic", matches
        if path_lower.endswith("sql"):
            return "sqli_attempt", "sqli_attempt", "generic", matches
        if path_lower.endswith("flag-access"):
            return "flag_access", "flag_access", "generic", matches
        if path_lower.endswith("redirect"):
            return "open_redirect", "open_redirect", "generic", matches
        if path_lower.endswith("login"):
            return "fake_login", "fake_login", "generic", matches
        if path_lower.endswith("dashboard/files"):
            return "dashboard_files", "dashboard_files", "generic", matches
        if path_lower.endswith("dashboard/settings"):
            return "dashboard_settings", "dashboard_settings", "generic", matches
        # --- NEW ADVANCED ROUTES (EXPANDED, WITH AND WITHOUT TRAILING SLASH) ---
        def ends(path, suffix):
            return path_lower.endswith(suffix) or path_lower.endswith(suffix + "/")

        if ends(path_lower, "graphql"):
            return "api_probe", "api", "graphql", matches
        if ends(path_lower, "payments"):
            return "payment_probe", "api", "payments", matches
        if ends(path_lower, "auth/refresh"):
            return "api_probe", "api", "auth_refresh", matches
        if ends(path_lower, "api/v1/session"):
            return "api_probe", "api", "session", matches
        if ends(path_lower, "api/v1/keys"):
            return "api_probe", "api", "keys", matches
        if ends(path_lower, "webhook/github"):
            return "webhook", "integration", "github", matches
        if ends(path_lower, "webhook/stripe"):
            return "webhook", "integration", "stripe", matches
        if ends(path_lower, "malware/upload") or ends(path_lower, "upload"):
            return "malware_upload", "sandbox", "upload", matches
        if ends(path_lower, "sandbox/scan"):
            return "malware_scan", "sandbox", "scan", matches
        if ends(path_lower, "sandbox/status"):
            return "sandbox_status", "sandbox", "status", matches
        if ends(path_lower, "sandbox/report"):
            return "sandbox_report", "sandbox", "report", matches
        if ends(path_lower, "sandbox/history"):
            return "sandbox_history", "sandbox", "history", matches
        if ends(path_lower, "sandbox/stats"):
            return "sandbox_stats", "sandbox", "stats", matches
        if ends(path_lower, "iot/status"):
            return "iot_probe", "iot", "status", matches
        if ends(path_lower, "logs/access.log"):
            return "log_access", "log", "access_log", matches
        if ends(path_lower, "logs/error.log"):
            return "log_access", "log", "error_log", matches
        if ends(path_lower, "waf"):
            return "waf_evasion", "security_bypass", "waf_test", matches
        if ends(path_lower, "telnet"):
            return "banner_probe", "network", "telnet", matches
        if ends(path_lower, "pop3"):
            return "banner_probe", "network", "pop3", matches
        if ends(path_lower, "imap"):
            return "banner_probe", "network", "imap", matches
        if ends(path_lower, "xxe"):
            return "xxe", "vuln_test", "generic", matches
        if ends(path_lower, "deserialize"):
            return "deserialization", "vuln_test", "generic", matches
        if ends(path_lower, "traversal"):
            return "traversal", "vuln_test", "generic", matches
        if ends(path_lower, "unstable"):
            return "error_sim", "system", "unstable", matches
        if ends(path_lower, "webmail"):
            return "fake_login", "mail", "webmail", matches
        if ends(path_lower, "smtp/login"):
            return "fake_login", "mail", "smtp", matches
        if ends(path_lower, "joomla/administrator"):
            return "fake_login", "cms", "joomla", matches
        if ends(path_lower, "magento/admin"):
            return "fake_login", "cms", "magento", matches
        if ends(path_lower, "drupal/user/login"):
            return "fake_login", "cms", "drupal", matches
        if ends(path_lower, "router/login"):
            return "fake_login", "iot", "router", matches
        if ends(path_lower, "wp-admin"):
            return "wordpress_probe", "cms", "wordpress", matches
        if ends(path_lower, "phpmyadmin"):
            return "database_probe", "database", "phpmyadmin", matches
        if ends(path_lower, "admin/panel"):
            return "admin_panel_probe", "admin_access", "panel", matches
        if ends(path_lower, "internal-panel"):
            return "internal_panel_access", "admin_access", "internal", matches
        if ends(path_lower, "stolen-cookie"):
            return "xss_chain", "cross_site_scripting", "cookie_theft", matches
        if ends(path_lower, "rce"):
            return "rce", "code_execution", "remote", matches
        if ends(path_lower, "ssrf"):
            return "ssrf", "server_side_request_forgery", "generic", matches
        if ends(path_lower, "lfi"):
            return "lfi", "local_file_inclusion", "generic", matches
        if ends(path_lower, "xss"):
            return "xss", "cross_site_scripting", "generic", matches
        if ends(path_lower, "api/v1/users"):
            return "api_probe", "api", "users", matches
        if ends(path_lower, "api/v1/settings"):
            return "api_probe", "api", "settings", matches
        if ends(path_lower, "api/v2/graphql"):
            return "api_probe", "api", "graphql", matches
        if ends(path_lower, "generate-secret"):
            return "secret_generation", "secret_access", "generation", matches
        if path_lower.startswith("/secret-") and path_lower.endswith(".zip"):
            return "secret_access", "secret_access", "download", matches
        if path_lower.startswith("/leak-") and path_lower.endswith(".sql"):
            return "data_leak", "data_access", "sql_dump", matches
        if ends(path_lower, "debug/stats"):
            return "debug_access", "debug", "stats", matches
        if ends(path_lower, "cves"):
            return "cve_enumeration", "vulnerability_scan", "cve_list", matches
        
        # --- NEW MISSING ROUTES ---
        # Administrative and log routes
        if path_lower == "/logs":
            return "log_access", "admin_access", "logs_main", matches
        if ends(path_lower, "logs/analysis"):
            return "log_analysis_access", "admin_access", "log_analysis", matches
        if ends(path_lower, "logs/by_fingerprint"):
            return "log_fingerprint_access", "admin_access", "fingerprint_logs", matches
        if ends(path_lower, "logs/fingerprint_info"):
            return "log_fingerprint_info", "admin_access", "fingerprint_info", matches
        if ends(path_lower, "logs/fingerprints_unicos"):
            return "log_unique_fingerprints", "admin_access", "unique_fingerprints", matches
        if ends(path_lower, "logs/debug"):
            return "log_debug_access", "admin_access", "debug_logs", matches
        if ends(path_lower, "logs/debug/stats"):
            return "log_debug_stats", "admin_access", "debug_stats", matches
        if ends(path_lower, "logs/debug/fingerprints"):
            return "log_debug_fingerprints", "admin_access", "debug_fingerprints", matches
        
        # Specific CVE routes that were missing
        if ends(path_lower, "wls-wsat/coordinatorporttype"):
            return "weblogic_exploit", "cve", "weblogic", matches
        
        # Specific service routes
        if ends(path_lower, "malware/upload"):
            return "malware_upload", "sandbox", "upload", matches
        if ends(path_lower, "sandbox/scan"):
            return "malware_scan", "sandbox", "scan", matches
        if ends(path_lower, "iot/status"):
            return "iot_probe", "iot", "status", matches
        if ends(path_lower, "logs/access.log"):
            return "log_access", "log", "access_log", matches
        if ends(path_lower, "logs/error.log"):
            return "log_access", "log", "error_log", matches
        if ends(path_lower, "waf"):
            return "waf_evasion", "security_bypass", "waf_test", matches
        if ends(path_lower, "telnet"):
            return "banner_probe", "network", "telnet", matches
        if ends(path_lower, "pop3"):
            return "banner_probe", "network", "pop3", matches
        if ends(path_lower, "imap"):
            return "banner_probe", "network", "imap", matches
        if ends(path_lower, "xxe"):
            return "xxe", "vuln_test", "generic", matches
        if ends(path_lower, "deserialize"):
            return "deserialization", "vuln_test", "generic", matches
        if ends(path_lower, "traversal"):
            return "traversal", "vuln_test", "generic", matches
        if ends(path_lower, "unstable"):
            return "error_sim", "system", "unstable", matches
        if ends(path_lower, "webmail"):
            return "fake_login", "mail", "webmail", matches
        if ends(path_lower, "joomla/administrator"):
            return "fake_login", "cms", "joomla", matches
        if ends(path_lower, "magento/admin"):
            return "fake_login", "cms", "magento", matches
        if ends(path_lower, "drupal/user/login"):
            return "fake_login", "cms", "drupal", matches
        if ends(path_lower, "router/login"):
            return "fake_login", "iot", "router", matches
    return "unknown", None, None, matches

# Correlation of campaigns
# Marks IP as scanner if it accesses many different paths in a short time
def update_scanner_score(ip, path):
    key = f"scanner:{ip}"
    redis_client.sadd(key, path)
    redis_client.expire(key, 600)
    count = redis_client.scard(key)
    if count > 10:
        redis_client.setex(f"scanner:flag:{ip}", 1800, 1)
    return count

def is_scanner(ip):
    return bool(redis_client.get(f"scanner:flag:{ip}"))

# Suspicious pattern detection (same as before)
def detect_patterns(data, headers, path=None):
    if path:
        patrones_payload = get_patterns_by_context(path)
    else:
        patrones_payload = get_payload_patterns()
    
    # Add specific attack patterns for more complete detection
    patrones_payload += get_sql_injection_patterns()
    patrones_payload += get_xss_patterns()
    patrones_payload += get_lfi_patterns()
    patrones_payload += get_rce_patterns()
    patrones_payload += get_ssrf_patterns()
    patrones_payload += get_open_redirect_patterns()
    patrones_payload += get_ftp_patterns() + get_ssh_patterns()
    
    patrones_headers = get_headers_patterns()
    patrones_headers += get_sql_injection_patterns()
    patrones_headers += get_xss_patterns()
    patrones_headers += get_lfi_patterns()
    patrones_headers += get_rce_patterns()
    patrones_headers += get_ssrf_patterns()
    patrones_headers += get_open_redirect_patterns()
    patrones_headers += get_ftp_patterns() + get_ssh_patterns()
    
    found = []
    if data:
        for patron in patrones_payload:
            if re.search(patron, data, re.IGNORECASE):
                found.append(f"payload:{patron}")
    if headers:
        headers_str = str(headers)
        for patron in patrones_headers:
            if re.search(patron, headers_str, re.IGNORECASE):
                found.append(f"header:{patron}")
    return found

redis_client = get_redis_client()

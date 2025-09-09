# Refined and corrected patterns to reduce false positives and negatives
# Some useful but not so generic patterns are reincorporated

def get_sql_injection_mapping():
    return [
        (r"(?i)\bunion\b.*\bselect\b", "sql_injection", "union_select"),
        (r"(?i)\binformation_schema\b", "sql_injection", "information_schema"),
        (r"(?i)\bload_file\b", "sql_injection", "load_file"),
        (r"(?i)\binto\s+outfile\b", "sql_injection", "into_outfile"),
        (r"(?i)\bselect\b.*\bfrom\b.*\bwhere\b.*=", "sql_injection", "select_where"),
        (r"(?i)\bupdate\b.*\bset\b.*=", "sql_injection", "update_set"),
        (r"(?i)\binsert\b.*\binto\b.*\bvalues\b", "sql_injection", "insert_values"),
        (r"(?i)\bdelete\b.*\bfrom\b.*\bwhere\b", "sql_injection", "delete_where"),
        (r"(?i)(?:--|#|\/\*|\*\/|;)\s*(?:select|insert|update|delete|drop|union|where)\b", "sql_injection", "comment"),
        (r"(?i)\bbenchmark\b|\bsleep\b|\bwaitfor\b", "sql_injection", "time_based"),
        (r"(?i)\bconcat\b|\bchar\b|\bcast\b|\bconvert\b", "sql_injection", "functions"),
        (r"(?i)(?:or|and)\s+[0-9]+\s*=\s*[0-9]+", "sql_injection", "boolean"),
        (r"(?i)(?:or|and)\s+'[^']*'\s*=\s*'[^']*'", "sql_injection", "boolean_string"),
        (r"(?i)(?:or|and)\s+1\s*=\s*1", "sql_injection", "boolean_true"),
    ]

def get_xss_mapping():
    return [
        (r"(?i)<script.*?>.*?</script>", "xss", "script_tag"),
        (r"(?i)<img[^>]*onerror=[^>]*>", "xss", "img_onerror"),
        (r"(?i)javascript:", "xss", "javascript_uri"),
        (r"(?i)on\w+\s*=", "xss", "event_handler"),
        (r"(?i)<iframe.*?>", "xss", "iframe_tag"),
        (r"(?i)<svg.*?>", "xss", "svg_tag"),
        (r"(?i)<body.*onload=.*?>", "xss", "body_onload"),
    ]

def get_lfi_mapping():
    return [
        (r"\.\./etc/passwd", "lfi", "critical_file"),
        (r"\.\./windows/win\.ini", "lfi", "critical_file"),
        (r"\.\./boot\.ini", "lfi", "critical_file"),
        (r"\.\./proc/self/environ", "lfi", "critical_file"),
        (r"\.\./var/log", "lfi", "critical_file"),
        (r"\.\./apache", "lfi", "critical_file"),
        (r"\.\./nginx", "lfi", "critical_file"),
        (r"\.\./php", "lfi", "critical_file"),
        (r"\.\./mysql", "lfi", "critical_file"),
        (r"\.\./shadow", "lfi", "critical_file"),
        (r"\.\./hosts", "lfi", "critical_file"),
        (r"\.\./", "lfi", "traversal"),
        (r"%2e%2e%2f", "lfi", "url_encoding"),
        (r"%2e%2e%5c", "lfi", "url_encoding"),
        (r"..%255c", "lfi", "double_encoding"),
    ]

# Fixing parentheses in regex patterns
def get_rce_mapping():
    return [
        (r"(?i);\s*(cat|ls|whoami|id|uname|nc|curl|wget|bash|sh|powershell)", "rce", "command_injection"),
        (r"(?i)\|\s*(cat|ls|whoami|id|uname|nc|curl|wget|bash|sh|powershell)", "rce", "command_injection"),
        (r"(?i)&&\s*(cat|ls|whoami|id|uname|nc|curl|wget|bash|sh|powershell)", "rce", "command_injection"),
        (r"(?i)system\(", "rce", "system_func"),
        (r"(?i)exec\(", "rce", "exec_func"),
        (r"(?i)popen\(", "rce", "popen_func"),
        (r"(?i)shell_exec\(", "rce", "shell_exec_func"),
        (r"(?i)cmd=.*(?:cat|ls|whoami|id|uname|nc|curl|wget|bash|sh|powershell)", "rce", "command_param"),
        (r"(?i)command=.*(?:cat|ls|whoami|id|uname|nc|curl|wget|bash|sh|powershell)", "rce", "command_param"),
    ]

def get_ssrf_mapping():
    return [
        (r"http://localhost[:\d]*/[^\s]*[^\s/]", "ssrf", "local_metadata"),
        (r"http://127\.0\.0\.1[:\d]*/[^\s]*[^\s/]", "ssrf", "local_metadata"),
        (r"http://0\.0\.0\.0[:\d]*/[^\s]*[^\s/]", "ssrf", "local_metadata"),
        (r"http://169\.254\.169\.254", "ssrf", "local_metadata"),
        (r"http://metadata\.google\.internal", "ssrf", "local_metadata"),
        (r"http://192\.168\.\d+\.\d+", "ssrf", "private"),
        (r"http://10\.\d+\.\d+\.\d+", "ssrf", "private"),
        (r"http://172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+", "ssrf", "private"),
        (r"(?i)internal|metadata|admin|config", "ssrf", "keywords"),
    ]

def get_open_redirect_mapping():
    return [
        (r"(?i)(url|redirect|next|dest|target|out|return|callback|link|go)=(http[s]?|//)", "open_redirect", "param"),
    ]

def get_config_leak_mapping():
    return [
        (r"config\.php", "config_leak", "php_config"),
        (r"\.env", "config_leak", "dotenv"),
        (r"settings\.py", "config_leak", "python_config"),
        (r"wp-config\.php", "config_leak", "wordpress"),
        (r"database\.yml", "config_leak", "rails_config"),
        (r"local\.settings\.json", "config_leak", "azure_config"),
        (r"application\.properties", "config_leak", "java_config"),
        (r"web\.config", "config_leak", "aspnet_config"),
        (r"composer\.json", "config_leak", "php_config"),
        (r"package\.json", "config_leak", "node_config"),
        (r"\.git", "config_leak", "git"),
    ]

def get_payload_mapping():
    # Combines all for 'payload'
    return (
        get_sql_injection_mapping()
        + get_xss_mapping()
        + get_lfi_mapping()
        + get_rce_mapping()
        + get_ssrf_mapping()
        + get_open_redirect_mapping()
        + get_config_leak_mapping()
    )

def get_headers_mapping():
    return [
        (r"curl", "headers", "automation"),
        (r"wget", "headers", "automation"),
        (r"python-requests", "headers", "automation"),
        (r"sqlmap", "headers", "automation"),
        (r"nmap", "headers", "automation"),
        (r"nikto", "headers", "automation"),
        (r"bot", "headers", "automation"),
        (r"scanner", "headers", "automation"),
        (r"BurpSuite", "headers", "automation"),
        (r"ZAP", "headers", "automation"),
        (r"PostmanRuntime", "headers", "automation"),
        (r"Go-http-client", "headers", "automation"),
        (r"Java/", "headers", "automation"),
        (r"Apache-HttpClient", "headers", "automation"),
        (r"Mozilla/5\.0 \(compatible; Googlebot\)", "headers", "user_agent"),
        (r"Baiduspider", "headers", "user_agent"),
        (r"YandexBot", "headers", "user_agent"),
        (r"bingbot", "headers", "user_agent"),
        (r"AhrefsBot", "headers", "user_agent"),
        (r"SemrushBot", "headers", "user_agent"),
        (r"DotBot", "headers", "user_agent"),
        (r"MJ12bot", "headers", "user_agent"),
        (r"crawler", "headers", "user_agent"),
        (r"spider", "headers", "user_agent"),
        (r"robot", "headers", "user_agent"),
        (r"scraper", "headers", "user_agent"),
        (r"harvest", "headers", "user_agent"),
        (r"X-Forwarded-For", "headers", "proxy"),
        (r"X-Real-IP", "headers", "proxy"),
        (r"Proxy-Connection", "headers", "proxy"),
        (r"Authorization", "headers", "auth"),
        (r"Cookie", "headers", "cookies"),
        (r"Referer", "headers", "referer"),
        (r"Content-Type: application/json", "headers", "content_type"),
        (r"Content-Type: text/xml", "headers", "content_type"),
        (r"Content-Type: multipart/form-data", "headers", "content_type"),
        (r"User-Agent: .*curl.*", "headers", "user_agent"),
        (r"User-Agent: .*wget.*", "headers", "user_agent"),
    ]

def get_sql_injection_patterns():
    return [pat for pat, _, _ in get_sql_injection_mapping()]
def get_xss_patterns():
    return [pat for pat, _, _ in get_xss_mapping()]
def get_lfi_patterns():
    return [pat for pat, _, _ in get_lfi_mapping()]
def get_rce_patterns():
    return [pat for pat, _, _ in get_rce_mapping()]
def get_ssrf_patterns():
    return [pat for pat, _, _ in get_ssrf_mapping()]
def get_open_redirect_patterns():
    return [pat for pat, _, _ in get_open_redirect_mapping()]
def get_config_leak_patterns():
    return [pat for pat, _, _ in get_config_leak_mapping()]
def get_payload_patterns():
    return [pat for pat, _, _ in get_payload_mapping()]
def get_headers_patterns():
    return [pat for pat, _, _ in get_headers_mapping()]

def get_patterns_by_context(path):
    if path.endswith("config.php"):
        # Only search for config_leak patterns
        patterns = get_config_leak_mapping()
    else:
        # Search for other patterns according to context
        patterns = get_payload_mapping()
    return [pat for pat, _, _ in patterns]

def get_ftp_mapping():
    return [
        (r"(?i)USER\s+\w+", "ftp", "user_cmd"),
        (r"(?i)PASS\s+.*", "ftp", "pass_cmd"),
        (r"(?i)LIST", "ftp", "list_cmd"),
        (r"(?i)RETR\s+.*", "ftp", "retr_cmd"),
        (r"(?i)STOR\s+.*", "ftp", "stor_cmd"),
        (r"(?i)DELE\s+.*", "ftp", "dele_cmd"),
        (r"(?i)QUIT", "ftp", "quit_cmd"),
        (r"(?i)FTP_CONNECTION_ATTEMPT", "ftp", "connection_attempt"),
    ]

def get_ssh_mapping():
    return [
        (r"(?i)ssh-\d\.\d+", "ssh", "protocol_banner"),
        (r"(?i)password", "ssh", "password_auth"),
        (r"(?i)publickey", "ssh", "publickey_auth"),
        (r"(?i)root", "ssh", "root_login"),
        (r"(?i)Failed password", "ssh", "failed_password"),
        (r"(?i)Accepted password", "ssh", "accepted_password"),
        (r"(?i)SSH_CONNECTION_ATTEMPT", "ssh", "connection_attempt"),
    ]

def get_ftp_patterns():
    return [pat for pat, _, _ in get_ftp_mapping()]
def get_ssh_patterns():
    return [pat for pat, _, _ in get_ssh_mapping()]

def get_admin_panel_mapping():
    return [
        (r"(?i)username=admin", "admin_panel_probe", "admin_login"),
        (r"(?i)user=admin", "admin_panel_probe", "admin_login"),
        (r"(?i)log=admin", "admin_panel_probe", "admin_login"),
        (r"(?i)/admin", "admin_panel_probe", "admin_path"),
        (r"(?i)/wp-admin", "admin_panel_probe", "wordpress_admin"),
        (r"(?i)/administrator", "admin_panel_probe", "admin_path"),
        (r"(?i)/panel", "admin_panel_probe", "admin_path"),
    ]

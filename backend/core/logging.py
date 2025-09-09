from database import save_log_to_db, calculate_request_frequency
from utils.utils import get_location_and_ip, analyze_user_agent, get_dns, query_abuseipdb, generate_fingerprint, register_suspicious_fingerprint
from core.detection import detect_patterns, fingerprint_request, classify_attack, update_scanner_score, is_scanner
from config import Config
from datetime import datetime, timezone
import hashlib
from utils.logger import get_logger

logger = get_logger(__name__)

def is_legitimate_route(path):
    """Check if a route is legitimate and should not be logged by the honeypot."""
    if not path:
        return False
    
    path_lower = path.lower()
    
    # Authentication API routes (using AUTH_ROUTE_PREFIX from config)
    # Any route starting with /api/{AUTH_ROUTE_PREFIX} is legitimate
    auth_prefix = f"/api/{Config.AUTH_ROUTE_PREFIX}"
    if path_lower.startswith(auth_prefix.lower()):
        return True
    
    # Legitimate log access routes (when authenticated)
    # These are protected by JWT auth, so legitimate access should not be logged
    legitimate_log_routes = [
        "/logs",
        "/logs/analysis", 
        "/logs/by_fingerprint",
        "/logs/fingerprint_info",
        "/logs/fingerprints_unicos",
        "/logs/debug",
        "/logs/debug/stats",
        "/logs/debug/fingerprints"
    ]
    
    if path_lower in legitimate_log_routes:
        return True
    
    # Static assets and legitimate frontend routes
    if path_lower.startswith("/static/") or path_lower.startswith("/assets/"):
        return True
    
    return False

"""
Advanced logging module for the HoneyGuard honeypot.
Records each suspicious request and enriches it with threat intelligence and fingerprinting.
"""

def create_log(request, extra=None):
    """Creates and saves an enriched log of the received HTTP request."""
    if getattr(request, "_already_logged", False):
        return None
    
    # Skip logging for legitimate admin routes
    if is_legitimate_route(request.path):
        return None
    ip, location, lat, lon, isp = get_location_and_ip(request)
    user_agent = request.headers.get("User-Agent", "Unknown")
    headers = dict(request.headers)
    data = request.get_data(as_text=True) if request.method == "POST" else request.query_string.decode()
    device, os_info, browser = analyze_user_agent(user_agent)
    timestamp = datetime.now(timezone.utc).isoformat()
    dns = get_dns(ip)
    freq = calculate_request_frequency(ip)
    patrones = detect_patterns(data, headers, path=request.path)
    payload_hash = hashlib.sha256(data.encode()).hexdigest() if data else ""
    fingerprint_details = fingerprint_request(request)
    fingerprint_hash = generate_fingerprint(request)
    register_suspicious_fingerprint(
        request,
        {
            "ip": ip,
            "user_agent": user_agent,
            "path": request.path
        }
    )

    # Reinforcement: if the route is /admin and there is no attack_type, force admin_panel_probe
    if (request.path.lower() == "/admin") and (not extra or "attack_type" not in extra):
        if not extra:
            extra = {}
        extra["attack_type"] = "admin_panel_probe"

    # Get the original attack type from extra if it exists
    original_attack_type = extra.get("attack_type") if extra else None
    attack_type, attack_category, attack_subcategory, attack_matches = classify_attack(data, headers, path=request.path, original_attack_type=original_attack_type)
    
    scanner_score = update_scanner_score(ip, request.path)
    suspicious_exact_routes = [
        "/config.php", "/wp-login.php", "/phpmyadmin", "/database", "/upload", "/debug.log"
    ]
    suspicious_prefix_routes = [
        "/admin"
    ]
    path_lower = request.path.lower()
    is_suspicious_route = (
        path_lower in suspicious_exact_routes or
        any(path_lower.startswith(r) for r in suspicious_prefix_routes)
    )
    
    # Exception: legitimate endpoints are not suspicious
    is_legitimate_endpoint = attack_type in [
        "home_access", "auth_access", "log_access_legitimate"
    ] or attack_category == "legitimate"
    
    log = {
        "ip": ip,
        "timestamp": timestamp,
        "path": request.path,
        "data": data,
        "method": request.method,
        "user_agent": user_agent,
        "headers": headers,
        "origin": headers.get("Origin", "Unknown"),
        "location": location,
        "latitude": lat,
        "longitude": lon,
        "isp": isp,
        "device": device,
        "os": os_info,
        "browser": browser,
        "dns": dns,
        "request_frequency": freq,
        "patterns_detected": patrones,
        "suspicious": (bool(patrones) or is_suspicious_route) and not is_legitimate_endpoint,
        "payload_hash": payload_hash,
        "fingerprint": fingerprint_hash,
        "fingerprint_details": fingerprint_details,
        "attack_type": attack_type,
        "attack_category": attack_category,
        "attack_subcategory": attack_subcategory,
        "attack_matches": attack_matches,
        "scanner_score": scanner_score,
        "is_scanner": is_scanner(ip),
        "is_bot": fingerprint_details.get("is_bot", False),
        "tool": fingerprint_details.get("tool"),
    }
    if extra:
        log.update(extra)
        for k in ["attack_type", "attack_category", "attack_subcategory", "cve"]:
            if k in extra and extra[k]:
                log[k] = extra[k]

    # Threat intelligence consultation
    threat_info = query_abuseipdb(ip)
    # Extract main fields for separate columns
    log["abuse_confidence_score"] = threat_info.get("abuseConfidenceScore")
    log["abuse_country_code"] = threat_info.get("countryCode")
    log["abuse_usage_type"] = threat_info.get("usageType")
    log["abuse_domain"] = threat_info.get("domain")
    log["abuse_total_reports"] = threat_info.get("totalReports")
    log["abuse_last_reported_at"] = threat_info.get("lastReportedAt")

    logger.info(f"[LOG] {ip} {request.method} {request.path} suspicious={log['suspicious']} type={log['attack_type']} UA={user_agent}")
    save_log_to_db(log)
    return log

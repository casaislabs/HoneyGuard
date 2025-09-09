import re
import hashlib
import time
import random
from datetime import datetime, timezone
import requests
import socket
from patterns import get_payload_patterns, get_headers_patterns
from services.redis_singleton import get_redis_client
from flask import request, make_response
import functools
import json
from config import Config

redis_client = get_redis_client()

def validate_ip(ip):
    """Validates if an IP address has a correct format."""
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_regex, ip) is not None

def generate_hash(data):
    """Generates a SHA-256 hash for a given string."""
    return hashlib.sha256(data.encode()).hexdigest()

def format_date(date):
    """Formats a date in ISO 8601."""
    return date.isoformat()

def calculate_time_difference(start_time, end_time):
    """Calculates the time difference between two timestamps."""
    return end_time - start_time

def is_suspicious(data, patterns):
    """Detects if a string contains suspicious patterns."""
    for p in patterns:
        if re.search(p, data, re.IGNORECASE):
            return True
    return False

def analyze_user_agent(user_agent):
    """Analyzes the User-Agent to determine the device, operating system, and browser or tool."""
    device = "Unknown"
    os = "Unknown"
    browser = "Unknown"

    # Detection of CLI/bot tools
    cli_tools = [
        ("curl", "curl"),
        ("wget", "wget"),
        ("httpie", "httpie"),
        ("sqlmap", "sqlmap"),
        ("nmap", "nmap"),
        ("nikto", "nikto"),
        ("wpscan", "wpscan"),
        ("fuzz", "fuzz"),
        ("hydra", "hydra"),
        ("acunetix", "acunetix"),
        ("zaproxy", "zaproxy"),
        ("python-requests", "python-requests"),
        ("java", "java"),
        ("go-http-client", "go-http-client"),
    ]
    user_agent_lower = user_agent.lower()
    for tool, tool_name in cli_tools:
        if tool in user_agent_lower:
            os = "CLI"
            browser = tool_name
            device = "Desktop"
            return device, os, browser

    if "Windows" in user_agent:
        os = "Windows"
    elif "Linux" in user_agent:
        os = "Linux"
    elif "Mac OS" in user_agent:
        os = "Mac OS"

    if "Chrome" in user_agent:
        browser = "Chrome"
    elif "Firefox" in user_agent:
        browser = "Firefox"
    elif "Safari" in user_agent:
        browser = "Safari"

    if "Mobile" in user_agent:
        device = "Mobile"
    elif "Tablet" in user_agent:
        device = "Tablet"
    else:
        device = "Desktop"

    return device, os, browser

def handle_error(e):
    """Handles errors and returns a formatted message."""
    return {"error": str(e)}

def get_suspicious_patterns():
    """Returns suspicious patterns for payloads and headers."""
    patrones_payload = get_payload_patterns()
    patrones_headers = get_headers_patterns()
    return patrones_payload, patrones_headers

def get_current_timestamp():
    """Returns the current timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def get_location_and_ip(request):
    """Gets the IP of the client."""
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        if not validate_ip(ip):
            return ip
        return ip
    except Exception:
        return "Unknown"

def get_dns(ip):
    """Gets the DNS associated with an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_ip(req=None) -> str:
    """Gets the client's IP from the request (defaults to flask.request global)."""
    req = req or request
    return req.headers.get("X-Forwarded-For", req.remote_addr)

def get_fail_count(key: str) -> int:
    """Gets the number of failures for a key in Redis."""
    count = redis_client.get(key)
    return int(count) if count else 0

def inc_fail_count(key: str, expire: int = 3600) -> None:
    """Increments the failure count in Redis and updates its expiration."""
    redis_client.incr(key)
    redis_client.expire(key, expire)

def reset_fail_count(key: str) -> None:
    """Resets the failure count in Redis."""
    redis_client.delete(key)

def adaptive_sleep(ip: str) -> None:
    """Increases response latency based on the number of IP failures."""
    key = f"fail:{ip}"
    count = get_fail_count(key)
    base = 0.2
    extra = min(count * 0.3, 3.0)
    time.sleep(base + random.uniform(0, 0.5) + extra)

def query_abuseipdb(ip):
    """Queries the reputation of an IP in AbuseIPDB."""
    api_key = Config.ABUSEIPDB_API_KEY
    if not api_key:
        return {"error": "No API key configured"}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "domain": data.get("domain"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            }
        return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def cache_response(timeout=60):
    """Caches the response of an endpoint in Redis."""
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(*args, **kwargs):
            # Unique key for endpoint, method, and parameters
            key_data = {
                "path": request.path,
                "method": request.method,
                "args": request.args.to_dict(),
                "form": request.form.to_dict(),
                "data": request.get_data(as_text=True)
            }
            key_str = json.dumps(key_data, sort_keys=True)
            cache_key = "cache:" + hashlib.sha256(key_str.encode()).hexdigest()
            cached = redis_client.get(cache_key)
            if cached:
                cached_data = json.loads(cached)
                resp = make_response(cached_data["body"], cached_data["status"])
                for h, v in cached_data["headers"].items():
                    resp.headers[h] = v
                return resp
            # Execute the original function
            resp = view_func(*args, **kwargs)
            # Package the response for caching
            if isinstance(resp, tuple):
                body, status = resp[0], resp[1]
            else:
                body, status = resp, 200
            headers = dict(getattr(resp, "headers", {}))
            cache_value = json.dumps({
                "body": body if isinstance(body, str) else body.get_data(as_text=True),
                "status": status,
                "headers": headers
            })
            redis_client.setex(cache_key, timeout, cache_value)
            return resp
        return wrapped
    return decorator

def generate_fingerprint(req=None):
    """Generates a unique fingerprint for an attacker using IP, User-Agent, and key headers."""
    req = req or request
    ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    user_agent = req.headers.get("User-Agent", "")
    # You can add more headers if you want
    accept = req.headers.get("Accept", "")
    accept_lang = req.headers.get("Accept-Language", "")
    # Construct a unique string
    fingerprint_str = f"{ip}|{user_agent}|{accept}|{accept_lang}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def register_fingerprint(fingerprint, info=None, expire=7*24*3600):
    """Saves the fingerprint in Redis along with additional information and a timestamp."""
    now = datetime.now(timezone.utc).isoformat()
    key = f"fingerprint:{fingerprint}"
    # Enrich info: list of IPs, User-Agents, accessed paths, event counter
    base_info = info or {}
    ip = base_info.get("ip")
    user_agent = base_info.get("user_agent")
    path = base_info.get("path")
    # Load previous info if it exists
    if redis_client.exists(key):
        prev = redis_client.get(key)
        if prev:
            prev_data = json.loads(prev)
            first_seen = prev_data.get("first_seen", now)
            prev_info = prev_data.get("info", {})
            prev_info["count"] = prev_info.get("count", 0) + 1
            
            # --- Correction to ensure IPs are updated ---
            # Get the current list, ensuring it's a list
            ip_list = prev_info.get("ips", [])
            if not isinstance(ip_list, list):
                ip_list = []
            
            # Add the new IP if it doesn't exist
            if ip and ip not in ip_list:
                ip_list.append(ip)
            
            prev_info["ips"] = ip_list
            # --- End of correction ---

            # Update unique values for other fields (optional but recommended)
            if user_agent and user_agent not in prev_info.get("user_agents", []):
                prev_info.setdefault("user_agents", []).append(user_agent)
            if path and path not in prev_info.get("paths", []):
                prev_info.setdefault("paths", []).append(path)

            data = {
                "first_seen": first_seen,
                "last_seen": now,
                "count": prev_info["count"],
                "info": prev_info
            }
        else:
            data = {
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                "info": {}
            }
    else:
        # First registration
        info_data = {}
        if ip:
            info_data["ips"] = [ip]
        if user_agent:
            info_data["user_agents"] = [user_agent]
        if path:
            info_data["paths"] = [path]
        data = {
            "first_seen": now,
            "last_seen": now,
            "count": 1,
            "info": info_data
        }
    redis_client.setex(key, expire, json.dumps(data))

def query_fingerprint(fingerprint):
    """Queries detailed information about a fingerprint in Redis."""
    key = f"fingerprint:{fingerprint}"
    if not redis_client.exists(key):
        return None
    
    data = redis_client.get(key)
    try:
        info = json.loads(data)
        # Extract data from nested 'info' structure
        nested_info = info.get("info", {})
        ips_list = nested_info.get("ips", [])
        
        return {
            "fingerprint": fingerprint,
            "count": info.get("count", 0),
            "total_attempts": info.get("count", 0),
            "unique_ips": len(ips_list),
            "ips": ips_list,
            "first_seen": info.get("first_seen"),
            "last_seen": info.get("last_seen"),
            "user_agents": nested_info.get("user_agents", []),
            "paths": nested_info.get("paths", [])
        }
    except json.JSONDecodeError:
        return {"error": "Failed to decode fingerprint data"}

def register_suspicious_fingerprint(req=None, info=None):
    fingerprint = generate_fingerprint(req)
    register_fingerprint(fingerprint, info)
    return fingerprint

def register_suspicious_event(req=None, info=None):
    """Alias for register_suspicious_fingerprint"""
    return register_suspicious_fingerprint(req, info)

def list_unique_fingerprints():
    """Returns a list of all unique fingerprints and their statistics."""
    keys = redis_client.keys("fingerprint:*")
    fingerprints = []
    for key in keys:
        try:
            data = redis_client.get(key)
            if data:
                info = json.loads(data)
                # Extract data from nested 'info' structure
                nested_info = info.get("info", {})
                ips_list = nested_info.get("ips", [])
                
                fingerprints.append({
                    "fingerprint": key.split(":")[1],
                    "count": info.get("count", 0),
                    "unique_ips": len(ips_list),
                    "ips": ips_list,
                    "first_seen": info.get("first_seen"),
                    "last_seen": info.get("last_seen"),
                })
        except Exception:
            continue
    # Sort by last seen, most recent first
    return sorted(fingerprints, key=lambda x: x["last_seen"], reverse=True)

# Optimized Gunicorn Configuration for HoneyGuard
# Auto-adaptive for any OS, system configuration, and multi-app environments

import os
import platform
import multiprocessing
import socket
import time
import json
from pathlib import Path
from config import Config

try:
    import psutil
except ImportError:
    psutil = None

# ============================================================================
# SYSTEM DETECTION AND ANALYSIS
# ============================================================================

class SystemAnalyzer:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.cpu_count = multiprocessing.cpu_count()
        self.memory_gb = self._get_memory_gb()
        self.hostname = socket.gethostname().lower()
        self.is_container = self._detect_container()
        self.is_cloud = self._detect_cloud()
        self.environment = self._detect_environment()
        self.load_avg = self._get_load_average()
        
    def _get_memory_gb(self):
        """Get system memory in GB with fallback"""
        if psutil:
            return round(psutil.virtual_memory().total / (1024**3), 2)
        else:
            # Fallback estimation based on common configurations
            return 4.0  # Assume 4GB as safe default
    
    def _detect_container(self):
        """Detect if running in Docker, LXC, or other containers"""
        try:
            indicators = [
                os.path.exists('/.dockerenv'),
                os.path.exists('/proc/1/cgroup') and 'docker' in open('/proc/1/cgroup', 'r').read(),
                os.environ.get('container') is not None,
                os.path.exists('/run/.containerenv'),  # Podman
                'microsoft' in platform.uname().release.lower(),  # WSL
            ]
            return any(indicators)
        except:
            return False
    
    def _detect_cloud(self):
        """Detect cloud providers"""
        cloud_indicators = {
            'aws': ['ec2', 'aws', 'amazon'],
            'gcp': ['gce', 'google', 'gcp'],
            'azure': ['azure', 'microsoft'],
            'digitalocean': ['droplet', 'digitalocean'],
            'vultr': ['vultr'],
            'linode': ['linode'],
            'hetzner': ['hetzner'],
        }
        
        hostname_lower = self.hostname.lower()
        for provider, keywords in cloud_indicators.items():
            if any(keyword in hostname_lower for keyword in keywords):
                return provider
        return None
    
    def _detect_environment(self):
        """Advanced environment detection"""
        # Check environment variables first
        env_override = os.environ.get('GUNICORN_ENVIRONMENT')
        if env_override and env_override.lower() != 'auto':
            return env_override.lower()
        
        # Development indicators
        dev_indicators = [
            'dev' in self.hostname,
            'local' in self.hostname,
            'test' in self.hostname,
            os.path.exists('.git'),
            self.os_type == 'windows' and not self.is_container,
            os.environ.get('FLASK_ENV') == 'development',
        ]
        
        # Production indicators
        prod_indicators = [
            'prod' in self.hostname,
            'server' in self.hostname,
            'web' in self.hostname,
            self.is_cloud,
            os.path.exists('/etc/nginx'),
            os.path.exists('/etc/apache2'),
            os.path.exists('/var/log/nginx'),
            os.environ.get('FLASK_ENV') == 'production',
        ]
        
        # Staging indicators
        staging_indicators = [
            'staging' in self.hostname,
            'stage' in self.hostname,
        ]
        
        if any(prod_indicators) and not any(dev_indicators):
            return 'production'
        elif any(staging_indicators):
            return 'staging'
        else:
            return 'development'
    
    def _get_load_average(self):
        """Get system load average with fallback"""
        try:
            if self.os_type != 'windows' and hasattr(os, 'getloadavg'):
                return os.getloadavg()[0]  # 1-minute load average
            elif psutil:
                return psutil.cpu_percent(interval=0.1)
            else:
                return 0.0
        except:
            return 0.0
    
    def get_optimal_workers(self):
        """Calculate optimal workers with improved algorithm"""
        base_workers = self.cpu_count
        
        # Memory-based worker calculation (minimum 512MB per worker)
        # Note: Memory constraints are handled in the optimization logic below
        
        # Environment-specific optimization
        if self.environment == 'development':
            return 1  # Single worker for development
        elif self.environment == 'staging':
            return min(2, base_workers)
        else:  # production
            # Improved formula: (CPU * 2) + 1, but with intelligent limits
            optimal = min((base_workers * 2) + 1, 8)  # Cap at 8 workers
            
            # Memory constraints
            if self.memory_gb < 2:
                optimal = min(optimal, 1)
            elif self.memory_gb < 4:
                optimal = min(optimal, 2)
            elif self.memory_gb < 8:
                optimal = min(optimal, 4)
            
            # Load-based adjustment
            if self.load_avg > 0:
                if self.load_avg > base_workers * 0.8:
                    optimal = int(optimal * 0.7)  # Reduce if system is loaded
                elif self.load_avg < base_workers * 0.3:
                    optimal = min(int(optimal * 1.2), 8)  # Increase if idle
            
            # Multi-app server consideration
            if self.is_cloud or 'server' in self.hostname:
                optimal = int(optimal * 0.6)  # Reserve resources for other apps
            
            return max(1, optimal)

# ============================================================================
# CONFIGURATION GENERATOR
# ============================================================================

analyzer = SystemAnalyzer()

# Port configuration from config.py
port = int(Config.GUNICORN_PORT)

# Worker configuration
workers = analyzer.get_optimal_workers()

# Bind configuration
if analyzer.environment == 'development':
    bind = f"127.0.0.1:{port}"
else:
    bind = f"0.0.0.0:{port}"

# Worker class configuration - simplified for honeypot stability
worker_class = "sync"
worker_connections = min(100, 25 * workers)

# Timeout configuration with environment-specific values
timeout_config = {
    'development': {'timeout': 300, 'graceful_timeout': 60, 'keepalive': 10},
    'staging': {'timeout': 120, 'graceful_timeout': 45, 'keepalive': 5},
    'production': {'timeout': 60, 'graceful_timeout': 30, 'keepalive': 5}
}

timeout_settings = timeout_config.get(analyzer.environment, timeout_config['production'])
timeout = timeout_settings['timeout']
graceful_timeout = timeout_settings['graceful_timeout']
keepalive = timeout_settings['keepalive']

# Memory and performance settings
max_requests_config = {
    'development': 100,
    'staging': 500,
    'production': 1500
}

max_requests = max_requests_config.get(analyzer.environment, 1000)
max_requests_jitter = max_requests // 5
preload_app = analyzer.environment != 'development'

# Logging configuration
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

log_config = {
    'development': {'level': 'debug', 'reload': True, 'capture_output': True},
    'staging': {'level': 'info', 'reload': False, 'capture_output': True},
    'production': {'level': 'warning', 'reload': False, 'capture_output': False}
}

log_settings = log_config.get(analyzer.environment, log_config['production'])
loglevel = log_settings['level']
reload = log_settings['reload']
capture_output = log_settings['capture_output']

# OS-specific optimizations
if analyzer.os_type == 'linux':
    worker_tmp_dir = "/dev/shm" if os.path.exists("/dev/shm") else "/tmp"
    sendfile = True
elif analyzer.os_type == 'darwin':  # macOS
    worker_tmp_dir = "/tmp"
    sendfile = True
else:  # Windows
    worker_tmp_dir = None
    sendfile = False

# Container-specific settings
if analyzer.is_container:
    worker_tmp_dir = "/tmp"
    preload_app = True
    max_requests = max_requests * 2  # Containers handle restarts better

# ============================================================================
# FINAL CONFIGURATION
# ============================================================================

# Server socket
backlog = 2048

# Process management
daemon = False
user = os.environ.get('GUNICORN_USER')
group = os.environ.get('GUNICORN_GROUP')

# Logging files
accesslog = str(log_dir / f"gunicorn_access_{analyzer.environment}.log")
errorlog = str(log_dir / f"gunicorn_error_{analyzer.environment}.log")

# Access log format (optimized for each environment)
if analyzer.environment == 'development':
    access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(D)s'
else:
    access_log_format = '%(h)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s %(p)s'

# Process naming
proc_name = f"honeyguard_{analyzer.environment}_{port}"

# PID file
pidfile = str(log_dir / f"gunicorn_{analyzer.environment}_{port}.pid")

# Security limits (more restrictive)
limit_request_line = 2048
limit_request_fields = 50
limit_request_field_size = 4096

# SSL auto-detection
certfile = None
keyfile = None

ssl_cert_paths = [
    "/etc/ssl/certs/honeyguard.crt",
    "/etc/letsencrypt/live/*/fullchain.pem",
    "./ssl/certificate.crt",
]

ssl_key_paths = [
    "/etc/ssl/private/honeyguard.key",
    "/etc/letsencrypt/live/*/privkey.pem",
    "./ssl/private.key",
]

for cert_path in ssl_cert_paths:
    if os.path.exists(cert_path):
        certfile = cert_path
        break

for key_path in ssl_key_paths:
    if os.path.exists(key_path):
        keyfile = key_path
        break

# ============================================================================
# CALLBACKS AND MONITORING
# ============================================================================

def when_ready(server):
    """Callback when server is ready"""
    server.log.info(f"🚀 HoneyGuard server ready on {bind}")

def worker_int(worker):
    """Callback when worker receives SIGINT"""
    worker.log.info(f"⚠️  Worker {worker.pid} received SIGINT")

def pre_fork(server, worker):
    """Callback before worker fork"""
    server.log.info(f"👷 Worker spawned (pid: {worker.pid})")

def post_fork(server, worker):
    """Callback after worker fork"""
    server.log.info(f"✅ Worker {worker.pid} ready")

def worker_abort(worker):
    """Callback when worker is aborted"""
    worker.log.error(f"💥 Worker {worker.pid} aborted")

# ============================================================================
# STARTUP INFORMATION
# ============================================================================

config_info = {
    "🚀 HoneyGuard Gunicorn Configuration": {
        "Environment": analyzer.environment,
        "OS": f"{analyzer.os_type} ({platform.platform()})",
        "Container": analyzer.is_container,
        "Cloud Provider": analyzer.is_cloud or "None",
        "CPUs": analyzer.cpu_count,
        "Memory": f"{analyzer.memory_gb} GB",
        "Load Average": round(analyzer.load_avg, 2),
        "Workers": workers,
        "Worker Class": worker_class,
        "Worker Connections": worker_connections,
        "Bind": bind,
        "Port": port,
        "Timeout": timeout,
        "Max Requests": max_requests,
        "Log Level": loglevel,
        "Process Name": proc_name,
        "SSL Enabled": bool(certfile and keyfile),
        "Preload App": preload_app,
        "Reload": reload
    }
}

print("\n" + "="*70)
for section, details in config_info.items():
    print(f"{section}:")
    for key, value in details.items():
        print(f"   {key}: {value}")
print("="*70 + "\n")

# Save configuration for monitoring
config_file = log_dir / f"gunicorn_config_{analyzer.environment}.json"
with open(config_file, 'w') as f:
    json.dump(config_info, f, indent=2)

# ============================================================================
# ENVIRONMENT VARIABLE OVERRIDES
# ============================================================================

# Configuration from config.py with auto-detection fallback
workers = int(Config.GUNICORN_WORKERS) if Config.GUNICORN_WORKERS != 'auto' else workers
bind = Config.GUNICORN_BIND if Config.GUNICORN_BIND != 'auto' else bind
loglevel = Config.GUNICORN_LOG_LEVEL if Config.GUNICORN_LOG_LEVEL != 'auto' else loglevel
timeout = int(Config.GUNICORN_TIMEOUT) if Config.GUNICORN_TIMEOUT != 'auto' else timeout
max_requests = int(Config.GUNICORN_MAX_REQUESTS) if Config.GUNICORN_MAX_REQUESTS != 'auto' else max_requests

# Environment override for special cases
if Config.GUNICORN_ENVIRONMENT != 'auto':
    analyzer.environment = Config.GUNICORN_ENVIRONMENT

# ============================================================================
# CONFIG.PY INTEGRATION
# ============================================================================

# Access to application configuration through Config class
# This allows gunicorn to be aware of application settings
app_config = {
    'redis_host': Config.REDIS_HOST,
    'has_telegram': bool(Config.TELEGRAM_BOT_TOKEN and Config.TELEGRAM_CHAT_ID),

    'has_abuseipdb': bool(Config.ABUSEIPDB_API_KEY),
    'sqlite_db_path': Config.SQLITE_DB_PATH,
}

# Log application configuration status
print(f"📊 Application Configuration Status:")
print(f"   Redis: {'✅ Configured' if app_config['redis_host'] else '❌ Not configured'}")
print(f"   Telegram Alerts: {'✅ Enabled' if app_config['has_telegram'] else '❌ Disabled'}")

print(f"   AbuseIPDB API: {'✅ Enabled' if app_config['has_abuseipdb'] else '❌ Disabled'}")
print(f"   Database: {app_config['sqlite_db_path']}")
print(f"   CORS: ❌ Disabled (Honeypot mode - No restrictions)")
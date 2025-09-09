# 🛡️ HoneyGuard Backend

**Flask-based Honeypot Backend with Advanced Threat Detection**

The HoneyGuard backend is a sophisticated Flask application designed to simulate vulnerable services and capture attack attempts in real-time. It provides comprehensive logging, threat analysis, and administrative APIs for monitoring honeypot activity.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Flask App     │    │   Detection     │    │   External      │
│                 │    │   Engine        │    │   Services      │
│ • Routes        │◄──►│                 │◄──►│                 │
│ • Middleware    │    │ • Pattern Match │    │ • Redis Cache   │
│ • Auth System   │    │ • IP Analysis   │    │ • AbuseIPDB     │
│ • Rate Limiting │    │ • Logging       │    │ • Telegram      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10
- Redis Cloud account (recommended) or local Redis instance
- AbuseIPDB API key (optional, for enhanced IP reputation analysis)
- SQLite (included)

### Installation

1. **Clone and navigate to backend:**
```bash
cd backend
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Run the application:**
```bash
# Development
python main.py

# Production with Gunicorn
gunicorn -c gunicorn.conf.py main:app
```

### Docker Deployment

#### Option 1: Using start.sh (Recommended)
```bash
# Automated deployment with validation
./start.sh
```

#### Option 2: Manual Docker
```bash
# Create isolated network first
docker network create honeyguard-net

# Build image
docker build -t honeyguard-backend .

# Run with security hardening
docker run -d \
  --name honeyguard-backend \
  --env-file .env \
  --network honeyguard-net \
  -p 127.0.0.1:${FLASK_PORT:-5000}:5000 \
  -v honeyguard-logs:/app/logs \
  -v honeyguard-uploads:/app/uploads \
  --memory="512m" \
  --cpus="1" \
  --restart unless-stopped \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/tmp \
  honeyguard-backend

# Note: Bind to 127.0.0.1 for reverse proxy setup
# Use named volumes for data persistence
# Apply resource limits and security constraints
```

#### Option 3: Docker Compose
```bash
# Production deployment with compose
docker-compose up -d
```

## ⚙️ Configuration

### Environment Variables

#### Required Configuration
```env
# Redis Cloud Configuration (Required)
REDIS_HOST=your-redis-cloud-endpoint.redislabs.com
REDIS_PORT=15845
REDIS_USERNAME=default
REDIS_PASSWORD=your-redis-cloud-password
# Rate Limiting with Redis Cloud (Required for production security)
RATELIMIT_STORAGE_URL=redis://default:your-redis-cloud-password@your-redis-cloud-endpoint.redislabs.com:15845

# Security (Required)
SECRET_KEY=your-secret-key-here
UNLOCK_PASSWORD=your-admin-password
AUTH_ROUTE_PREFIX=your-custom-auth-prefix
```

#### Optional Configuration
```env
# AbuseIPDB API (Optional - for IP reputation analysis)
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_CHAT_ID=your-telegram-chat-id

# Database
SQLITE_DB_PATH=logs.db

# Logging
LOG_LEVEL=INFO
LOG_TO_FILE=True
LOG_FILE_PATH=logs/app.log

# Security Settings
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=False
SESSION_COOKIE_SAMESITE=None
SSL_DISABLE=True
FORCE_HTTPS=False

# Gunicorn Configuration (Auto-adaptive)
GUNICORN_WORKERS=auto          # Auto-detects optimal worker count
GUNICORN_PORT=5000             # Server port
GUNICORN_BIND=auto             # Auto-detects bind address
GUNICORN_LOG_LEVEL=auto        # Environment-based log level
GUNICORN_TIMEOUT=auto          # Environment-based timeout
GUNICORN_MAX_REQUESTS=auto     # Environment-based max requests
GUNICORN_ENVIRONMENT=auto      # Auto-detects environment

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
```

## 📡 API Endpoints

### Authentication Endpoints

#### POST `/auth/login`
Authenticate and receive JWT token.

**Request:**
```json
{
  "password": "your-admin-password"
}
```

**Response:**
```json
{
  "token": "jwt-token-here",
  "expires_in": 86400,
  "user": {
    "id": "admin",
    "role": "administrator"
  }
}
```

#### GET `/auth/verify`
Verify JWT token validity.

**Headers:** `Authorization: Bearer <token>`

#### POST `/auth/refresh`
Refresh JWT token.

**Headers:** `Authorization: Bearer <token>`

### Log Management Endpoints

#### GET `/logs`
Retrieve all honeypot logs.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2024-01-15T10:30:00Z",
    "ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "method": "POST",
    "endpoint": "/wp-login.php",
    "payload": {"username": "admin", "password": "123456"},
    "fingerprint": "wp_bruteforce",
    "threat_level": "medium",
    "geolocation": {"country": "US", "city": "New York"}
  }
]
```

#### GET `/logs/analysis`
Get statistical analysis of logs.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "total_attacks": 1250,
  "unique_ips": 89,
  "top_attack_types": [
    {"type": "wp_bruteforce", "count": 450},
    {"type": "sql_injection", "count": 320}
  ],
  "geographic_distribution": {
    "US": 340,
    "CN": 280,
    "RU": 190
  },
  "timeline": {
    "last_24h": 45,
    "last_7d": 312,
    "last_30d": 1250
  }
}
```

#### GET `/logs/by_fingerprint`
Filter logs by attack fingerprint.

**Parameters:**
- `fingerprint` (required): Attack pattern identifier
- `ip` (optional): Filter by specific IP address

#### GET `/logs/fingerprint_info/<fingerprint>`
Get detailed information about a specific attack pattern.

#### GET `/logs/fingerprints_unicos`
Get list of unique attack fingerprints.

#### GET `/uploads`
Retrieve information about uploaded files.

### Debug Endpoints

#### GET `/logs/debug`
Detailed debug information about recent attacks.

#### GET `/logs/debug/stats`
Comprehensive statistics for debugging.

#### GET `/logs/debug/fingerprints`
Detailed fingerprint analysis.

## 🎭 Honeypot Services

### Web Application Honeypots

#### WordPress Simulation
- **GET/POST** `/wp-admin` - WordPress admin panel
- **POST** `/wp-login.php` - WordPress login endpoint
- **GET** `/wp-content/` - WordPress content directory

#### Content Management Systems
- **GET/POST** `/joomla/administrator` - Joomla admin panel
- **GET/POST** `/drupal/user/login` - Drupal login
- **GET/POST** `/magento/admin` - Magento admin panel

#### Database Management
- **GET/POST** `/phpmyadmin` - phpMyAdmin interface
- **GET/POST** `/database` - Generic database interface
- **GET/POST** `/mysql` - MySQL interface simulation

### Administrative Interfaces

#### Generic Admin Panels
- **GET/POST** `/admin` - Generic admin login
- **GET** `/admin/panel` - Admin dashboard
- **GET** `/admin/backup` - Backup management
- **GET** `/admin/users` - User management

#### Network Services
- **GET/POST** `/router/login` - Router admin interface
- **GET/POST** `/webmail` - Webmail interface
- **GET/POST** `/smtp/login` - SMTP configuration

### Vulnerability Simulation

#### Injection Attacks
- **GET/POST** `/sql` - SQL injection honeypot
- **GET/POST** `/xss` - XSS vulnerability simulation
- **GET** `/lfi` - Local file inclusion
- **GET** `/traversal` - Directory traversal
- **POST** `/xxe` - XML external entity injection

#### Remote Code Execution
- **GET/POST** `/rce` - Remote code execution simulation
- **POST** `/deserialize` - Unsafe deserialization
- **GET/POST** `/upload` - File upload vulnerabilities

#### Information Disclosure
- **GET** `/config.php` - Configuration file exposure
- **GET** `/debug.log` - Debug log exposure
- **GET** `/backup.zip` - Backup file exposure
- **GET** `/logs/access.log` - Access log exposure
- **GET** `/logs/error.log` - Error log exposure

### API Endpoints

#### RESTful APIs
- **GET** `/api/v1/users` - User API
- **GET** `/api/v1/settings` - Settings API
- **GET** `/api/v1/session` - Session management
- **GET** `/api/v1/keys` - API key management
- **POST** `/api/v1/payments` - Payment processing
- **POST** `/api/v1/auth/refresh` - Authentication refresh

#### GraphQL
- **POST** `/api/v2/graphql` - GraphQL endpoint

#### Webhooks
- **POST** `/webhook/github` - GitHub webhook simulation
- **POST** `/webhook/stripe` - Stripe webhook simulation

### Network Services Simulation

#### Protocol Simulations
- **GET/POST** `/ftp` - FTP service simulation
- **GET/POST** `/ssh` - SSH service simulation
- **GET/POST** `/telnet` - Telnet service simulation
- **GET/POST** `/pop3` - POP3 email service
- **GET/POST** `/imap` - IMAP email service

#### IoT and Embedded
- **GET** `/iot/status` - IoT device status
- **GET** `/unstable` - Unstable service simulation

### Advanced Deception

#### Dynamic Content
- **GET** `/generate-secret` - Dynamic secret generation
- **GET** `/secret-<token>.zip` - Dynamic secret files
- **GET** `/leak-<name>.sql` - Dynamic database leaks

#### Behavioral Simulation
- **GET** `/ssrf` - Server-side request forgery
- **GET** `/redirect` - Open redirect simulation
- **GET** `/stolen-cookie` - Cookie theft simulation
- **GET** `/flag-access` - CTF-style flag access

## 🔍 Detection Engine

### Pattern Recognition
The detection engine uses sophisticated pattern matching to identify:

- **Brute Force Attacks**: Login attempt patterns
- **SQL Injection**: Malicious SQL patterns
- **XSS Attempts**: Cross-site scripting patterns
- **Directory Traversal**: Path traversal attempts
- **File Upload Attacks**: Malicious file uploads
- **Bot Activity**: Automated scanning patterns

### Threat Classification

#### Threat Levels
- **Low**: Basic scanning, common bots
- **Medium**: Targeted attacks, credential stuffing
- **High**: Advanced persistent threats, zero-day exploits
- **Critical**: Active exploitation attempts

#### Fingerprinting
Each attack is assigned a unique fingerprint based on:
- Attack vector
- Payload characteristics
- User agent patterns
- Request frequency
- Geographic origin

### Adaptive Response

#### Rate Limiting

**Dual Configuration Strategy:**
- **Honeypot Routes**: Permissive limits (5000/hour, 500/minute, 50/second) to attract attackers
- **Real Dashboard Routes**: Strict production limits for security

**Dashboard Route Limits:**
- Login endpoint: 10 requests/minute (prevents brute force)
- Token verification: 60 requests/minute
- Token refresh: 30 requests/minute
- Logs endpoint: 120 requests/minute
- Analysis endpoint: 60 requests/minute

**Redis Cloud Storage:**
- All rate limiting data stored in Redis Cloud
- Persistent across server restarts
- Shared across multiple instances
- IP-based throttling
- Progressive delays for repeated attacks

#### Deception Techniques
- Realistic error messages
- Delayed responses to simulate processing
- Dynamic content generation
- Honeytokens and canary files

## 📊 Logging and Monitoring

### Log Storage

#### SQLite Database
- **File**: `logs.db`
- **Tables**: attacks, uploads, fingerprints
- **Retention**: Configurable (default: unlimited)

#### Redis Cloud Integration

This project uses **Redis Cloud** for:
- Session storage and rate limiting
- Temporary fingerprint data
- Request frequency tracking
- Scanner detection flags
- Cache for API responses

**Setup Redis Cloud:**
1. Sign up at [Redis Cloud](https://redis.com/try-free/)
2. Create a new database
3. Copy connection details to your `.env` file
4. Test connection: `redis-cli -h your-host -p 15845 -a your-password ping`

#### AbuseIPDB Integration

Optional service for IP reputation analysis:

**Getting API Key:**
1. Register at [AbuseIPDB](https://www.abuseipdb.com/register)
2. Verify email and go to [API Settings](https://www.abuseipdb.com/account/api)
3. Generate API key and add to `.env` as `ABUSEIPDB_API_KEY`

**Features:**
- IP reputation scoring (0-100% abuse confidence)
- Country and usage type detection
- Historical abuse reports
- Rate limits: 1000 requests/day (free tier)
- **Purpose**: Rate limiting storage, session management, fingerprint caching
- **TTL**: Configurable per data type
- **Clustering**: Supported for high availability

### Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "method": "POST",
  "endpoint": "/wp-login.php",
  "headers": {
    "Host": "honeypot.example.com",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "payload": {
    "username": "admin",
    "password": "123456"
  },
  "fingerprint": "wp_bruteforce",
  "threat_level": "medium",
  "geolocation": {
    "country": "US",
    "region": "NY",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "response_time": 0.245,
  "response_code": 401
}
```

### External Integrations

#### AbuseIPDB
- **Purpose**: IP reputation checking
- **API**: RESTful integration
- **Rate Limits**: Respected automatically

#### Telegram Notifications
- **Real-time Alerts**: Critical threats
- **Daily Summaries**: Attack statistics
- **Custom Filters**: Configurable alert criteria

## 🔧 Development

### Project Structure

```
backend/
├── main.py                 # Application entry point
├── config.py              # Configuration management
├── database.py            # Database operations
├── patterns.py            # Attack pattern definitions
├── gunicorn.conf.py       # Gunicorn configuration
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose setup
├── start.sh              # Startup script
├── core/                 # Core modules
│   ├── detection.py      # Detection engine
│   └── logging.py        # Logging utilities
├── routes/               # API routes
│   ├── auth.py          # Authentication endpoints
│   ├── logs.py          # Log management endpoints
│   ├── fake_services.py # Main honeypot services
│   ├── fake_wp.py       # WordPress honeypot
│   ├── fake_admin.py    # Admin panel honeypot
│   ├── fake_cves.py     # CVE simulation
│   └── __init__.py
├── services/            # External services
│   └── redis_singleton.py
├── utils/               # Utility modules
│   ├── auth.py         # Authentication utilities
│   ├── error_handler.py # Error handling
│   ├── logger.py       # Logging configuration
│   └── utils.py        # General utilities
├── logs/               # Log files
└── uploads/            # Uploaded files storage
```

### Adding New Honeypots

1. **Create Blueprint:**
```python
# routes/fake_newservice.py
from flask import Blueprint, request, jsonify
from core.logging import create_log

fake_newservice_bp = Blueprint("fake_newservice", __name__)

@fake_newservice_bp.route("/newservice", methods=["GET", "POST"])
def fake_newservice():
    create_log(
        endpoint="/newservice",
        method=request.method,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        payload=request.get_json() or request.form.to_dict(),
        fingerprint="newservice_attack"
    )
    return jsonify({"error": "Service unavailable"}), 503
```

2. **Register Blueprint:**
```python
# routes/fake_services.py
from .fake_newservice import fake_newservice_bp
fake_services.register_blueprint(fake_newservice_bp)
```

3. **Add Detection Patterns:**
```python
# patterns.py
NEWSERVICE_PATTERNS = [
    r"malicious_pattern_1",
    r"malicious_pattern_2"
]
```

### Testing

```bash
# Install test dependencies
pip install pytest pytest-flask

# Run tests
pytest

# Run with coverage
pytest --cov=.
```

### Performance Tuning

#### Gunicorn Configuration
```python
# gunicorn.conf.py
workers = 8  # CPU cores * 2
worker_class = "gevent"
worker_connections = 1000
max_requests = 3000
max_requests_jitter = 300
timeout = 60
keepalive = 5
```

#### Redis Optimization
```env
# Use Redis clustering for high availability
REDIS_CLUSTER_NODES=node1:6379,node2:6379,node3:6379

# Optimize memory usage
REDIS_MAXMEMORY=1gb
REDIS_MAXMEMORY_POLICY=allkeys-lru
```

## 🔒 Security Considerations

### Honeypot Security
1. **Network Isolation**: Deploy in DMZ or isolated network
2. **Resource Limits**: Configure Docker resource constraints
3. **File System**: Use read-only containers where possible
4. **Monitoring**: Monitor the honeypot for compromise

### Data Protection
1. **Encryption**: Encrypt sensitive configuration data
2. **Access Control**: Restrict admin endpoint access
3. **Audit Logging**: Log all administrative actions
4. **Backup Security**: Secure backup storage

### Operational Security
1. **Regular Updates**: Keep dependencies updated
2. **Vulnerability Scanning**: Regular security assessments
3. **Incident Response**: Prepare for honeypot compromise
4. **Legal Compliance**: Ensure compliance with local laws

## 📈 Performance Metrics

### Benchmarks
- **Concurrent Connections**: 1000+ simultaneous connections
- **Request Throughput**: 500+ requests/second
- **Response Time**: <100ms average
- **Memory Usage**: <512MB under normal load
- **CPU Usage**: <50% under normal load

### Monitoring
```bash
# Monitor application performance
tail -f logs/gunicorn_access_production.log

# Check Redis performance
redis-cli --latency-history

# Monitor system resources
htop
iotop

# Check container status
docker ps | grep honeyguard-backend

# View application logs
docker logs -f honeyguard-backend

# Monitor system resources
docker stats honeyguard-backend
```

## 🐛 Troubleshooting

### Common Issues

#### Redis Connection Errors
```bash
# Check Redis connectivity
redis-cli -h $REDIS_HOST -p $REDIS_PORT ping

# Verify credentials
redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD ping
```

#### Database Issues
```bash
# Check SQLite database
sqlite3 logs.db ".tables"

# Verify database permissions
ls -la logs.db
```

#### Container Issues
```bash
# Check container logs
docker logs honeyguard-backend

# Verify environment variables
docker exec honeyguard-backend env | grep FLASK

# Restart container
docker restart honeyguard-backend
```

#### Gunicorn Configuration
```bash
# Check Gunicorn configuration output
docker logs honeyguard-backend | grep "Gunicorn Configuration"

# View configuration file
cat logs/gunicorn_config_production.json
```

#### Performance Issues
```bash
# Check Gunicorn worker status
ps aux | grep gunicorn

# Monitor memory usage
free -h

# Check disk space
df -h
```

### Debug Mode
```env
# Enable debug logging
DEBUG=True
LOG_LEVEL=DEBUG

# Enable Flask debug mode (development only)
FLASK_ENV=development
```

## 📚 Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Gunicorn Documentation](https://gunicorn.org/)
- [Redis Documentation](https://redis.io/documentation)
- [Docker Documentation](https://docs.docker.com/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)

---

**For frontend documentation, see [../frontend/README.md](../frontend/README.md)**
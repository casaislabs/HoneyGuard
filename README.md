# 🛡️ HoneyGuard

**Advanced Honeypot System with Real-time Threat Detection and Analysis**

HoneyGuard is a sophisticated honeypot platform designed to attract, detect, and analyze cyber threats in real-time. It combines deceptive services with comprehensive logging and monitoring capabilities to provide valuable threat intelligence.

## 🌟 Features

### 🎭 Deceptive Services
- **Fake Web Applications**: WordPress, Drupal, Joomla, Magento login pages
- **Administrative Interfaces**: phpMyAdmin, admin panels, and control dashboards
- **API Endpoints**: Vulnerable-looking REST APIs and services
- **File Upload Services**: Honeypot file upload functionality
- **CVE Simulation**: Fake vulnerable services mimicking known CVEs

### 🔍 Detection & Analysis
- **Real-time Threat Detection**: Advanced pattern matching and behavioral analysis
- **IP Reputation Checking**: Integration with AbuseIPDB for threat intelligence
- **Attack Pattern Recognition**: Automated classification of attack types
- **Geolocation Tracking**: Geographic analysis of attack sources

### 📊 Monitoring & Alerting
- **Comprehensive Logging**: Detailed attack logs with metadata
- **Real-time Dashboard**: Live monitoring of threats and system status
- **Telegram Notifications**: Instant alerts for critical threats
- **Historical Analysis**: Trend analysis and reporting capabilities

### 🔒 Security Features
- **Rate Limiting**: Protection against resource exhaustion
- **Secure Authentication**: JWT-based authentication for admin access
- **Environment Isolation**: Docker containerization for security
- **Configurable Security**: Adjustable security parameters

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   External      │
│   (React)       │◄──►│   (Flask)       │◄──►│   Services      │
│                 │    │                 │    │                 │
│ • Honeypot UI   │    │ • API Routes    │    │ • Redis Cache   │
│ • Admin Panel   │    │ • Detection     │    │ • AbuseIPDB     │
│ • Real Dashboard│    │ • Logging       │    │ • Telegram      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Backend:**
- **Framework**: Flask (Python)
- **Database**: SQLite + Redis
- **Server**: Gunicorn with Gevent workers
- **Security**: Flask-Limiter, JWT authentication
- **Monitoring**: Custom logging and detection engine

**Frontend:**
- **Framework**: React 19 with Vite
- **Styling**: TailwindCSS
- **Routing**: React Router DOM
- **HTTP Client**: Axios
- **Icons**: Lucide React

## 🚀 Quick Start

### Prerequisites
- Docker (for production deployment)
- Python 3.10+ (for development)
- Node.js 18+ (for frontend development)
- Redis Cloud account (recommended) or local Redis instance
- AbuseIPDB API key (optional, for IP reputation analysis)

### Production Deployment (Recommended)

1. **Clone the repository:**
```bash
git clone https://github.com/casaislabs/HoneyGuard.git
cd HoneyGuard
```

2. **Configure backend:**
```bash
cd backend
cp .env.example .env
# Edit .env with your production settings
```

#### Getting Redis Cloud Credentials

1. Sign up at [Redis Cloud](https://redis.com/try-free/)
2. Create a new database
3. Copy the endpoint, port, username, and password from your database details
4. Use these credentials in your `.env` file

#### Getting AbuseIPDB API Key (Optional)

1. Register at [AbuseIPDB](https://www.abuseipdb.com/register)
2. Verify your email address
3. Go to [API Settings](https://www.abuseipdb.com/account/api)
4. Generate a new API key
5. Copy the key to your `.env` file as `ABUSEIPDB_API_KEY`

**Note:** AbuseIPDB provides IP reputation data to enhance threat analysis. Free accounts have rate limits.

3. **Deploy backend with Docker:**
```bash
# Using the provided start script
./start.sh

# Or manually with Docker
docker build -t honeyguard-backend .
docker run -d --name honeyguard-backend --env-file .env -p 5000:5000 honeyguard-backend
```

4. **Configure and build frontend:**
```bash
cd ../frontend
cp env.example .env
# Edit .env with your settings
npm install
npm run build
npm run preview
```

### Development Setup

For detailed development instructions, see:
- [Backend Development Guide](backend/README.md)
- [Frontend Development Guide](frontend/README.md)

## 📋 Configuration

### Required Environment Variables

**Backend (.env):**
```env
# Redis Cloud Configuration (Required)
REDIS_HOST=your-redis-cloud-endpoint.redislabs.com
REDIS_PORT=15845
REDIS_USERNAME=default
REDIS_PASSWORD=your-redis-cloud-password

# Rate Limiting (Production Security)
RATELIMIT_STORAGE_URL=redis://default:password@your-redis-cloud-endpoint.redislabs.com:15845
# Note: Honeypot routes use permissive limits, dashboard routes use strict limits

# Security
SECRET_KEY=your-secret-key
AUTH_ROUTE_PREFIX=your-custom-auth-prefix
UNLOCK_PASSWORD=your-admin-password

# AbuseIPDB API (Optional - for IP reputation analysis)
ABUSEIPDB_API_KEY=your-abuseipdb-api-key

# Telegram Notifications (Optional)
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_CHAT_ID=your-telegram-chat-id
```

**Frontend (.env):**
```env
VITE_API_URL=http://localhost:5000
VITE_AUTH_ROUTE_PREFIX=your-custom-auth-prefix
VITE_REAL_DASHBOARD_ROUTE=/your-real-dashboard-route
```

## 🎯 Usage

### Accessing the Honeypot
1. **Frontend**: `https://honeyguard.casaislabs.com/`
2. **Backend**: `http://api-honeyguard.casaislabs.com/` - Requests Logged

### Monitoring Attacks
1. Access the admin dashboard using your configured route
2. Authenticate with your unlock password
3. Monitor real-time attacks and analyze patterns
4. Review historical data and trends

### API Access
The backend provides RESTful APIs for:
- Attack log retrieval
- System statistics
- Configuration management
- Real-time monitoring data

## 📁 Project Structure

```
HoneyGuard/
├── backend/                 # Flask backend application
│   ├── core/               # Core detection and logging modules
│   ├── routes/             # API routes and honeypot endpoints
│   ├── services/           # External service integrations
│   ├── utils/              # Utility functions and helpers
│   ├── logs/               # Application logs
│   ├── uploads/            # File upload honeypot storage
│   └── requirements.txt    # Python dependencies
├── frontend/               # React frontend application
│   ├── src/
│   │   ├── components/     # Reusable React components
│   │   ├── pages/          # Page components (honeypot & real)
│   │   ├── services/       # API service functions
│   │   └── utils/          # Frontend utilities
│   └── package.json        # Node.js dependencies
└── README.md              # This file
```

## 🔧 Advanced Configuration

### Custom Honeypot Routes
Modify the authentication route prefix to hide admin endpoints:
```env
AUTH_ROUTE_PREFIX=my-secret-admin-path
```

### Rate Limiting
The system uses dual rate limiting strategy:
- **Honeypot routes**: Permissive limits to allow attackers
- **Real dashboard**: Strict limits for security (10 login attempts/minute)

Adjust rate limits in `backend/main.py`:
```python
default_limits=["5000 per hour", "500 per minute", "50 per second"]
```

### Detection Patterns
Customize attack detection patterns in `backend/patterns.py`

### Docker Configuration

The system uses Docker with Gunicorn for production deployment:

**Dockerfile highlights:**
- Multi-stage build for optimized image size
- Non-root user for security
- Gunicorn WSGI server for production
- Automatic configuration based on environment

**Start script (`start.sh`):**
- Automated Docker build and deployment
- Environment validation
- Container lifecycle management
- Port configuration from .env

**Gunicorn configuration:**
- Auto-adaptive worker scaling
- Environment-specific optimizations
- Comprehensive logging
- SSL/TLS support

### System Monitoring

```bash
# View application logs
docker logs -f honeyguard-backend

# Monitor system resources
docker stats honeyguard-backend

# Check container status
docker ps | grep honeyguard
```

## 📊 Monitoring & Alerts

### Telegram Integration
1. Create a Telegram bot via @BotFather
2. Get your chat ID
3. Configure in `.env` file
4. Receive real-time attack notifications

### Log Analysis
- **SQLite Database**: `backend/logs.db`
- **Application Logs**: `backend/logs/app.log`
- **Gunicorn Logs**: `backend/logs/gunicorn_*.log`

## 🛠️ Development

### Backend Development
See [backend/README.md](backend/README.md) for detailed backend documentation.

### Frontend Development
See [frontend/README.md](frontend/README.md) for detailed frontend documentation.

## 🔒 Security Considerations

1. **Network Isolation**: Deploy in isolated network segments
2. **Regular Updates**: Keep dependencies updated
3. **Access Control**: Secure admin routes with strong authentication
4. **Monitoring**: Monitor the honeypot itself for compromise
5. **Data Protection**: Secure sensitive configuration data

## 📈 Performance

- **Concurrent Connections**: Supports high concurrent loads with Gunicorn + Gevent
- **Resource Usage**: Optimized for minimal resource consumption
- **Scalability**: Horizontal scaling support with Redis clustering
- **Caching**: Redis-based caching for improved performance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is intended for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- Flask and React communities for excellent frameworks
- AbuseIPDB for threat intelligence API
- Redis for high-performance caching
- All contributors and security researchers

---

**Made with ❤️ for cybersecurity research and education**
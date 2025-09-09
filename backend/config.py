import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Security Configuration
    # ✅ HONEYPOT CONFIGURATION (Permissive - Attracts attacks)
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'False').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'None')
    
    # SSL/TLS Configuration - Optional for honeypot
    SSL_DISABLE = os.getenv('SSL_DISABLE', 'True').lower() == 'true'
    FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'False').lower() == 'true'
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_TO_FILE = os.getenv('LOG_TO_FILE', 'False').lower() == 'true'
    LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', 'app.log')
    
    # Application Configuration
    REDIS_HOST = os.getenv("REDIS_HOST")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_USERNAME = os.getenv("REDIS_USERNAME")
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "logs.db")
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

    
    # Dashboard Authentication
    UNLOCK_PASSWORD = os.getenv("UNLOCK_PASSWORD")
    
    # Authentication Route Configuration
    AUTH_ROUTE_PREFIX = os.getenv('AUTH_ROUTE_PREFIX', 'auth')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))
    
    # Gunicorn Configuration
    GUNICORN_PORT = os.getenv("GUNICORN_PORT", "5000")
    GUNICORN_ENVIRONMENT = os.getenv("GUNICORN_ENVIRONMENT", "auto")
    GUNICORN_WORKERS = os.getenv("GUNICORN_WORKERS", "auto")
    GUNICORN_BIND = os.getenv("GUNICORN_BIND", "auto")
    GUNICORN_LOG_LEVEL = os.getenv("GUNICORN_LOG_LEVEL", "auto")
    GUNICORN_TIMEOUT = os.getenv("GUNICORN_TIMEOUT", "auto")
    GUNICORN_MAX_REQUESTS = os.getenv("GUNICORN_MAX_REQUESTS", "auto")

# Validate that required environment variables are configured
required_env_vars = ["REDIS_HOST", "REDIS_PORT", "REDIS_USERNAME", "REDIS_PASSWORD"]
for var in required_env_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Environment variable {var} is not configured.")
# Telegram variables are optional, but recommended if you want alerts.
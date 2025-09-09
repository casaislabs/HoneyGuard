from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS  # For development - in production honeypot doesn't need CORS
from database import init_db
from routes.fake_services import fake_services
from routes.logs import logs_bp
from routes.fake_cves import fake_cves_bp
from routes.fake_wp import fake_wp_bp
from routes.fake_admin import fake_admin_bp
from routes.auth import auth_bp
# from routes.health import health_bp  # Comentado - módulo no existe
import time
import logging
from logging.handlers import RotatingFileHandler
import os
from utils.logger import get_logger
from utils.error_handler import error_handler
from config import Config
from core.logging import create_log



def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # CORS Configuration - Honeypot mode: Completely permissive
    CORS(app, 
         origins="*",  # Allows any origin (honeypot)
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],  # All methods
         allow_headers="*",  # Any header
         supports_credentials=True)  # Allows cookies (more vulnerable)
    
    # Initialize Flask-Limiter with Redis as storage backend
    # Dual configuration: Moderate for honeypot, restrictive for real dashboard
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri=app.config['RATELIMIT_STORAGE_URL'],  # Redis Cloud
        default_limits=["1000 per hour", "100 per minute", "10 per second"],  # Moderate for honeypot
        # Real dashboard routes will have stricter limits applied individually
        headers_enabled=True,
        retry_after="delta-seconds"
    )
    
    # Configure logging with rotation
    if app.config['LOG_TO_FILE']:
        # Use relative path to logs directory
        log_file_path = app.config['LOG_FILE_PATH']
        
        # Ensure logs directory exists
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure rotating file handler
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=10*1024*1024,  # 10MB per file
            backupCount=5  # Keep 5 backup files
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        ))
        
        # Configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s'
        ))
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, app.config['LOG_LEVEL']),
            handlers=[file_handler, console_handler]
        )
    else:
        logging.basicConfig(
            level=getattr(logging, app.config['LOG_LEVEL']),
            format='%(asctime)s %(levelname)s %(name)s %(message)s'
        )
    
    # Register route Blueprints
    app.register_blueprint(fake_services)
    app.register_blueprint(logs_bp)
    app.register_blueprint(fake_cves_bp)
    app.register_blueprint(fake_wp_bp)
    app.register_blueprint(fake_admin_bp)
    
    # Health check endpoints (no auth required for monitoring)
    # app.register_blueprint(health_bp, url_prefix='/api')  # Comentado - módulo no existe
    
    # Configurable auth route for security (honeypot)
    app.register_blueprint(auth_bp, url_prefix=f'/api/{Config.AUTH_ROUTE_PREFIX}')
    
    # Apply strict rate limiting to dashboard routes after blueprint registration
    limiter.limit("10 per minute")(app.view_functions[f'auth.login'])
    limiter.limit("60 per minute")(app.view_functions[f'auth.verify_token'])
    limiter.limit("30 per minute")(app.view_functions[f'auth.refresh_token'])
    limiter.limit("120 per minute")(app.view_functions[f'logs.get_logs_route'])
    limiter.limit("60 per minute")(app.view_functions[f'logs.analyze_logs_route'])
    
    # HTTPS redirect disabled for honeypot - we want to attract HTTP attacks
    # @app.before_request
    # def force_https():
    #     """Force HTTPS disabled for honeypot - HTTP is more attractive to attackers."""
    #     if app.config.get('FORCE_HTTPS') and not request.is_secure:
    #         if request.headers.get('X-Forwarded-Proto') != 'https':
    #             return redirect(request.url.replace('http://', 'https://'))
    
    @app.before_request
    def start_timer():
        """Start timer to measure response time for each request."""
        request.start_time = time.time()

    @app.after_request
    @error_handler
    def log_response_time(response):
        """Log response time and request details for honeypot analysis."""
        duration = time.time() - request.start_time
        response.headers["X-Response-Time"] = f"{duration:.2f}s"
        
        # Log all requests for honeypot analysis
        logger = get_logger(__name__)
        logger.info(f"Request: {request.method} {request.path} - Status: {response.status_code} - Duration: {duration:.2f}s - IP: {request.remote_addr}")
        
        # Only log honeypot requests, not legitimate admin operations
        from core.logging import is_legitimate_route
        if not is_legitimate_route(request.path):
            extra = {
                "http_status": response.status_code,
                "response_size": response.calculate_content_length() if hasattr(response, 'calculate_content_length') else len(response.get_data(as_text=True)),
                "duration": duration
            }
            create_log(request, extra)
        return response

    # Security headers - Honeypot configuration
    @app.after_request
    def set_security_headers(response):
        """
        Configure vulnerable headers to attract attackers to the honeypot.
        Simulates a misconfigured Apache server with PHP and outdated software.
        """
        # Main headers that reveal vulnerable technology
        response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'  # Apparently legitimate server
        response.headers['X-Powered-By'] = 'PHP/7.4.3'         # Outdated PHP
        
        # Headers suggesting configuration vulnerabilities
        response.headers['X-Debug-Mode'] = 'enabled'            # Exposed debug mode
        response.headers['X-Admin-Panel'] = '/admin'            # Revealed admin panel
        response.headers['X-Backup-Files'] = '/backup'          # Exposed backup files
        
        # Outdated software headers (known CVEs)
        response.headers['X-WordPress-Version'] = '5.8.1'       # WordPress with vulnerabilities
        response.headers['X-PHP-Version'] = '7.4.3'            # PHP with CVEs
        
        # Omit important security headers to appear vulnerable:
        # - No X-Content-Type-Options (allows MIME sniffing)
        # - No X-Frame-Options (allows clickjacking)
        # - No Content-Security-Policy (vulnerable to XSS)
        # - No X-XSS-Protection (no XSS protection)
        
        return response

    
    return app

app = create_app()
logger = get_logger(__name__)

# Initialize database with application context
with app.app_context():
    init_db()

if __name__ == "__main__":
    logger.info("Starting HoneyGuard backend...")
    app.run(debug=False, host='0.0.0.0', port=int(Config.GUNICORN_PORT))
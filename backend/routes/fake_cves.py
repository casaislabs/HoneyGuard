from flask import Blueprint, request, jsonify, make_response
from core.logging import create_log
from utils.utils import get_ip, adaptive_sleep
import re

fake_cves_bp = Blueprint("fake_cves", __name__)

# --- CVE-2017-5638: Apache Struts2 RCE ---
@fake_cves_bp.route("/struts2", methods=["GET", "POST"])
def fake_struts2():
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2017-5638"
    
    # Simulate Struts2 login page
    if request.method == "GET":
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Struts2 Web Application</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 600px; margin: 0 auto; }
                .form-group { margin-bottom: 15px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 8px; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Struts2 Application Login</h1>
                <form method="POST">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <p><small>Struts2 v2.5.12</small></p>
            </div>
        </body>
        </html>
        """
        # Log GET access
        create_log(request, {
            "cve": cve,
        })
        return html
    
    # Process POST request
    content_type = request.headers.get("Content-Type", "")
    data = request.get_data(as_text=True)
    
    # Detect typical exploit payload
    if re.search(r'%\{.*?\}', content_type) or "Content-Type: %{" in data:
        # Simulate successful RCE
        response = make_response("""
        <html>
        <head><title>Error</title></head>
        <body>
            <h1>Internal Server Error</h1>
            <p>OGNL expression detected and executed!</p>
            <p>Command: %{@java.lang.Runtime@getRuntime().exec('whoami')}</p>
        </body>
        </html>
        """, 500)
        
        # Log exploitation attempt
        create_log(request, {
            "cve": cve,
            "exploit_attempt": True,
            "payload_detected": "OGNL expression"
        })
        
        return response
    
    # Normal login (always fails)
    # Log login attempt
    create_log(request, {
        "cve": cve,
    })
    
    return """
    <html>
    <head><title>Login Failed</title></head>
    <body>
        <h1>Authentication Failed</h1>
        <p>Invalid username or password.</p>
        <a href="/struts2">Try again</a>
    </body>
    </html>
    """, 403

# --- CVE-2022-22965: Spring4Shell ---
@fake_cves_bp.route("/spring", methods=["GET", "POST"])
def fake_spring4shell():
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2022-22965"
    
    # Simulate Spring Boot application
    if request.method == "GET":
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Spring Boot Application</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 600px; margin: 0 auto; }
                .form-group { margin-bottom: 15px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 8px; }
                button { background: #6db33f; color: white; padding: 10px 20px; border: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Spring Boot User Management</h1>
                <form method="POST">
                    <div class="form-group">
                        <label>Name:</label>
                        <input type="text" name="name" required>
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="text" name="email" required>
                    </div>
                    <button type="submit">Create User</button>
                </form>
                <p><small>Spring Boot v2.6.3</small></p>
            </div>
        </body>
        </html>
        """
        # Log GET access
        create_log(request, {
            "cve": cve,
        })
        return html
    
    # Process POST request
    data = request.get_data(as_text=True)
    
    # Detect typical Spring4Shell payload
    if "class.module.classLoader.resources.context.parent.pipeline.first.pattern" in data:
        # Simulate successful exploitation
        response = make_response("""
        <html>
        <head><title>Whitelabel Error Page</title></head>
        <body>
            <h1>Whitelabel Error Page</h1>
            <p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>
            <p>Exception: java.lang.NullPointerException</p>
            <p>Message: class.module.classLoader.resources.context.parent.pipeline.first.pattern</p>
        </body>
        </html>
        """, 500)
        
        # Log exploitation attempt
        create_log(request, {
            "cve": cve,
            "exploit_attempt": True,
            "payload_detected": "Spring4Shell payload"
        })
        
        return response
    
    # Normal operation
    # Log normal attempt
    create_log(request, {
        "cve": cve,
    })
    
    return """
    <html>
    <head><title>User Created</title></head>
    <body>
        <h1>User Created Successfully</h1>
        <p>User has been added to the system.</p>
        <a href="/spring">Create another user</a>
    </body>
    </html>
    """, 200

# --- CVE-2018-7600: Drupalgeddon2 ---
@fake_cves_bp.route("/drupal", methods=["GET", "POST"])
def fake_drupalgeddon2():
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2018-7600"
    
    # Simulate Drupal registration page
    if request.method == "GET":
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Drupal - Create new account</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; }
                .form-group { margin-bottom: 15px; }
                input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 8px; }
                button { background: #0071b8; color: white; padding: 10px 20px; border: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Create new account</h1>
                <form method="POST">
                    <input type="hidden" name="form_id" value="user_register_form">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" name="name" required>
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="mail" required>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" name="pass[pass1]" required>
                    </div>
                    <button type="submit">Create new account</button>
                </form>
                <p><small>Drupal 7.58</small></p>
            </div>
        </body>
        </html>
        """
        # Log GET access
        create_log(request, {
            "cve": cve,
        })
        return html
    
    # If the request is JSON (from React frontend)
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        if username and email and password:
            create_log(request, {
                "cve": cve,
                "username": username,
                "email": email,
                "success": True
            })
            return jsonify(success=True)
        else:
            create_log(request, {
                "cve": cve,
                "username": username,
                "email": email,
                "success": False
            })
            return jsonify(success=False, error="All fields are required")
    
    # Process POST request
    data = request.get_data(as_text=True)
    
    # Detect typical Drupalgeddon2 payload
    if "form_id" in data and "user/register" in data and ("#type" in data or "element_parents" in data):
        # Simulate successful exploitation
        response = make_response("""
        <html>
        <head><title>Drupal Error</title></head>
        <body>
            <h1>Fatal error</h1>
            <p>Uncaught exception 'ReflectionException' with message 'Class element_parents does not exist'</p>
            <p>in /var/www/html/includes/form.inc:1234</p>
        </body>
        </html>
        """, 500)
        
        # Log exploitation attempt
        create_log(request, {
            "cve": cve,
            "exploit_attempt": True,
            "payload_detected": "Drupalgeddon2 payload"
        })
        
        return response
    
    # Normal registration
    # Log normal attempt
    create_log(request, {
        "cve": cve,
    })
    
    return """
    <html>
    <head><title>Account Created</title></head>
    <body>
        <h1>Account Created</h1>
        <p>Your account has been created successfully.</p>
        <a href="/drupal">Create another account</a>
    </body>
    </html>
    """, 200

@fake_cves_bp.route("/drupal/user/login", methods=["POST"])
def fake_drupal_login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Simulate login logic
    if username == 'admin' and password == 'drupal':
        create_log(request, {
            "cve": "CVE-2018-7600",
            "username": username,
            "success": True
        })
        return jsonify(success=True)
    else:
        create_log(request, {
            "cve": "CVE-2018-7600",
            "username": username,
            "success": False
        })
        return jsonify(success=False, error="Invalid credentials")

# --- CVE-2014-6271: Shellshock ---
@fake_cves_bp.route("/cgi-bin/bash", methods=["GET", "POST"])
def fake_shellshock():
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2014-6271"
    
    # Simulate CGI script
    if request.method == "GET":
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CGI Script</title>
        </head>
        <body>
            <h1>CGI Test Script</h1>
            <p>This is a test CGI script.</p>
            <p>Server: Apache/2.4.7 (Ubuntu)</p>
            <p>CGI Version: 1.1</p>
        </body>
        </html>
        """
        # Log GET access
        create_log(request, {
            "cve": cve,
        })
        return html
    
    # Search for typical payload in headers
    for header, value in request.headers.items():
        if re.search(r'\(\)\s*\{\s*:;\s*\}', value):
            # Simulate successful exploitation
            response = make_response("""
            <html>
            <head><title>Internal Server Error</title></head>
            <body>
                <h1>500 Internal Server Error</h1>
                <p>The server encountered an internal error and was unable to complete your request.</p>
                <p>Error: Shellshock vulnerability exploited</p>
                <p>Command executed: () { :; }; /bin/bash -c 'whoami'</p>
            </body>
            </html>
            """, 500)
            
            # Log exploitation attempt
            create_log(request, {
                "cve": cve,
                "exploit_attempt": True,
                "payload_detected": "Shellshock payload",
                "exploited_header": header
            })
            
            return response
    
    # Normal operation
    # Log normal attempt
    create_log(request, {
        "cve": cve,
    })
    
    return """
    <html>
    <head><title>CGI Response</title></head>
    <body>
        <h1>CGI Script Executed</h1>
        <p>Script completed successfully.</p>
    </body>
    </html>
    """, 200

# --- CVE-2019-2725: WebLogic RCE ---
@fake_cves_bp.route("/wls-wsat/CoordinatorPortType", methods=["GET", "POST"])
def fake_weblogic():
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2019-2725"
    
    # Simulate WebLogic SOAP endpoint
    if request.method == "GET":
        html = """
        <html>
        <head><title>WebLogic SOAP Service</title></head>
        <body>
            <h1>WebLogic SOAP Endpoint</h1>
            <p>CoordinatorPortType service is running.</p>
            <p>WebLogic Server Version: 12.2.1.3.0</p>
            <p>This endpoint accepts SOAP requests via POST.</p>
        </body>
        </html>
        """
        # Log GET access
        create_log(request, {
            "cve": cve,
        })
        return html, 200
    
    # Process POST request
    data = request.get_data(as_text=True)
    
    # Detect typical WebLogic payload
    if "<work:WorkContext" in data and "java.lang.ProcessBuilder" in data:
        # Simulate successful exploitation
        response = make_response("""
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <soap:Fault>
                    <faultcode>soap:Server</faultcode>
                    <faultstring>java.lang.NullPointerException</faultstring>
                    <detail>
                        <ns1:hostname xmlns:ns1="http://xmlns.oracle.com/weblogic/weblogic-web-app">localhost</ns1:hostname>
                    </detail>
                </soap:Fault>
            </soap:Body>
        </soap:Envelope>
        """, 500)
        
        # Log exploitation attempt
        create_log(request, {
            "cve": cve,
            "exploit_attempt": True,
            "payload_detected": "WebLogic RCE payload"
        })
        
        return response
    
    # Normal SOAP request
    # Log normal attempt
    create_log(request, {
        "cve": cve,
    })
    
    return """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <ns1:getStatus xmlns:ns1="http://xmlns.oracle.com/weblogic/weblogic-web-app">
                <ns1:status>OK</ns1:status>
            </ns1:getStatus>
        </soap:Body>
    </soap:Envelope>
    """, 200

# --- CVE-2021-41773: Apache Path Traversal ---
@fake_cves_bp.route("/cgi-bin/<path:filename>", methods=["GET"])
def fake_apache_path_traversal(filename):
    ip = get_ip(request)
    adaptive_sleep(ip)
    cve = "CVE-2021-41773"
    
    # Search for path traversal attempt
    if "..%2f" in filename.lower() or "../" in filename or "..%252f" in filename:
        # Simulate successful exploitation
        response = make_response("""
        <html>
        <head><title>Forbidden</title></head>
        <body>
            <h1>403 Forbidden</h1>
            <p>You don't have permission to access this resource.</p>
            <p>Path traversal attempt detected: """ + filename + """</p>
            <p>Server: Apache/2.4.49 (Ubuntu)</p>
        </body>
        </html>
        """, 403)
        
        # Log exploitation attempt
        create_log(request, {
            "cve": cve,
            "exploit_attempt": True,
            "payload_detected": "Path traversal attempt",
            "traversal_filename": filename
        })
        
        return response
    
    # Normal access
    # Log normal access
    create_log(request, {
        "cve": cve,
        "filename": filename
    })
    
    return f"""
    <html>
    <head><title>CGI File</title></head>
    <body>
        <h1>CGI File: {filename}</h1>
        <p>This is a CGI script file.</p>
        <p>Server: Apache/2.4.49 (Ubuntu)</p>
    </body>
    </html>
    """, 200

@fake_cves_bp.route("/magento/admin", methods=["GET"])
def fake_magento_login_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Magento Admin</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; }
            .container { max-width: 400px; margin: 60px auto; background: white; padding: 30px; border-radius: 8px; }
            .logo { text-align: center; margin-bottom: 20px; }
            .logo img { height: 40px; }
            .form-group { margin-bottom: 15px; }
            input[type='text'], input[type='password'] { width: 100%; padding: 8px; }
            button { background: #ee672f; color: white; padding: 10px 20px; border: none; width: 100%; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Magento.svg" alt="Magento" />
            </div>
            <h2>Magento Admin Login</h2>
            <form method="POST">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Log in</button>
            </form>
        </div>
    </body>
    </html>
    """

@fake_cves_bp.route("/joomla/administrator", methods=["GET"])
def fake_joomla_login_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Joomla! Administrator</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; }
            .container { max-width: 400px; margin: 60px auto; background: white; padding: 30px; border-radius: 8px; }
            .logo { text-align: center; margin-bottom: 20px; }
            .logo img { height: 40px; }
            .form-group { margin-bottom: 15px; }
            input[type='text'], input[type='password'] { width: 100%; padding: 8px; }
            button { background: #5091cd; color: white; padding: 10px 20px; border: none; width: 100%; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <img src="https://www.joomla.org/images/joomla-logo.png" alt="Joomla" />
            </div>
            <h2>Joomla! Administrator Login</h2>
            <form method="POST">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Log in</button>
            </form>
        </div>
    </body>
    </html>
    """

@fake_cves_bp.route("/joomla/administrator", methods=["POST"])
def fake_joomla_login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == 'admin' and password == 'joomla':
        create_log(request, {
            "username": username,
            "success": True
        })
        return jsonify(success=True)
    else:
        create_log(request, {
            "username": username,
            "success": False
        })
        return jsonify(success=False, error="Invalid credentials")

@fake_cves_bp.route("/magento/admin", methods=["POST"])
def fake_magento_login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == 'admin' and password == 'magento':
        create_log(request, {
            "username": username,
            "success": True
        })
        return jsonify(success=True)
    else:
        create_log(request, {
            "username": username,
            "success": False
        })
        return jsonify(success=False, error="Invalid credentials")

@fake_cves_bp.route("/phpmyadmin", methods=["POST"])
def fake_phpmyadmin_login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == 'root' and password == 'phpmyadmin':
        create_log(request, {
            "username": username,
            "success": True
        })
        return jsonify(success=True)
    else:
        create_log(request, {
            "username": username,
            "success": False
        })
        return jsonify(success=False, error="Invalid credentials")

# --- CVE index page ---
@fake_cves_bp.route("/cves", methods=["GET"])
def cves_index():
    """Index page showing all available CVEs"""
    # Log access to CVE page
    create_log(request, {
    })
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CVE Vulnerability Database - Honeypot</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
            .cve-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .cve-title { color: #d32f2f; font-weight: bold; }
            .cve-desc { color: #666; margin: 5px 0; }
            .cve-link { color: #1976d2; text-decoration: none; }
            .cve-link:hover { text-decoration: underline; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>CVE Vulnerability Database</h1>
            <div class="warning">
                <strong>⚠️ Warning:</strong> This is a honeypot for security research. 
                All vulnerabilities are simulated for educational purposes.
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2017-5638 - Apache Struts2 RCE</div>
                <div class="cve-desc">Remote Code Execution vulnerability in Apache Struts2</div>
                <a href="/struts2" class="cve-link">Test endpoint →</a>
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2022-22965 - Spring4Shell</div>
                <div class="cve-desc">Remote Code Execution in Spring Framework</div>
                <a href="/spring" class="cve-link">Test endpoint →</a>
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2018-7600 - Drupalgeddon2</div>
                <div class="cve-desc">Remote Code Execution in Drupal</div>
                <a href="/drupal" class="cve-link">Test endpoint →</a>
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2014-6271 - Shellshock</div>
                <div class="cve-desc">Bash vulnerability in CGI scripts</div>
                <a href="/cgi-bin/bash" class="cve-link">Test endpoint →</a>
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2019-2725 - WebLogic RCE</div>
                <div class="cve-desc">Remote Code Execution in Oracle WebLogic</div>
                <a href="/wls-wsat/CoordinatorPortType" class="cve-link">Test endpoint →</a>
            </div>
            
            <div class="cve-item">
                <div class="cve-title">CVE-2021-41773 - Apache Path Traversal</div>
                <div class="cve-desc">Path traversal vulnerability in Apache HTTP Server</div>
                <a href="/cgi-bin/test.cgi" class="cve-link">Test endpoint →</a>
            </div>
            
            <hr style="margin: 30px 0;">
            <p><small>This honeypot logs all access attempts for security research purposes.</small></p>
        </div>
    </body>
    </html>
    """

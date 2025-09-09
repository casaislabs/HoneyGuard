from flask import Blueprint, request
from utils.utils import get_ip, get_fail_count, inc_fail_count, adaptive_sleep
from core.logging import create_log
import random

fake_wp_bp = Blueprint("fake_wp", __name__)

"""
Blueprint: fake_wp
Simulates a fake WordPress login to detect automated attacks and stolen credentials.
"""

WP_ERRORS = [
    "Error: The password you entered is incorrect.",
    "Error: The user does not exist.",
    "Error: Access denied.",
    "Error: Too many failed attempts. Try again later.",
]
WP_BANNERS = [
    "WordPress 6.2.2",
    "WordPress 5.9.3",
    "WordPress 6.1.1",
]

@fake_wp_bp.route("/wp-admin", methods=["GET"])
def fake_wp_admin():
    """Redirects wp-admin to the WordPress login page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>WordPress › Log In</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f1f1f1; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
            .form-group { margin-bottom: 15px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; }
            button { background: #0073aa; color: white; padding: 12px 20px; border: none; width: 100%; }
            .logo { text-align: center; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>WordPress</h1>
            </div>
            <form method="POST" action="/wp-login.php">
                <div class="form-group">
                    <label>Username or Email Address</label>
                    <input type="text" name="log" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="pwd" required>
                </div>
                <button type="submit">Log In</button>
            </form>
            <p style="text-align: center; margin-top: 20px;">
                <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
            </p>
            <p style="text-align: center; font-size: 12px; color: #666;">
                WordPress 6.2.2
            </p>
        </div>
    </body>
    </html>
    """

@fake_wp_bp.route("/wp-login.php", methods=["POST"])
def fake_wp_login():
    """Endpoint for simulating a vulnerable WordPress login."""
    ip = get_ip(request)
    
    # Log the request
    username = request.form.get("log", "Unknown")
    password = request.form.get("pwd", "Unknown")
    
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    fail_key = f"fail:wp:{ip}"
    adaptive_sleep(ip)
    banner = random.choice(WP_BANNERS)
    fail_count = get_fail_count(fail_key)
    inc_fail_count(fail_key)
    if fail_count >= 3:
        return f"<html><head><title>{banner}</title></head><body><h1>User blocked due to too many attempts</h1></body></html>", 403
    error = random.choice(WP_ERRORS)
    response_html = f"""
        <html>
            <head><title>{banner}</title></head>
            <body>
                <h1>{banner} - Login</h1>
                <p>{error}</p>
                <p>Username: {username}</p>
            </body>
        </html>
    """
    return response_html, 403

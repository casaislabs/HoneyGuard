from flask import Blueprint, request
from utils.utils import get_ip, get_fail_count, inc_fail_count, adaptive_sleep
from core.logging import create_log
import random

fake_admin_bp = Blueprint("fake_admin", __name__)

"""
Blueprint: fake_admin
Simulates a fake admin panel to detect unauthorized access attempts.
"""

ADMIN_ERRORS = [
    "Incorrect username or password.",
    "Access denied: user blocked.",
    "Too many failed attempts. Try again later.",
    "User does not have sufficient permissions.",
]
ADMIN_BANNERS = [
    "Administration Panel - v2.3.1",
    "Admin Console - Secure Login",
    "Enterprise Management System",
]

@fake_admin_bp.route("/admin", methods=["GET", "POST"])
def fake_admin():
    """Honeypot endpoint to simulate a vulnerable admin panel."""
    ip = get_ip(request)
    
    # Log the request
    username = request.form.get("username", "Unknown") if request.method == "POST" else None
    password = request.form.get("password", "Unknown") if request.method == "POST" else None
    
    create_log(request, {
        "username": username,
        "password": password,
    })
    
    fail_key = f"fail:admin:{ip}"
    adaptive_sleep(ip)
    banner = random.choice(ADMIN_BANNERS)
    fail_count = get_fail_count(fail_key)
    if request.method == "POST":
        inc_fail_count(fail_key)
        if fail_count >= 3:
            return f"<html><head><title>{banner}</title></head><body><h1>User blocked due to too many attempts</h1></body></html>", 403
        error = random.choice(ADMIN_ERRORS)
        response_html = f"""
            <html>
                <head><title>{banner}</title></head>
                <body>
                    <h1>Access error</h1>
                    <p>{error}</p>
                    <p>Attempt recorded: {fail_count+1} times</p>
                </body>
            </html>
        """
        return response_html, 403
    response_html = f"""
        <html>
            <head><title>{banner}</title></head>
            <body>
                <h1>{banner}</h1>
                <form method="POST">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username"><br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password"><br>
                    <button type="submit">Login</button>
                </form>
                <p>Status: {random.choice(['Available', 'Under maintenance'])}</p>
            </body>
        </html>
    """
    return response_html, 200

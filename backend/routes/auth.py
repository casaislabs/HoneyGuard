from flask import Blueprint, request, jsonify, current_app
from utils.auth import generate_jwt_token, require_jwt_auth, validate_admin_password
from config import Config
from datetime import datetime, timezone
import uuid

auth_bp = Blueprint('auth', __name__)

# Get limiter instance from main app
def get_limiter():
    return current_app.extensions.get('limiter')


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authentication endpoint that validates credentials and returns a JWT token.
    Rate limited to 10 requests per minute for security.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'No data provided',
                'message': 'Request body must contain JSON data',
                'status': 'bad_request'
            }), 400
        
        password = data.get('password')
        
        if not password:
            return jsonify({
                'error': 'Password required',
                'message': 'Password field is required',
                'status': 'bad_request'
            }), 400
        
        # Verify password using the unified auth module
        try:
            if not validate_admin_password(password):
                return jsonify({
                    'error': 'Invalid credentials',
                    'message': 'Incorrect password',
                    'status': 'unauthorized'
                }), 401
        except ValueError as e:
            return jsonify({
                'error': 'Server configuration error',
                'message': str(e),
                'status': 'server_error'
            }), 500
        
        # Generate JWT token with unique data for greater randomness
        user_data = {
            'jti': str(uuid.uuid4()),  # Unique JWT ID
            'iat': datetime.now(timezone.utc)    # Issuance timestamp
        }
        
        token = generate_jwt_token(user_data)
        
        return jsonify({
            'message': 'Authentication successful',
            'access_token': token,
            'status': 'success'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Authentication failed',
            'message': str(e),
            'status': 'server_error'
        }), 500

@auth_bp.route('/verify', methods=['GET'])
@require_jwt_auth()
def verify_token():
    """
    Endpoint to verify if a JWT token is valid.
    """
    return jsonify({
        'status': 'success',
        'message': 'Token is valid',
        'authenticated': True
    }), 200

@auth_bp.route('/refresh', methods=['POST'])
@require_jwt_auth()
def refresh_token():
    """
    Endpoint to refresh a valid JWT token.
    """
    # Generate new token with unique data for greater randomness
    user_data = {
        'jti': str(uuid.uuid4()),  # Unique JWT ID
        'iat': datetime.now(timezone.utc)    # Issuance timestamp
    }
    
    new_token = generate_jwt_token(user_data)
    
    return jsonify({
        'status': 'success',
        'message': 'Token refreshed successfully',
        'access_token': new_token,
        'expires_in': Config.JWT_EXPIRATION_HOURS * 3600
    }), 200
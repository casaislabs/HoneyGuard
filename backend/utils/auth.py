import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify
from config import Config

def generate_jwt_token(user_data=None):
    """
    Generates a JWT token for authenticated access.
    
    Args:
        user_data (dict, optional): Additional user data to include in the token
    """
    payload = {
        'authenticated': True,
        'exp': datetime.now(timezone.utc) + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
    }
    
    # Add additional user data if provided
    if user_data:
        payload.update(user_data)
    
    # Ensure iat is present (can come from user_data or is added here)
    if 'iat' not in payload:
        payload['iat'] = datetime.now(timezone.utc)
    
    token = jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    return token

def verify_jwt_token(token):
    """
    Verifies and decodes a JWT token.
    Returns the payload if valid, None if invalid.
    """
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_jwt_auth():
    """
    Decorator to protect routes with simple JWT authentication.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please provide Authorization header with Bearer token',
                    'status': 'unauthorized'
                }), 401
            
            # Verify Bearer format
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid authentication format',
                    'message': 'Use Bearer token format',
                    'status': 'unauthorized'
                }), 401
            
            try:
                # Extract token
                token = auth_header.split(' ')[1]
                
                # Verify token
                payload = verify_jwt_token(token)
                
                if not payload:
                    return jsonify({
                        'error': 'Invalid or expired token',
                        'message': 'Please login again',
                        'status': 'unauthorized'
                    }), 401
                
                # Verify that the token indicates valid authentication
                if not payload.get('authenticated'):
                    return jsonify({
                        'error': 'Invalid token',
                        'message': 'Token does not indicate valid authentication',
                        'status': 'unauthorized'
                    }), 401
                
                # Add basic information to request
                request.current_user = {
                    'authenticated': True
                }
                
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({
                    'error': 'Authentication failed',
                    'message': 'Invalid token format',
                    'status': 'unauthorized'
                }), 401
        
        return decorated_function
    return decorator

def validate_admin_password(password):
    """
    Validates the access password against the environment variable.
    Returns True if valid, False otherwise.
    """
    expected_password = Config.UNLOCK_PASSWORD
    if not expected_password:
        raise ValueError('Unlock password not configured')
    
    return password == expected_password
from flask import Blueprint, jsonify, request, current_app
from database import get_logs, analyze_logs
from utils.utils import query_fingerprint, list_unique_fingerprints
from routes.auth import require_jwt_auth
from datetime import datetime
import sqlite3
from config import Config

logs_bp = Blueprint("logs", __name__)

# Get limiter instance from main app
def get_limiter():
    return current_app.extensions.get('limiter')

"""
Blueprint: logs
Provides endpoints to query and analyze honeypot logs.
"""

@logs_bp.route("/logs", methods=["GET"])
@require_jwt_auth()
def get_logs_route():
    """Returns all logs stored in the database."""
    try:
        logs = get_logs()
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/analysis", methods=["GET"])
@require_jwt_auth()
def analyze_logs_route():
    """Returns a statistical analysis of stored logs."""
    try:
        analysis = analyze_logs()
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/by_fingerprint", methods=["GET"])
@require_jwt_auth()
def get_logs_by_fingerprint():
    """Returns logs filtered by fingerprint (and optionally by IP)."""
    fingerprint = request.args.get("fingerprint")
    ip = request.args.get("ip")
    if not fingerprint:
        return jsonify({"error": "The 'fingerprint' parameter is required"}), 400
    try:
        logs = get_logs()
        filtrados = [l for l in logs if l.get("fingerprint") == fingerprint]
        if ip:
            filtrados = [l for l in filtrados if l.get("ip") == ip]
        return jsonify(filtrados)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/fingerprint_info/<fingerprint>", methods=["GET"])
@require_jwt_auth()
def get_fingerprint_info(fingerprint):
    """Returns fingerprint information stored in Redis."""
    try:
        info = query_fingerprint(fingerprint)
        if info:
            return jsonify(info)
        return jsonify({"error": "Fingerprint not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/fingerprints_unicos", methods=["GET"])
@require_jwt_auth()
def get_fingerprints_unicos():
    """Returns all unique fingerprints and their statistics from Redis."""
    try:
        fingerprints = list_unique_fingerprints()
        return jsonify(fingerprints)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/debug", methods=["GET"])
@require_jwt_auth()
def debug_logs():
    """Debug endpoint to verify database content."""
    try:
        from database import Config
        import sqlite3
        conn = sqlite3.connect(Config.SQLITE_DB_PATH)
        cursor = conn.cursor()
        
        # Check logs
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        
        # Check today's logs
        cursor.execute("SELECT COUNT(*) FROM logs WHERE date(timestamp) = date('now')")
        today_logs = cursor.fetchone()[0]
        
        # Verify unique IPs
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM logs")
        unique_ips = cursor.fetchone()[0]
        
        # Check some sample logs
        cursor.execute("SELECT ip, timestamp, path, attack_type, attack_category, suspicious FROM logs LIMIT 5")
        sample_logs = cursor.fetchall()
        
        # Check file_uploads
        cursor.execute("SELECT COUNT(*) FROM file_uploads")
        total_files = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            "total_logs": total_logs,
            "today_logs": today_logs,
            "unique_ips": unique_ips,
            "total_files": total_files,
            "sample_logs": [
                {
                    "ip": row[0],
                    "timestamp": row[1],
                    "path": row[2],
                    "attack_type": row[3],
                    "attack_category": row[4],
                    "suspicious": row[5]
                }
                for row in sample_logs
            ]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/debug/stats", methods=["GET"])
@require_jwt_auth()
def debug_stats():
    """Specific debug endpoint for statistics."""
    try:
        from database import Config
        import sqlite3
        conn = sqlite3.connect(Config.SQLITE_DB_PATH)
        cursor = conn.cursor()
        
        # Basic statistics
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM logs WHERE date(timestamp) = date('now')")
        today_logs = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM logs")
        unique_ips = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM file_uploads")
        total_files = cursor.fetchone()[0]
        
        # Check what analyze_logs() returns
        from database import analyze_logs
        analysis_result = analyze_logs()
        
        conn.close()
        
        return jsonify({
            "database_stats": {
                "total_logs": total_logs,
                "today_logs": today_logs,
                "unique_ips": unique_ips,
                "total_files": total_files
            },
            "analyze_logs_result": analysis_result,
            "general_stats": analysis_result.get("general_stats", {}),
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@logs_bp.route("/logs/debug/fingerprints", methods=["GET"])
@require_jwt_auth()
def debug_fingerprints():
    """Debug endpoint to verify fingerprints in Redis."""
    try:
        from services.redis_singleton import get_redis_client
        import json
        redis_client = get_redis_client()
        # The key is already decoded by Redis client configuration
        keys = redis_client.keys("fingerprint:*")
        
        fingerprints_data = []
        for key in keys:
            data = redis_client.get(key)
            fingerprints_data.append({
                "key": key,
                "data": json.loads(data) if data else None
            })

        return jsonify({
            "total_keys_found": len(keys),
            "keys": keys,
            "data": fingerprints_data
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Note: Redis is ideal for fingerprints because it allows fast access, automatic expiration and temporary storage of session or aggregated data. SQLite3 is better for historical logs and complex queries, but Redis is more efficient for frequently accessed data that can expire (like active or recent fingerprints).

@logs_bp.route("/uploads", methods=["GET"])
@require_jwt_auth()
def get_uploaded_files():
    """Returns uploaded files grouped by IP address for the real dashboard."""
    try:
        conn = sqlite3.connect(Config.SQLITE_DB_PATH)
        cursor = conn.cursor()
        
        # Get uploaded files with IP information
        cursor.execute("""
            SELECT 
                ip,
                timestamp,
                filename,
                file_type,
                file_size,
                file_hash,
                is_suspicious,
                stored_path,
                analysis_report
            FROM file_uploads 
            ORDER BY timestamp DESC
        """)
        
        files = cursor.fetchall()
        conn.close()
        
        # Group files by IP
        uploads_by_ip = {}
        total_files = 0
        suspicious_files = 0
        
        for file_data in files:
            ip, timestamp, filename, file_type, file_size, file_hash, is_suspicious, stored_path, analysis_report = file_data
            
            if ip not in uploads_by_ip:
                uploads_by_ip[ip] = {
                    "ip": ip,
                    "total_files": 0,
                    "suspicious_files": 0,
                    "total_size": 0,
                    "first_upload": timestamp,
                    "last_upload": timestamp,
                    "files": []
                }
            
            # Update IP statistics
            uploads_by_ip[ip]["total_files"] += 1
            uploads_by_ip[ip]["total_size"] += file_size or 0
            if is_suspicious:
                uploads_by_ip[ip]["suspicious_files"] += 1
                suspicious_files += 1
            
            # Update timestamps
            if timestamp < uploads_by_ip[ip]["first_upload"]:
                uploads_by_ip[ip]["first_upload"] = timestamp
            if timestamp > uploads_by_ip[ip]["last_upload"]:
                uploads_by_ip[ip]["last_upload"] = timestamp
            
            # Add file details
            file_info = {
                "filename": filename,
                "file_type": file_type,
                "file_size": file_size,
                "file_hash": file_hash,
                "is_suspicious": bool(is_suspicious),
                "timestamp": timestamp,
                "stored_path": stored_path
            }
            
            # Parse analysis report if available
            if analysis_report:
                try:
                    import json
                    file_info["analysis_report"] = json.loads(analysis_report)
                except:
                    file_info["analysis_report"] = analysis_report
            
            uploads_by_ip[ip]["files"].append(file_info)
            total_files += 1
        
        # Convert to list and sort by number of files (most active IPs first)
        uploads_list = list(uploads_by_ip.values())
        uploads_list.sort(key=lambda x: x["total_files"], reverse=True)
        
        return jsonify({
            "status": "success",
            "summary": {
                "total_files": total_files,
                "suspicious_files": suspicious_files,
                "unique_ips": len(uploads_by_ip),
                "total_size": sum(ip_data["total_size"] for ip_data in uploads_by_ip.values())
            },
            "uploads_by_ip": uploads_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
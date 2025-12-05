"""
Profile, Settings, and Statistics API Endpoints
Add these endpoints to Backend/app_enhanced.py
"""

from flask import jsonify, request
import time
from datetime import datetime, timedelta

def register_profile_endpoints(app, get_db, limiter, logger, RATE_LIMITS):
    """Register all profile-related API endpoints"""

    @app.route('/api/user/profile', methods=['GET'])
    def get_user_profile():
        """Get user profile information"""
        try:
            username = request.args.get('username')
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, email, phone_number, security_level, 
                       created_at, updated_at, last_login, login_count
                FROM users 
                WHERE username = %s AND is_active = true
            ''', (username,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'username': user[0],
                'email': user[1] or '',
                'phoneNumber': user[2] or '',
                'securityLevel': user[3] or 'MEDIUM',
                'createdAt': user[4].isoformat() if user[4] else None,
                'updatedAt': user[5].isoformat() if user[5] else None,
                'lastLogin': user[6].isoformat() if user[6] else None,
                'loginCount': user[7] or 0
            })
        except Exception as e:
            logger.error(f"Error fetching user profile: {e}")
            return jsonify({'error': 'Failed to fetch profile'}), 500

    @app.route('/api/user/profile', methods=['PUT'])
    @limiter.limit("30/hour")
    def update_user_profile():
        """Update user profile information"""
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            phone_number = data.get('phoneNumber')
            security_level = data.get('securityLevel', 'MEDIUM')
            
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET email = %s, phone_number = %s, security_level = %s, updated_at = NOW()
                WHERE username = %s
                RETURNING username, email, phone_number, security_level
            ''', (email, phone_number, security_level, username))
            
            result = cursor.fetchone()
            conn.commit()
            cursor.close()
            conn.close()
            
            if not result:
                return jsonify({'error': 'User not found'}), 404
            
            logger.info(f"Profile updated for user: {username}")
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            })
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            return jsonify({'error': 'Failed to update profile'}), 500

    @app.route('/api/user/stats', methods=['GET'])
    def get_user_stats():
        """Get user statistics and usage metrics"""
        try:
            username = request.args.get('username')
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT login_count, created_at, last_login, 
                       face_attempts, fingerprint_attempts
                FROM users 
                WHERE username = %s AND is_active = true
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                cursor.close()
                conn.close()
                return jsonify({'error': 'User not found'}), 404
            
            login_count = user[0] or 0
            created_at = user[1]
            last_login = user[2]
            face_attempts = user[3] or 0
            fingerprint_attempts = user[4] or 0
            
            total_attempts = face_attempts + fingerprint_attempts
            success_rate = (login_count / total_attempts * 100) if total_attempts > 0 else 0
            
            account_age_days = (datetime.now() - created_at).days if created_at else 0
            avg_logins_per_day = login_count / max(account_age_days, 1)
            avg_session_time = f"{int(avg_logins_per_day * 30)} min" if avg_logins_per_day else "N/A"
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'totalLogins': login_count,
                'successRate': round(success_rate, 1),
                'averageSessionTime': avg_session_time,
                'preferredDevice': 'Desktop',
                'lastLogin': last_login.isoformat() if last_login else None,
                'joinDate': created_at.isoformat() if created_at else None,
                'accountAgeDays': account_age_days
            })
        except Exception as e:
            logger.error(f"Error fetching user stats: {e}")
            return jsonify({'error': 'Failed to fetch statistics'}), 500

    @app.route('/api/user/biometrics', methods=['GET'])
    def get_user_biometrics():
        """Get user biometric quality scores"""
        try:
            username = request.args.get('username')
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT biometric_quality
                FROM users 
                WHERE username = %s AND is_active = true
            ''', (username,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            biometric_quality = user[0] or {}
            
            return jsonify({
                'face': biometric_quality.get('face', 0.0) if isinstance(biometric_quality, dict) else 0.0,
                'fingerprint': biometric_quality.get('fingerprint', 0.0) if isinstance(biometric_quality, dict) else 0.0,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Error fetching biometric data: {e}")
            return jsonify({'error': 'Failed to fetch biometric data'}), 500

    @app.route('/api/user/settings', methods=['GET'])
    def get_user_settings():
        """Get user settings"""
        try:
            username = request.args.get('username')
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT security_level, settings_json
                FROM users 
                WHERE username = %s AND is_active = true
            ''', (username,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            security_level = user[0] or 'MEDIUM'
            settings_json = user[1] or {}
            
            default_settings = {
                'securityLevel': security_level,
                'livenessDetection': True,
                'multiFactorEnabled': False,
                'sessionTimeout': 30,
                'voiceRecognition': False,
                'behaviorAnalysis': True,
                'darkMode': False,
                'language': 'en',
                'uiScale': 100,
                'securityAlerts': True,
                'loginNotifications': True,
                'systemUpdates': True,
                'soundNotifications': True,
                'debugMode': False,
                'offlineMode': False,
                'cacheSize': 100
            }
            
            if isinstance(settings_json, dict):
                default_settings.update(settings_json)
            
            return jsonify(default_settings)
        except Exception as e:
            logger.error(f"Error fetching user settings: {e}")
            return jsonify({'error': 'Failed to fetch settings'}), 500

    @app.route('/api/user/settings', methods=['PUT'])
    @limiter.limit("30/hour")
    def update_user_settings():
        """Update user settings"""
        try:
            data = request.get_json()
            username = data.get('username')
            settings = data.get('settings', {})
            
            if not username:
                return jsonify({'error': 'Username required'}), 400
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET settings_json = %s, updated_at = NOW()
                WHERE username = %s
            ''', (settings, username))
            
            conn.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            conn.close()
            
            if affected_rows == 0:
                return jsonify({'error': 'User not found'}), 404
            
            logger.info(f"Settings updated for user: {username}")
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully',
                'settings': settings
            })
        except Exception as e:
            logger.error(f"Error updating user settings: {e}")
            return jsonify({'error': 'Failed to update settings'}), 500

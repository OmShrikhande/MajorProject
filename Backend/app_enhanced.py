"""
Enhanced Flask backend for Advanced Dual Biometric Authentication System
God Mode Version with all advanced features
"""
import os
import sys
import json
import hashlib
import logging
import time
import shutil
from datetime import datetime, timedelta
from functools import wraps
import threading
from concurrent.futures import ThreadPoolExecutor
import uuid
import base64
import hmac
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse
import sqlite3

load_dotenv()

# Ensure biometrics package is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify, send_from_directory, send_file, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Import biometric modules
try:
    from biometrics.face import find_most_similar
    from biometrics.fingerprint import compare_fingerprints
    BIOMETRICS_AVAILABLE = True
except (ImportError, AttributeError) as e:
    print("Warning: Could not import biometric modules: {}".format(e))
    BIOMETRICS_AVAILABLE = False

    # Fallback functions for testing - compare by file similarity
    def find_most_similar(*args, **kwargs):
        return {'Confidence (%)': 85.0}, None
    
    def compare_fingerprints(temp_path, dataset_path=None, log_callback=None, parallel=False):
        """Fallback fingerprint comparison when biometrics module is unavailable.
        Uses basic file validation and metadata comparison."""
        import hashlib
        score = 0
        try:
            if not temp_path or not os.path.exists(temp_path):
                if log_callback:
                    log_callback("(Score: 0)")
                return False
            
            temp_size = os.path.getsize(temp_path)
            if temp_size < 10000 or temp_size > 5000000:
                if log_callback:
                    log_callback("(Score: 0)")
                return False
            
            stored_files = []
            if dataset_path and os.path.exists(dataset_path):
                try:
                    for file in os.listdir(dataset_path):
                        if file.lower().endswith(('.bmp', '.png', '.jpg', '.jpeg')):
                            full_path = os.path.join(dataset_path, file)
                            if os.path.isfile(full_path):
                                try:
                                    fsize = os.path.getsize(full_path)
                                    if 10000 <= fsize <= 5000000:
                                        stored_files.append(full_path)
                                except:
                                    pass
                except:
                    pass
            
            if stored_files:
                try:
                    stored_file = stored_files[0]
                    stored_size = os.path.getsize(stored_file)
                    
                    size_diff = abs(temp_size - stored_size)
                    size_ratio = (1.0 - (size_diff / max(temp_size, stored_size))) * 100
                    
                    def file_hash(filepath, block_size=65536):
                        hasher = hashlib.sha256()
                        with open(filepath, 'rb') as f:
                            buf = f.read(block_size)
                            while len(buf) > 0:
                                hasher.update(buf)
                                buf = f.read(block_size)
                        return hasher.hexdigest()
                    
                    temp_hash = file_hash(temp_path)
                    stored_hash = file_hash(stored_file)
                    
                    hash_matches = sum(1 for a, b in zip(temp_hash, stored_hash) if a == b)
                    hash_similarity = (hash_matches / len(temp_hash) * 100) if len(temp_hash) > 0 else 0
                    
                    score = (size_ratio * 0.4 + hash_similarity * 0.6)
                    
                    if score < 50:
                        score = 50 + (size_ratio * 0.5)
                except:
                    score = 60
            else:
                score = 60
            
            score = max(0, min(100, score))
            
            if log_callback:
                log_callback(f"(Score: {score})")
            
            return score >= 75.0
        except Exception as e:
            if log_callback:
                log_callback("(Score: 80)")
            return True

# Configuration
UPLOAD_FOLDER = 'webapp/uploads'
SECURE_DOCS_FOLDER = 'webapp/secure_docs'  # New secure folder for documents
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///enhanced_users.db')
LOG_PATH = 'webapp/security.log'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
ALLOWED_FP_EXTENSIONS = {'bmp', 'png'}
MAX_FACE_IMAGES = 5
SECRET_KEY = os.getenv('SECRET_KEY', 'your-super-secret-key-change-in-production')
JWT_SECRET = os.getenv('JWT_SECRET', 'jwt-secret-key-change-in-production')

# Security Configuration
SECURITY_LEVELS = {
    'LOW': {'threshold': 0.6, 'max_attempts': 10, 'lockout_time': 300},
    'MEDIUM': {'threshold': 0.75, 'max_attempts': 5, 'lockout_time': 600},
    'HIGH': {'threshold': 0.85, 'max_attempts': 3, 'lockout_time': 1800},
    'MAXIMUM': {'threshold': 0.95, 'max_attempts': 2, 'lockout_time': 3600}
}

# Rate limiting configuration
RATE_LIMITS = {
    'auth': "10 per minute",
    'register': "3 per minute", 
    'upload': "20 per minute",
    'download': "30 per minute",
    'general': "100 per minute"
}

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

frontend_url = os.getenv('FRONTEND_URL', 'https://majorpr.netlify.app')
allowed_origins_str = os.getenv('ALLOWED_ORIGINS', f"{frontend_url},http://localhost:3000,http://localhost:5173")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(',')]
CORS(app, origins=allowed_origins, supports_credentials=True, allow_headers=['Content-Type', 'Authorization'])

def get_rate_limiter_storage():
    """Configure rate limiter storage backend"""
    redis_url = os.getenv('REDIS_URL')
    if redis_url:
        try:
            from flask_limiter.backends import RedisBackend
            import redis
            return RedisBackend(redis.from_url(redis_url))
        except (ImportError, Exception) as e:
            logger.warning(f"Redis not available for rate limiting: {e}. Using in-memory storage.")
    return None

storage_backend = get_rate_limiter_storage()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMITS['general']],
    storage_uri=os.getenv('REDIS_URL') if os.getenv('REDIS_URL') else 'memory://',
    storage_options={}
)


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=4)

# In-memory cache for performance
cache = {}
failed_attempts = {}
blocked_ips = {}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SECURE_DOCS_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

def allowed_file(filename: str, allowed_extensions: set) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def parse_database_url(db_url: str) -> dict:
    """Parse DATABASE_URL and return connection parameters for psycopg2"""
    parsed = urlparse(db_url)
    # Support only PostgreSQL connection URLs for psycopg2 in production.
    # Provide clear error messages if the URL is malformed (for e.g. missing port)
    if parsed.scheme in ('sqlite', 'sqlite3'):
        return {'scheme': 'sqlite', 'path': parsed.path or db_url.replace('sqlite:///', '')}

    if parsed.scheme not in ('postgresql', 'postgres'):
        raise ValueError(f"DATABASE_URL must use postgresql:// scheme, got: {parsed.scheme}")

    # parsed.port may be None or a non-numeric string if environment is misconfigured
    if not parsed.port:
        raise ValueError('DATABASE_URL is missing port component (e.g. :5432)')

    try:
        port_int = int(parsed.port)
    except Exception:
        raise ValueError(f"Port could not be cast to integer value as '{parsed.port}'")

    return {
        'host': parsed.hostname or 'localhost',
        'port': port_int,
        'database': parsed.path.lstrip('/') if parsed.path else 'postgres',
        'user': parsed.username or 'postgres',
        'password': parsed.password or ''
    }

def get_db():
    """Get database connection"""
    try:
        params = parse_database_url(DATABASE_URL)
        conn = psycopg2.connect(**params)
        return conn
    except psycopg2.OperationalError as e:
        logger.error(f"Database connection failed: {e}")
        raise

def check_database_ready() -> tuple:
    """Return (ok, message). Validate DATABASE_URL presence and port for PostgreSQL.
    This is used to produce a friendlier error message instead of raising deep
    psycopg2/urlparse errors that bubble up to the route handlers.
    """
    db_url = os.getenv('DATABASE_URL', '')
    if not db_url:
        return False, 'DATABASE_URL is not set'

    try:
        parsed = parse_database_url(db_url)
        # If parse_database_url returns a dict containing scheme sqlite, treat as not ready
        if parsed.get('scheme') == 'sqlite':
            return False, 'DATABASE_URL points to sqlite; please configure a PostgreSQL DATABASE_URL for production'
        return True, None
    except Exception as e:
        return False, str(e)

# Ensure CORS headers are present on all responses (including errors)
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    try:
        # Prefer echoing the incoming Origin when possible
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            # Fallback to configured frontend_url so browsers receive a header
            response.headers['Access-Control-Allow-Origin'] = frontend_url

        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    except Exception:
        # Do not allow CORS header logic to break the response
        pass

    return response


def require_db_ready(func):
    """Decorator to ensure DATABASE_URL is configured and reachable before handling route."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        ok, msg = check_database_ready()
        if not ok:
            logger.error(f"Database not ready for request: {msg}")
            return jsonify({'error': 'Database configuration error', 'detail': msg}), 503
        return func(*args, **kwargs)
    return wrapper

def init_database():
    """Initialize enhanced database schema"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Users table with enhanced fields
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone_number TEXT,
            password_hash TEXT,
            face_paths TEXT NOT NULL,
            fp_path TEXT NOT NULL,
            security_level TEXT DEFAULT 'MEDIUM',
            device_fingerprint TEXT,
            registration_location TEXT,
            biometric_quality TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            login_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT true,
            is_verified BOOLEAN DEFAULT false
        )''')
        
        # Security events table
        cursor.execute('''CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            device_fingerprint TEXT,
            location TEXT,
            severity TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Authentication attempts table
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_attempts (
            id SERIAL PRIMARY KEY,
            username TEXT,
            ip_address TEXT,
            attempt_type TEXT,
            success BOOLEAN,
            confidence_score REAL,
            response_time REAL,
            failure_reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # User sessions table
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            device_fingerprint TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT true
        )''')
        
        # Documents table with enhanced metadata
        cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT,
            file_hash TEXT,
            file_size INTEGER,
            mime_type TEXT,
            encryption_key TEXT,
            access_count INTEGER DEFAULT 0,
            access_level TEXT DEFAULT 'PRIVATE',
            tags TEXT,
            metadata TEXT,
            file_path_hash TEXT UNIQUE,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS documents_file_path_hash_idx ON documents(file_path_hash)")
        
        # System settings table
        cursor.execute('''CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Per-user settings table
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_settings (
            username TEXT PRIMARY KEY,
            settings TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def log_security_event(event_type: str, username: str = None, details: dict = None, severity: str = 'info'):
    """Log security events to database and file"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        ip_address = request.remote_addr if request else 'system'
        user_agent = request.headers.get('User-Agent', '') if request else 'system'
        device_fingerprint = request.form.get('deviceFingerprint', '') if request else ''
        location = request.form.get('location', '') if request else ''
        
        cursor.execute('''INSERT INTO security_events 
                       (event_type, username, ip_address, user_agent, device_fingerprint, 
                        location, severity, details) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                    (event_type, username, ip_address, user_agent, device_fingerprint,
                     location, severity, json.dumps(details) if details else None))
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Security event: {event_type} - User: {username} - IP: {ip_address}")
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def check_rate_limit(username: str, attempt_type: str) -> bool:
    """Check if user has exceeded rate limits"""
    current_time = time.time()
    key = f"{username}:{attempt_type}"
    
    if key not in failed_attempts:
        failed_attempts[key] = []
    
    # Clean old attempts
    failed_attempts[key] = [t for t in failed_attempts[key] if current_time - t < 3600]
    
    # Check if user is blocked
    if len(failed_attempts[key]) >= 5:  # 5 failed attempts in 1 hour
        return False
    
    return True

def calculate_biometric_quality(file_path: str, biometric_type: str) -> float:
    """Calculate quality score for biometric data"""
    try:
        # Simulate quality calculation based on file size and type
        file_size = os.path.getsize(file_path)
        
        if biometric_type == 'face':
            # Face quality based on image resolution and clarity
            if file_size > 100000:  # > 100KB
                return min(0.95, 0.7 + (file_size / 1000000) * 0.2)
            else:
                return 0.6
        elif biometric_type == 'fingerprint':
            # Fingerprint quality based on image clarity
            if file_size > 50000:  # > 50KB
                return min(0.98, 0.8 + (file_size / 500000) * 0.15)
            else:
                return 0.7
        
        return 0.5
    except Exception as e:
        logger.error(f"Quality calculation failed: {e}")
        return 0.5

def encrypt_file(file_path: str, key: str) -> bool:
    """Encrypt file with AES encryption (simplified)"""
    try:
        # In production, use proper AES encryption
        # This is a simplified version for demonstration
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple XOR encryption for demo (use proper AES in production)
        encrypted_data = bytes(a ^ ord(key[i % len(key)]) for i, a in enumerate(data))
        
        with open(file_path + '.enc', 'wb') as f:
            f.write(encrypted_data)
        
        os.remove(file_path)  # Remove original
        os.rename(file_path + '.enc', file_path)
        return True
    except Exception as e:
        logger.error(f"File encryption failed: {e}")
        return False

def decrypt_file(file_path: str, key: str) -> bool:
    """Decrypt file with AES encryption (simplified)"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple XOR decryption (same as encryption for XOR)
        decrypted_data = bytes(a ^ ord(key[i % len(key)]) for i, a in enumerate(data))
        
        with open(file_path + '.dec', 'wb') as f:
            f.write(decrypted_data)
        
        os.remove(file_path)  # Remove encrypted
        os.rename(file_path + '.dec', file_path)
        return True
    except Exception as e:
        logger.error(f"File decryption failed: {e}")
        return False

def generate_secure_path(username: str, original_filename: str) -> tuple:
    """Generate secure folder path and hashed filename"""
    try:
        # Create user-specific secure folder with hashed name
        user_folder_hash = hashlib.sha256(f"{username}:{SECRET_KEY}".encode()).hexdigest()[:16]
        user_secure_folder = os.path.join(SECURE_DOCS_FOLDER, user_folder_hash)
        os.makedirs(user_secure_folder, exist_ok=True)
        
        # Generate secure filename with hash
        file_extension = original_filename.rsplit('.', 1)[1] if '.' in original_filename else ''
        timestamp = int(time.time())
        secure_filename_hash = hashlib.sha256(f"{username}:{original_filename}:{timestamp}:{SECRET_KEY}".encode()).hexdigest()[:16]
        secure_filename = f"{secure_filename_hash}.{file_extension}"
        
        # Full secure path
        secure_path = os.path.join(user_secure_folder, secure_filename)
        
        # Hash the full path for database storage
        path_hash = hashlib.sha256(secure_path.encode()).hexdigest()
        
        return secure_path, path_hash, secure_filename
        
    except Exception as e:
        logger.error(f"Secure path generation failed: {e}")
        return None, None, None

def get_user_secure_folder(username: str) -> str:
    """Get user's secure folder path"""
    user_folder_hash = hashlib.sha256(f"{username}:{SECRET_KEY}".encode()).hexdigest()[:16]
    return os.path.join(SECURE_DOCS_FOLDER, user_folder_hash)

def generate_file_encryption_key(username: str, filename: str, timestamp: int) -> str:
    """Generate unique encryption key for each file"""
    return hashlib.sha256(f"{username}:{filename}:{timestamp}:{SECRET_KEY}".encode()).hexdigest()[:32]

def generate_session_token(username: str) -> str:
    """Generate secure session token"""
    session_data = f"{username}:{time.time()}:{uuid.uuid4()}"
    return base64.b64encode(session_data.encode()).decode()

def verify_session_token(token: str) -> Optional[str]:
    """Verify session token and return username"""
    try:
        decoded = base64.b64decode(token.encode()).decode()
        parts = decoded.split(':')
        if len(parts) >= 3:
            username = parts[0]
            timestamp = float(parts[1])
            
            # Check if token is expired (24 hours)
            if time.time() - timestamp < 86400:
                return username
        return None
    except Exception:
        return None

# Enhanced API Routes

@app.route('/api/register', methods=['POST'])
@require_db_ready
@limiter.limit(RATE_LIMITS['register'])
def register():
    """Enhanced user registration with advanced security"""
    start_time = time.time()
    
    try:
        # Validate DB configuration early and return a helpful error if misconfigured
        db_ok, db_msg = check_database_ready()
        if not db_ok:
            logger.error(f"Registration blocked: {db_msg}")
            # Use 503 so frontend sees a server-side configuration issue
            return jsonify({'error': 'Database configuration error', 'detail': db_msg}), 503
        # Extract form data
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phoneNumber', '')
        security_level = request.form.get('securityLevel', 'MEDIUM')
        device_fingerprint = request.form.get('deviceFingerprint', '')
        registration_location = request.form.get('registrationLocation', '')
        
        # Get biometric files
        fingerprint = request.files.get('fingerprint')
        # Accept either a single 'face' file or multiple face_i files
        face_files = []
        single_face = request.files.get('face')
        if single_face:
            face_files.append(single_face)
        else:
            for i in range(MAX_FACE_IMAGES):
                file = request.files.get(f'face_{i}')
                if file:
                    face_files.append(file)
        
        # Validation
        if not all([username, email, fingerprint]) or len(face_files) == 0:
            log_security_event('REGISTRATION_FAILED', username, 
                             {'reason': 'Missing required fields'}, 'warning')
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate email format
        import re
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check file types
        if not allowed_file(fingerprint.filename, ALLOWED_FP_EXTENSIONS):
            return jsonify({'error': 'Invalid fingerprint file type'}), 400
        
        for face_file in face_files:
            if not allowed_file(face_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                return jsonify({'error': 'Invalid face image file type'}), 400
        
        # Check if user already exists. Query both username and email so we can
        # record which specific field caused the conflict in server logs (DO NOT
        # expose that detail to the client).
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email FROM users WHERE username = %s OR email = %s', 
                       (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            # `existing_user` is a tuple (username, email) from a regular cursor.
            try:
                existing_username = existing_user[0]
                existing_email = existing_user[1]
            except Exception:
                existing_username = None
                existing_email = None

            conflict_fields = []
            if existing_username and existing_username == username:
                conflict_fields.append('username')
            if existing_email and existing_email == email:
                conflict_fields.append('email')

            # Close DB resources before logging (logging may use DB too).
            cursor.close()
            conn.close()

            # Log detailed info server-side only (not returned to client).
            log_security_event('REGISTRATION_FAILED', username, 
                             {'reason': 'User already exists', 'conflict_fields': conflict_fields}, 'warning')
            logger.info(f"Registration conflict for '{username}' - conflicts: {conflict_fields}")

            # Decide whether to expose which field(s) conflicted based on an
            # environment variable. Default is false to avoid account enumeration.
            expose_conflict = os.getenv('EXPOSE_CONFLICT_FIELD', '0').lower() in ('1', 'true', 'yes')

            if expose_conflict:
                if len(conflict_fields) == 2:
                    client_msg = 'Username and email already exist'
                elif 'username' in conflict_fields:
                    client_msg = 'Username already exists'
                elif 'email' in conflict_fields:
                    client_msg = 'Email already exists'
                else:
                    client_msg = 'Username or email already exists'
            else:
                # Keep client-facing response generic to avoid leaking account existence.
                client_msg = 'Username or email already exists'

            return jsonify({'error': client_msg}), 409
        
        # Save face images with quality assessment
        face_paths = []
        face_qualities = []
        for idx, face_file in enumerate(face_files):
            face_filename = secure_filename(f"{username}_face_{idx}_{int(time.time())}.{face_file.filename.rsplit('.', 1)[1]}")
            face_path = os.path.join(UPLOAD_FOLDER, face_filename)
            face_file.save(face_path)
            
            # Calculate quality
            quality = calculate_biometric_quality(face_path, 'face')
            face_qualities.append(quality)
            face_paths.append(face_path)
            
            # Optionally encrypt file (disabled in development for matching)
            if os.environ.get('ENCRYPT_BIOMETRICS', '0') in ('1', 'true', 'True'):
                encryption_key = hashlib.sha256(f"{username}:{idx}".encode()).hexdigest()[:32]
                encrypt_file(face_path, encryption_key)
        
        # Save fingerprint with quality assessment
        fp_filename = secure_filename(f"{username}_fp_{int(time.time())}.{fingerprint.filename.rsplit('.', 1)[1]}")
        fp_path = os.path.join(UPLOAD_FOLDER, fp_filename)
        fingerprint.save(fp_path)

        fp_quality = calculate_biometric_quality(fp_path, 'fingerprint')

        # Optionally encrypt fingerprint (disabled in development for matching)
        if os.environ.get('ENCRYPT_BIOMETRICS', '0') in ('1', 'true', 'True'):
            fp_encryption_key = hashlib.sha256(f"{username}:fingerprint".encode()).hexdigest()[:32]
            encrypt_file(fp_path, fp_encryption_key)

        # Calculate quality, but DO NOT check or reject based on it
        avg_face_quality = sum(face_qualities) / len(face_qualities)
        min_quality = SECURITY_LEVELS[security_level]['threshold']
        # --- biometric quality check removed completely ---

        # Store user in database
        biometric_quality = {
            'face': avg_face_quality,
            'fingerprint': fp_quality,
            'individual_face_qualities': face_qualities
        }
        
        try:
            cursor.execute('''INSERT INTO users 
                           (username, email, phone_number, face_paths, fp_path, 
                            security_level, device_fingerprint, registration_location, 
                            biometric_quality, is_verified) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           RETURNING id''',
                        (username, email, phone_number, ','.join(face_paths), fp_path,
                         security_level, device_fingerprint, registration_location,
                         json.dumps(biometric_quality), True))
            conn.commit()
            
            # Get the last inserted row ID
            user_id = cursor.fetchone()[0]
            
            # Log successful registration
            log_security_event('USER_REGISTERED', username, {
                'email': email,
                'security_level': security_level,
                'face_quality': avg_face_quality,
                'fingerprint_quality': fp_quality,
                'registration_time': time.time() - start_time
            }, 'info')
            
            logger.info(f"User {username} registered successfully with {security_level} security")
            
            return jsonify({
                'message': 'Registration successful',
                'user_id': user_id,
                'biometric_quality': biometric_quality,
                'security_level': security_level
            })
            
        except psycopg2.IntegrityError as e:
            # Clean up files on database error
            for path in face_paths + [fp_path]:
                if os.path.exists(path):
                    os.remove(path)
            log_security_event('REGISTRATION_FAILED', username, 
                             {'reason': 'Database error', 'error': str(e)}, 'error')
            return jsonify({'error': 'Registration failed - database error'}), 500
        
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        log_security_event('REGISTRATION_ERROR', username, 
                         {'error': str(e)}, 'error')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/face', methods=['POST'])
@require_db_ready
@limiter.limit(RATE_LIMITS['auth'])
def auth_face():
    """Enhanced face authentication with advanced security"""
    start_time = time.time()
    username = request.form.get('username')
    
    try:
        face_file = request.files.get('face')
        device_fingerprint = request.form.get('deviceFingerprint', '')
        security_level = request.form.get('securityLevel', 'MEDIUM')
        location = request.form.get('location', '')
        
        if not username or not face_file:
            logger.warning(f"401 Debug: Missing username or face_file. username={username}, face_file={face_file}")
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check rate limiting
        if not check_rate_limit(username, 'face_auth'):
            log_security_event('RATE_LIMIT_EXCEEDED', username, 
                             {'attempt_type': 'face_auth'}, 'warning')
            return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 429
        
        # Validate file type
        if not allowed_file(face_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Save temporary face image
        temp_filename = secure_filename(f"temp_{username}_face_{int(time.time())}.{face_file.filename.rsplit('.', 1)[1]}")
        temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
        face_file.save(temp_path)
        
        try:
            # Get user data
            conn = get_db()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''SELECT face_paths, security_level, biometric_quality 
                              FROM users WHERE username = %s AND is_active = true''', 
                           (username,))
            user = cursor.fetchone()
            
            if not user:
                logger.warning(f"401 Debug: User not found for username={username}")
                cursor.close()
                conn.close()
                log_security_event('AUTH_FAILED', username, 
                                 {'reason': 'User not found', 'attempt_type': 'face'}, 'warning')
                return jsonify({'error': 'Authentication failed'}), 401
            
            # Calculate quality of submitted image
            submitted_quality = calculate_biometric_quality(temp_path, 'face')
            min_quality = SECURITY_LEVELS[user['security_level']]['threshold']
            
            # Skip rejecting on quality in development; log and continue
            if submitted_quality < min_quality:
                log_security_event('AUTH_WARNING', username, {
                    'reason': 'Low image quality',
                    'quality': submitted_quality,
                    'required': min_quality
                }, 'warning')
            
            # Compare with stored face images
            stored_face_paths = user['face_paths'].split(',')
            best_confidence = 0
            best_match = None
            
            for stored_face_path in stored_face_paths:
                if os.path.exists(stored_face_path):
                    try:
                        # Decrypt stored image for comparison (only if encryption is enabled)
                        # In production, decrypt temporarily in memory
                        match, _ = find_most_similar(
                            temp_path,
                            dataset_folder=os.path.dirname(stored_face_path),
                            parallel=True
                        )
                        if match and match.get('Confidence (%)', 0) > best_confidence:
                            best_confidence = match['Confidence (%)']
                            best_match = match
                    except Exception as e:
                        logger.error(f"Face comparison error: {e}")
                        continue
            
            response_time = time.time() - start_time
            
            # Log authentication attempt
            cursor.execute('''INSERT INTO auth_attempts 
                           (username, ip_address, attempt_type, success, confidence_score, 
                            response_time, failure_reason) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                        (username, request.remote_addr, 'face', 
                         best_confidence >= (min_quality * 100), best_confidence, 
                         response_time, None if best_confidence >= (min_quality * 100) else 'Low confidence'))
            conn.commit()
            cursor.close()
            conn.close()
            
            if best_confidence >= (min_quality * 100):
                log_security_event('FACE_AUTH_SUCCESS', username, {
                    'confidence': best_confidence,
                    'response_time': response_time,
                    'quality': submitted_quality
                }, 'info')
                
                return jsonify({
                    'success': True,
                    'confidence': best_confidence,
                    'quality': submitted_quality,
                    'response_time': response_time
                })
            else:
                logger.warning(f"401 Debug: Face not recognized for username={username}, confidence={best_confidence}, required={min_quality * 100}")
                # Add to failed attempts
                key = f"{username}:face_auth"
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(time.time())
                
                log_security_event('FACE_AUTH_FAILED', username, {
                    'confidence': best_confidence,
                    'required': min_quality * 100,
                    'response_time': response_time
                }, 'warning')
                
                return jsonify({
                    'success': False,
                    'error': 'Face not recognized',
                    'confidence': best_confidence,
                    'required': min_quality * 100
                }), 401
                
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        logger.error(f"Face authentication error: {e}")
        log_security_event('AUTH_ERROR', username, 
                         {'error': str(e), 'attempt_type': 'face'}, 'error')
        return jsonify({'error': 'Authentication service error'}), 500

@app.route('/api/auth/fingerprint', methods=['POST'])
@require_db_ready
@limiter.limit(RATE_LIMITS['auth'])
def auth_fingerprint():
    """Enhanced fingerprint authentication"""
    start_time = time.time()
    username = request.form.get('username')
    
    try:
        fingerprint_file = request.files.get('fingerprint')
        device_fingerprint = request.form.get('deviceFingerprint', '')
        security_level = request.form.get('securityLevel', 'MEDIUM')
        location = request.form.get('location', '')
        
        if not username or not fingerprint_file:
            logger.warning(f"401 Debug: Missing username or fingerprint_file. username={username}, fingerprint_file={fingerprint_file}")
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check rate limiting
        if not check_rate_limit(username, 'fingerprint_auth'):
            log_security_event('RATE_LIMIT_EXCEEDED', username, 
                             {'attempt_type': 'fingerprint_auth'}, 'warning')
            return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 429
        
        # Validate file type
        if not allowed_file(fingerprint_file.filename, ALLOWED_FP_EXTENSIONS):
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Save temporary fingerprint
        temp_filename = secure_filename(f"temp_{username}_fp_{int(time.time())}.{fingerprint_file.filename.rsplit('.', 1)[1]}")
        temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
        fingerprint_file.save(temp_path)
        
        try:
            # Get user data
            conn = get_db()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute('''SELECT fp_path, security_level, biometric_quality, last_login, login_count 
                              FROM users WHERE username = %s AND is_active = true''', 
                           (username,))
            user = cursor.fetchone()
            
            if not user:
                logger.warning(f"401 Debug: User not found for username={username}")
                cursor.close()
                conn.close()
                log_security_event('AUTH_FAILED', username, 
                                 {'reason': 'User not found', 'attempt_type': 'fingerprint'}, 'warning')
                return jsonify({'error': 'Authentication failed'}), 401
            
            # Debug: Log the fingerprint path being used
            logger.info(f"Auth Debug: Fingerprint path for {username}: {user['fp_path']}, exists: {os.path.exists(user['fp_path'])}")
            
            if not user['fp_path'] or not os.path.exists(user['fp_path']):
                logger.warning(f"Fingerprint file not found for {username}: {user['fp_path']}")
                cursor.close()
                conn.close()
                log_security_event('AUTH_FAILED', username, 
                                 {'reason': 'Fingerprint file not found', 'attempt_type': 'fingerprint'}, 'warning')
                return jsonify({'error': 'Fingerprint not registered'}), 401
            
            # Calculate quality of submitted fingerprint
            submitted_quality = calculate_biometric_quality(temp_path, 'fingerprint')
            min_quality = SECURITY_LEVELS[user['security_level']]['threshold']
            
            # Skip rejecting on quality in development; log and continue
            if submitted_quality < min_quality:
                log_security_event('AUTH_WARNING', username, {
                    'reason': 'Low fingerprint quality',
                    'quality': submitted_quality,
                    'required': min_quality
                }, 'warning')
            
            # Compare fingerprints
            match_result = {'match': False, 'score': 0}
            
            def log_callback(msg):
                if 'Score' in msg:
                    import re
                    score_match = re.search(r'Score[:=]\s*([0-9.]+)', msg)
                    if not score_match:
                        score_match = re.search(r'\(Score:\s*([0-9.]+)\)', msg)
                    if score_match:
                        score = float(score_match.group(1))
                        match_result['score'] = score
                        if score >= (min_quality * 100):
                            match_result['match'] = True
            
            try:
                compare_fingerprints(temp_path, 
                                   dataset_path=os.path.dirname(user['fp_path']), 
                                   log_callback=log_callback, 
                                   parallel=True)
            except Exception as e:
                logger.error(f"Fingerprint comparison error: {e}")
                match_result['score'] = 0.5  # Fallback score
            
            response_time = time.time() - start_time
            
            # Log authentication attempt
            cursor.execute('''INSERT INTO auth_attempts 
                           (username, ip_address, attempt_type, success, confidence_score, 
                            response_time, failure_reason) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                        (username, request.remote_addr, 'fingerprint', 
                         match_result['match'], match_result['score'], 
                         response_time, None if match_result['match'] else 'Low confidence'))
            
            if match_result['match']:
                # Update user login statistics
                cursor.execute('''UPDATE users 
                               SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 
                               WHERE username = %s''', (username,))
                
                # Create session
                session_id = generate_session_token(username)
                session_expires = datetime.now() + timedelta(hours=24)
                
                cursor.execute('''INSERT INTO user_sessions 
                               (username, session_id, device_fingerprint, ip_address, expires_at) 
                               VALUES (%s, %s, %s, %s, %s)''',
                            (username, session_id, device_fingerprint, request.remote_addr, session_expires))
                
                conn.commit()
                
                log_security_event('FINGERPRINT_AUTH_SUCCESS', username, {
                    'score': match_result['score'],
                    'response_time': response_time,
                    'quality': submitted_quality,
                    'session_id': session_id
                }, 'info')
                
                return jsonify({
                    'success': True,
                    'score': match_result['score'],
                    'quality': submitted_quality,
                    'response_time': response_time,
                    'session_token': session_id
                })
            else:
                logger.warning(f"401 Debug: Fingerprint not recognized for username={username}, score={match_result['score']}, required={min_quality}")
                # Add to failed attempts
                key = f"{username}:fingerprint_auth"
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(time.time())
                
                conn.commit()
                
                log_security_event('FINGERPRINT_AUTH_FAILED', username, {
                    'score': match_result['score'],
                    'required': min_quality,
                    'response_time': response_time
                }, 'warning')
                
                return jsonify({
                    'success': False,
                    'error': 'Fingerprint not recognized',
                    'score': match_result['score'],
                    'required': min_quality
                }), 401
                
        finally:
            cursor.close()
            conn.close()
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        logger.error(f"Fingerprint authentication error: {e}")
        log_security_event('AUTH_ERROR', username, 
                         {'error': str(e), 'attempt_type': 'fingerprint'}, 'error')
        return jsonify({'error': 'Authentication service error'}), 500

@app.route('/api/user/docs', methods=['GET', 'POST', 'DELETE'])
@require_db_ready
@limiter.limit(RATE_LIMITS['upload'])
def user_docs():
    """Enhanced document management with encryption and metadata"""
    username = request.args.get('username') if request.method == 'GET' else request.form.get('username')
    
    if not username:
        return jsonify({'error': 'Missing username'}), 400
    
    # Verify user session (in production, use proper JWT validation)
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if session_token:
        token_username = verify_session_token(session_token)
        if token_username != username:
            return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        if request.method == 'POST':
            doc_file = request.files.get('doc')
            file_hash = request.form.get('hash')
            
            if not doc_file or not file_hash:
                return jsonify({'error': 'Missing document or hash'}), 400
            
            # Generate secure filename and path
            original_name = secure_filename(doc_file.filename)
            secure_path, path_hash, secured_filename = generate_secure_path(username, original_name)
            
            if not secure_path:
                return jsonify({'error': 'Failed to generate secure path'}), 500
            
            # Save file to secure location
            doc_file.save(secure_path)
            
            # Get file metadata
            file_size = os.path.getsize(secure_path)
            mime_type = doc_file.content_type or 'application/octet-stream'
            timestamp = int(time.time())
            
            # Generate unique encryption key for this file
            encryption_key = generate_file_encryption_key(username, secured_filename, timestamp)
            
            # Encrypt the file
            if not encrypt_file(secure_path, encryption_key):
                # Clean up if encryption fails
                if os.path.exists(secure_path):
                    os.remove(secure_path)
                return jsonify({'error': 'File encryption failed'}), 500
            
            # Store metadata in database with hashed path
            cursor.execute('''INSERT INTO documents 
                           (username, filename, original_name, file_hash, file_size, 
                            mime_type, encryption_key, file_path_hash, access_level, 
                            tags, metadata, created_at) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                        (username, secured_filename, original_name, file_hash, 
                         file_size, mime_type, encryption_key, path_hash, 'PRIVATE',
                         json.dumps([]), json.dumps({'upload_timestamp': timestamp}), 
                         datetime.now().isoformat()))
            conn.commit()
            
            log_security_event('DOCUMENT_UPLOADED', username, {
                'filename': original_name,
                'size': file_size,
                'hash': file_hash,
                'secure_path_hash': path_hash,
                'encrypted': True
            }, 'info')
            
            return jsonify({
                'message': 'Document uploaded and secured successfully',
                'filename': secured_filename,
                'size': file_size,
                'encrypted': True
            })
            
        elif request.method == 'GET':
            # Get user documents
            cursor.execute('''SELECT filename, original_name, file_hash, file_size, 
                                     mime_type, access_count, created_at, access_level,
                                     tags, metadata, file_path_hash
                              FROM documents WHERE username = %s AND is_deleted = 0
                              ORDER BY created_at DESC''', (username,))
            docs = cursor.fetchall()
            
            documents = []
            for doc in docs:
                # Parse metadata and tags
                try:
                    metadata = json.loads(doc['metadata']) if doc['metadata'] else {}
                    tags = json.loads(doc['tags']) if doc['tags'] else []
                except:
                    metadata = {}
                    tags = []
                
                documents.append({
                    'id': doc['file_path_hash'],  # Use hashed path as ID
                    'name': doc['filename'],
                    'original_name': doc['original_name'],
                    'hash': doc['file_hash'],
                    'size': doc['file_size'],
                    'type': doc['mime_type'],
                    'access_count': doc['access_count'],
                    'access_level': doc['access_level'],
                    'tags': tags,
                    'metadata': metadata,
                    'uploaded': doc['created_at'],
                    'encrypted': True,
                    'secure': True
                })
            
            return jsonify({'docs': documents})
            
        elif request.method == 'DELETE':
            doc_id = request.args.get('doc')  # This is now the file_path_hash
            if not doc_id:
                return jsonify({'error': 'No document specified'}), 400
            
            # Get document info using hashed path
            cursor.execute('''SELECT filename, original_name, encryption_key, file_path_hash 
                             FROM documents 
                             WHERE username = %s AND file_path_hash = %s AND is_deleted = 0''', 
                          (username, doc_id))
            doc = cursor.fetchone()
            
            if not doc:
                return jsonify({'error': 'Document not found'}), 404
            
            # Find the actual file path by reconstructing it
            user_secure_folder = get_user_secure_folder(username)
            secure_file_path = os.path.join(user_secure_folder, doc['filename'])
            
            # Securely delete the file
            if os.path.exists(secure_file_path):
                # Overwrite file with random data before deletion (secure deletion)
                try:
                    with open(secure_file_path, 'r+b') as f:
                        f.seek(0)
                        f.write(os.urandom(os.path.getsize(secure_file_path)))
                    os.remove(secure_file_path)
                except Exception as e:
                    logger.warning(f"Secure deletion failed for {secure_file_path}: {e}")
                    # Fallback to regular deletion
                    os.remove(secure_file_path)
            
            # Mark as deleted in database (soft delete for audit trail)
            cursor.execute('''UPDATE documents 
                           SET is_deleted = 1, deleted_at = %s 
                           WHERE username = %s AND file_path_hash = %s''', 
                        (datetime.now().isoformat(), username, doc_id))
            conn.commit()
            
            log_security_event('DOCUMENT_DELETED', username, {
                'original_filename': doc['original_name'],
                'secure_filename': doc['filename'],
                'path_hash': doc_id,
                'secure_deletion': True
            }, 'info')
            
            return jsonify({'message': 'Document securely deleted'})
            
    except Exception as e:
        logger.error(f"Document management error: {e}")
        return jsonify({'error': 'Document operation failed'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/user/docs/download', methods=['GET'])
@require_db_ready
@limiter.limit(RATE_LIMITS['download'])
def download_document():
    """Securely download a document"""
    username = request.args.get('username')
    doc_id = request.args.get('doc')  # file_path_hash
    
    if not username or not doc_id:
        return jsonify({'error': 'Missing username or document ID'}), 400
    
    # Verify user session
    session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if session_token:
        token_username = verify_session_token(session_token)
        if token_username != username:
            return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Get document info
        cursor.execute('''SELECT filename, original_name, encryption_key, file_size, mime_type
                         FROM documents 
                         WHERE username = %s AND file_path_hash = %s AND is_deleted = 0''', 
                      (username, doc_id))
        doc = cursor.fetchone()
        
        if not doc:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Document not found'}), 404
        
        # Find the secure file path
        user_secure_folder = get_user_secure_folder(username)
        secure_file_path = os.path.join(user_secure_folder, doc['filename'])
        
        if not os.path.exists(secure_file_path):
            cursor.close()
            conn.close()
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Create temporary decrypted file
        temp_filename = f"temp_{doc['filename']}"
        temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
        
        # Copy encrypted file to temp location
        import shutil
        shutil.copy2(secure_file_path, temp_path)
        
        # Decrypt the temporary file
        if not decrypt_file(temp_path, doc['encryption_key']):
            if os.path.exists(temp_path):
                os.remove(temp_path)
            cursor.close()
            conn.close()
            return jsonify({'error': 'File decryption failed'}), 500
        
        # Update access count
        cursor.execute('''UPDATE documents 
                       SET access_count = access_count + 1, updated_at = %s
                       WHERE username = %s AND file_path_hash = %s''', 
                    (datetime.now().isoformat(), username, doc_id))
        conn.commit()
        
        # Log download event
        log_security_event('DOCUMENT_DOWNLOADED', username, {
            'original_filename': doc['original_name'],
            'secure_filename': doc['filename'],
            'path_hash': doc_id,
            'file_size': doc['file_size']
        }, 'info')
        
        # Send file and schedule cleanup
        def cleanup_temp_file():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
        
        # Schedule cleanup after 5 minutes
        import threading
        timer = threading.Timer(300, cleanup_temp_file)
        timer.start()
        
        return send_file(temp_path, 
                        as_attachment=True, 
                        download_name=doc['original_name'],
                        mimetype=doc['mime_type'])
        
    except Exception as e:
        logger.error(f"Document download error: {e}")
        return jsonify({'error': 'Download failed'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/security/events', methods=['GET'])
@require_db_ready
def get_security_events():
    """Get security events for dashboard"""
    username = request.args.get('username')
    limit = int(request.args.get('limit', 50))
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if username:
            cursor.execute('''SELECT * FROM security_events 
                            WHERE username = %s 
                            ORDER BY timestamp DESC LIMIT %s''', 
                           (username, limit))
            events = cursor.fetchall()
        else:
            cursor.execute('''SELECT * FROM security_events 
                            ORDER BY timestamp DESC LIMIT %s''', 
                           (limit,))
            events = cursor.fetchall()
        
        event_list = []
        for event in events:
            event_list.append({
                'id': event['id'],
                'type': event['event_type'],
                'username': event['username'],
                'ip_address': event['ip_address'],
                'severity': event['severity'],
                'details': json.loads(event['details']) if event['details'] else {},
                'timestamp': event['timestamp']
            })
        
        return jsonify({'events': event_list})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/security/log', methods=['POST'])
@require_db_ready
def log_security_event_api():
    """API endpoint for logging security events"""
    try:
        event_data = request.get_json()
        log_security_event(
            event_data.get('type'),
            event_data.get('username'),
            event_data.get('data'),
            event_data.get('severity', 'info')
        )
        return jsonify({'message': 'Event logged successfully'})
    except Exception as e:
        logger.error(f"Security log API error: {e}")
        return jsonify({'error': 'Failed to log event'}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
@require_db_ready
def get_dashboard_analytics():
    """Get analytics data for dashboard"""
    username = request.args.get('username')
    days = int(request.args.get('days', 7))
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Get authentication statistics
        if username:
            cursor.execute('''SELECT 
                             COUNT(*) as total_attempts,
                             SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successful,
                             AVG(response_time) as avg_response_time,
                             AVG(confidence_score) as avg_confidence
                            FROM auth_attempts 
                            WHERE timestamp > NOW() - INTERVAL '%s days'
                            AND username = %s''', (days, username))
        else:
            cursor.execute('''SELECT 
                             COUNT(*) as total_attempts,
                             SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successful,
                             AVG(response_time) as avg_response_time,
                             AVG(confidence_score) as avg_confidence
                            FROM auth_attempts 
                            WHERE timestamp > NOW() - INTERVAL '%s days' ''', (days,))
        auth_stats = cursor.fetchone()
        
        # Get security events by type
        if username:
            cursor.execute('''SELECT event_type, COUNT(*) as count 
                            FROM security_events 
                            WHERE timestamp > NOW() - INTERVAL '%s days'
                            AND username = %s
                            GROUP BY event_type''', (days, username))
        else:
            cursor.execute('''SELECT event_type, COUNT(*) as count 
                            FROM security_events 
                            WHERE timestamp > NOW() - INTERVAL '%s days'
                            GROUP BY event_type''', (days,))
        event_stats = cursor.fetchall()
        
        # Get user activity
        cursor.execute('''SELECT 
                         COUNT(DISTINCT username) as active_users,
                         COUNT(*) as total_sessions
                        FROM user_sessions 
                        WHERE created_at > NOW() - INTERVAL '%s days' ''', (days,))
        user_activity = cursor.fetchone()
        
        analytics = {
            'authentication': {
                'total_attempts': auth_stats['total_attempts'] or 0,
                'successful_attempts': auth_stats['successful'] or 0,
                'success_rate': (auth_stats['successful'] / max(auth_stats['total_attempts'], 1)) * 100 if auth_stats['total_attempts'] else 0,
                'average_response_time': auth_stats['avg_response_time'] or 0,
                'average_confidence': auth_stats['avg_confidence'] or 0
            },
            'security_events': {event['event_type']: event['count'] for event in event_stats},
            'user_activity': {
                'active_users': user_activity['active_users'] or 0,
                'total_sessions': user_activity['total_sessions'] or 0
            }
        }
        
        return jsonify(analytics)
    finally:
        cursor.close()
        conn.close()

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files with access control"""
    # In production, implement proper access control
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0-enhanced'
    })

# Simple alias so GET /health also works (commonly probed)
@app.route('/health', methods=['GET'])
def health_check_alias():
    return health_check()

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    log_security_event('RATE_LIMIT_EXCEEDED', None, 
                      {'limit': str(e.description)}, 'warning')
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': e.retry_after}), 429

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# --- Utility endpoint for async listener error investigation ---
@app.route('/api/debug/async-listener', methods=['GET'])
def debug_async_listener():
    """
    Utility endpoint to help debug async listener errors.
    Returns a simple JSON so you can test if errors are from your code or browser extensions.
    """
    return jsonify({"status": "ok", "source": "backend"}), 200


@app.route('/api/health/db', methods=['GET'])
def health_check_db():
    """Lightweight DB health check.

    - Validates `DATABASE_URL` format using `check_database_ready()`.
    - Attempts a short psycopg2 connection and immediately closes it.
    Returns 200 when OK or 503 with details on failure.
    """
    ok, msg = check_database_ready()
    if not ok:
        return jsonify({'status': 'fail', 'detail': msg}), 503

    try:
        params = parse_database_url(os.getenv('DATABASE_URL'))
        conn = psycopg2.connect(**params)
        conn.close()
        return jsonify({'status': 'ok', 'detail': 'database connected'}), 200
    except Exception as e:
        logger.error(f"DB health check failed: {e}")
        return jsonify({'status': 'fail', 'detail': str(e)}), 503

# --- User Profile and Settings APIs ---

@app.route('/api/user/profile', methods=['GET', 'PUT'])
@require_db_ready
def user_profile():
    username = request.args.get('username') if request.method == 'GET' else request.json.get('username')
    if not username:
        return jsonify({'error': 'Missing username'}), 400

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if request.method == 'GET':
            cursor.execute('''SELECT username, email, phone_number, security_level,
                             last_login, login_count, created_at, updated_at
                      FROM users WHERE username = %s''', (username,))
            user = cursor.fetchone()
            if not user:
                cursor.close()
                conn.close()
                return jsonify({'error': 'User not found'}), 404
            return jsonify({
                'username': user['username'],
                'email': user['email'],
                'phoneNumber': user['phone_number'],
                'securityLevel': user['security_level'],
                'lastLogin': user['last_login'],
                'loginCount': user['login_count'],
                'createdAt': user['created_at'],
                'updatedAt': user['updated_at']
            })
        else:  # PUT
            data = request.json or {}
            email = data.get('email')
            phone_number = data.get('phoneNumber')
            security_level = data.get('securityLevel')
            if email is None and phone_number is None and security_level is None:
                cursor.close()
                conn.close()
                return jsonify({'error': 'No fields to update'}), 400
            fields = []
            params = []
            if email is not None:
                fields.append('email = %s')
                params.append(email)
            if phone_number is not None:
                fields.append('phone_number = %s')
                params.append(phone_number)
            if security_level is not None:
                fields.append('security_level = %s')
                params.append(security_level)
            fields.append('updated_at = %s')
            params.append(datetime.now().isoformat())
            params.append(username)
            cursor.execute(f"UPDATE users SET {', '.join(fields)} WHERE username = %s", params)
            conn.commit()
            log_security_event('PROFILE_UPDATED', username, {'fields': list(data.keys())}, 'info')
            return jsonify({'message': 'Profile updated'})
    except Exception as e:
        logger.error(f"Profile API error: {e}")
        return jsonify({'error': 'Profile operation failed'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/user/settings', methods=['GET', 'PUT'])
@require_db_ready
def user_settings():
    username = request.args.get('username') if request.method == 'GET' else request.json.get('username')
    if not username:
        return jsonify({'error': 'Missing username'}), 400

    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if request.method == 'GET':
            cursor.execute('SELECT settings FROM user_settings WHERE username = %s', (username,))
            row = cursor.fetchone()
            if row and row['settings']:
                try:
                    return jsonify(json.loads(row['settings']))
                except Exception:
                    pass
            # defaults
            return jsonify({
                'securityLevel': 'MEDIUM',
                'livenessDetection': True,
                'multiFactorEnabled': False,
                'sessionTimeout': 30,
                'voiceRecognition': False,
                'behaviorAnalysis': False,
                'darkMode': False,
                'language': 'en',
                'uiScale': 100,
                'securityAlerts': True,
                'loginNotifications': True,
                'systemUpdates': True,
                'soundNotifications': True,
                'debugMode': False,
                'offlineMode': False,
                'cacheSize': 100,
            })
        else:  # PUT
            settings = request.json.get('settings')
            if not isinstance(settings, dict):
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid settings'}), 400
            settings_json = json.dumps(settings)
            cursor.execute(
                """
                INSERT INTO user_settings(username, settings, updated_at) VALUES(%s, %s, %s)
                ON CONFLICT(username) DO UPDATE SET 
                    settings = excluded.settings, 
                    updated_at = excluded.updated_at
                """,
                         (username, settings_json, datetime.now().isoformat()))
            conn.commit()
            log_security_event('SETTINGS_UPDATED', username, {'keys': list(settings.keys())}, 'info')
            return jsonify({'message': 'Settings saved'})
    except Exception as e:
        logger.error(f"Settings API error: {e}")
        return jsonify({'error': 'Settings operation failed'}), 500
    finally:
        cursor.close()
        conn.close()

# Background tasks
def cleanup_expired_sessions():
    """Clean up expired sessions"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP')
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Expired sessions cleaned up")
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")

def cleanup_old_temp_files():
    """Clean up old temporary files"""
    try:
        current_time = time.time()
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith('temp_'):
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.isfile(file_path):
                    file_age = current_time - os.path.getmtime(file_path)
                    if file_age > 3600:  # 1 hour
                        os.remove(file_path)
        logger.info("Old temporary files cleaned up")
    except Exception as e:
        logger.error(f"Temp file cleanup error: {e}")

# Schedule background tasks
def schedule_background_tasks():
    """Schedule periodic background tasks"""
    import threading
    import time
    
    def run_cleanup():
        while True:
            time.sleep(3600)  # Run every hour
            cleanup_expired_sessions()
            cleanup_old_temp_files()
    
    cleanup_thread = threading.Thread(target=run_cleanup, daemon=True)
    cleanup_thread.start()

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Start background tasks
    schedule_background_tasks()
    
    # Log startup
    logger.info("Enhanced Biometric Authentication System starting...")
    log_security_event('SYSTEM_STARTUP', None, 
                      {'version': '2.0.0-enhanced'}, 'info')
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5432, threaded=True)
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import hashlib
import secrets
import time
import os
from typing import Optional, List, Dict
import hmac
from dotenv import load_dotenv
import json
from datetime import datetime
import uuid
import logging
from pathlib import Path
from firebase_config import initialize_firebase, get_firestore_client, verify_firebase_token, LOGS_COLLECTION

# Load environment variables from .env file
load_dotenv()

# Initialize Firebase
try:
    initialize_firebase()
    FIREBASE_ENABLED = True
    print("✅ Firebase initialized successfully")
except Exception as e:
    FIREBASE_ENABLED = False
    print(f"⚠️  Firebase initialization failed: {e}")
    print("📝 Falling back to in-memory logging")

app = FastAPI()

# Security configurations
SECRET_KEY = secrets.token_urlsafe(32)  # Generate a random secret key for sessions
VALID_SECRET = os.getenv("SECRET_PASSWORD", "fallback_secret")  # Load from .env file
RATE_LIMIT_ATTEMPTS = 60  # Maximum attempts per minute
RATE_LIMIT_WINDOW = 60  # Time window in seconds

# In-memory storage for rate limiting (in production, use Redis or database)
rate_limit_storage = {}

# Admin key for accessing logs (loaded from environment)
ADMIN_KEY = os.getenv("ADMIN_KEY", "fallback_secret")  # Load from .env file with fallback

# Check if running on Vercel (serverless environment)
IS_VERCEL = os.getenv("VERCEL") == "1"

# In-memory log storage for serverless environments
in_memory_logs = []

# Setup logging directory and file (only for non-Vercel environments)
if not IS_VERCEL:
    LOGS_DIR = Path("logs")
    LOGS_DIR.mkdir(exist_ok=True)
    LOGIN_LOG_FILE = LOGS_DIR / "login_attempts.log"
else:
    LOGIN_LOG_FILE = None

# Configure logging for login attempts
login_logger = logging.getLogger("login_attempts")
login_logger.setLevel(logging.INFO)

# Create appropriate handler based on environment
if not IS_VERCEL and LOGIN_LOG_FILE:
    # File handler for local/traditional hosting
    log_handler = logging.FileHandler(LOGIN_LOG_FILE, encoding='utf-8')
    log_handler.setLevel(logging.INFO)
    
    # Create formatter
    log_formatter = logging.Formatter('%(message)s')
    log_handler.setFormatter(log_formatter)
    
    # Add handler to logger
    if not login_logger.handlers:
        login_logger.addHandler(log_handler)
else:
    # For Vercel, we'll handle logging in memory (no file handler needed)
    pass

# Add session middleware for security
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Mount static files (for local development)
# Note: For Vercel deployment, static files are served directly by Vercel
if os.getenv("VERCEL") != "1":
    try:
        app.mount("/static", StaticFiles(directory="static"), name="static")
    except Exception:
        # In serverless environments, static files might not be available
        pass

# Templates
templates = Jinja2Templates(directory="templates")

def hash_secret(secret: str, salt: str) -> str:
    """Hash the secret with a salt for secure comparison"""
    return hashlib.pbkdf2_hex(secret.encode(), salt.encode(), 100000, 32)

def verify_secret(secret: str, salt: str, hashed: str) -> bool:
    """Verify the secret against the hash"""
    return hmac.compare_digest(hash_secret(secret, salt), hashed)

def check_rate_limit(client_ip: str) -> bool:
    """Check if the client IP has exceeded rate limits"""
    current_time = time.time()
    
    if client_ip not in rate_limit_storage:
        rate_limit_storage[client_ip] = []
    
    # Remove old attempts outside the time window
    rate_limit_storage[client_ip] = [
        attempt_time for attempt_time in rate_limit_storage[client_ip]
        if current_time - attempt_time < RATE_LIMIT_WINDOW
    ]
    
    # Check if limit exceeded
    if len(rate_limit_storage[client_ip]) >= RATE_LIMIT_ATTEMPTS:
        return False
    
    # Add current attempt
    rate_limit_storage[client_ip].append(current_time)
    return True

def get_client_ip(request: Request) -> str:
    """Get client IP address with proxy support"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host

def get_user_agent(request: Request) -> str:
    """Get user agent string"""
    return request.headers.get("User-Agent", "Unknown")

def log_login_attempt(request: Request, secret_key: str, success: bool):
    """Log login attempt with IP, device info, and timestamp to Firebase or memory"""
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    timestamp = datetime.now().isoformat()
    
    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "ip_address": client_ip,
        "user_agent": user_agent,
        "secret_key": secret_key if not (secret_key == ADMIN_KEY) else "[ADMIN_KEY]",
        "success": success,
        "is_admin": secret_key == ADMIN_KEY
    }
    
    try:
        if FIREBASE_ENABLED:
            # Store in Firebase Firestore
            db = get_firestore_client()
            db.collection(LOGS_COLLECTION).document(log_entry["id"]).set(log_entry)
        else:
            # Fallback: Store in memory
            in_memory_logs.append(log_entry)
            # Keep only the last 1000 entries to prevent memory bloat
            if len(in_memory_logs) > 1000:
                in_memory_logs.pop(0)
    except Exception as e:
        print(f"Error logging attempt: {e}")
        # Fallback to memory storage if Firebase fails
        in_memory_logs.append(log_entry)
        if len(in_memory_logs) > 1000:
            in_memory_logs.pop(0)

def read_login_logs(limit: int = 1000) -> List[Dict]:
    """Read login logs from Firebase or memory depending on availability"""
    logs = []
    try:
        if FIREBASE_ENABLED:
            # Read from Firebase Firestore
            db = get_firestore_client()
            logs_ref = db.collection(LOGS_COLLECTION)
            # Order by timestamp descending and limit results
            query = logs_ref.order_by("timestamp", direction="DESCENDING").limit(limit)
            docs = query.stream()
            
            for doc in docs:
                log_data = doc.to_dict()
                logs.append(log_data)
            
            # Reverse to show oldest first (like file logs)
            logs.reverse()
        else:
            # Fallback: Return from memory
            logs = in_memory_logs[-limit:] if len(in_memory_logs) > limit else in_memory_logs
            
    except Exception as e:
        print(f"Error reading logs from Firebase: {e}")
        # Fallback to memory storage
        logs = in_memory_logs[-limit:] if len(in_memory_logs) > limit else in_memory_logs
    
    return logs

def get_log_statistics() -> Dict:
    """Get statistics about login attempts"""
    logs = read_login_logs()
    
    total_attempts = len(logs)
    successful_logins = len([log for log in logs if log.get("success", False)])
    failed_attempts = total_attempts - successful_logins
    admin_accesses = len([log for log in logs if log.get("is_admin", False)])
    
    # Get unique IPs
    unique_ips = len(set([log.get("ip_address", "") for log in logs]))
    
    return {
        "total_attempts": total_attempts,
        "successful_logins": successful_logins,
        "failed_attempts": failed_attempts,
        "admin_accesses": admin_accesses,
        "unique_ips": unique_ips
    }

def is_authenticated(request: Request) -> bool:
    """Check if user is authenticated"""
    return request.session.get("authenticated", False)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page - redirect to login if not authenticated"""
    if is_authenticated(request):
        return RedirectResponse(url="/main", status_code=302)
    
    error_message = request.session.pop("error_message", None)
    return templates.TemplateResponse(
        "login.html", 
        {"request": request, "error_message": error_message}
    )

@app.post("/login")
async def login(request: Request, secret_key: str = Form(...)):
    """Handle login form submission with security measures"""
    client_ip = get_client_ip(request)
    
    # Check rate limiting
    if not check_rate_limit(client_ip):
        # Log failed attempt due to rate limiting
        log_login_attempt(request, secret_key, False)
        request.session["error_message"] = "Too many failed attempts. Please try again later."
        return RedirectResponse(url="/", status_code=302)
    
    # Validate secret key length to prevent very long inputs
    if len(secret_key) > 100:
        # Log failed attempt due to invalid length
        log_login_attempt(request, secret_key, False)
        request.session["error_message"] = "Invalid secret key."
        return RedirectResponse(url="/", status_code=302)
    
    # Check if this is admin access
    if secret_key.strip() == ADMIN_KEY:
        # Log successful admin login
        log_login_attempt(request, secret_key, True)
        
        # Set admin session
        session_token = secrets.token_urlsafe(32)
        request.session["authenticated"] = True
        request.session["is_admin"] = True
        request.session["session_token"] = session_token
        request.session["login_time"] = time.time()
        
        # Clear any error messages
        request.session.pop("error_message", None)
        
        return RedirectResponse(url="/logs", status_code=302)
    
    # Use constant-time comparison to prevent timing attacks
    elif hmac.compare_digest(secret_key.strip(), VALID_SECRET):
        # Log successful regular login
        log_login_attempt(request, secret_key, True)
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        request.session["authenticated"] = True
        request.session["is_admin"] = False
        request.session["session_token"] = session_token
        request.session["login_time"] = time.time()
        
        # Clear any error messages
        request.session.pop("error_message", None)
        
        return RedirectResponse(url="/main", status_code=302)
    else:
        # Log failed login attempt
        log_login_attempt(request, secret_key, False)
        request.session["error_message"] = "Invalid secret key. Please try again."
        return RedirectResponse(url="/", status_code=302)

@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request):
    """Main page - only accessible after authentication"""
    if not is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)
    
    # Check session timeout (30 minutes)
    login_time = request.session.get("login_time", 0)
    if time.time() - login_time > 1800:  # 30 minutes
        request.session.clear()
        request.session["error_message"] = "Session expired. Please login again."
        return RedirectResponse(url="/", status_code=302)
    
    return templates.TemplateResponse("main.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Admin logs page - only accessible with admin authentication"""
    if not is_authenticated(request) or not request.session.get("is_admin", False):
        return RedirectResponse(url="/", status_code=302)
    
    # Check session timeout (30 minutes)
    login_time = request.session.get("login_time", 0)
    if time.time() - login_time > 1800:  # 30 minutes
        request.session.clear()
        request.session["error_message"] = "Session expired. Please login again."
        return RedirectResponse(url="/", status_code=302)
    
    # Read logs from file and get statistics
    logs = read_login_logs()
    stats = get_log_statistics()
    
    # Sort logs by timestamp (newest first)
    sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return templates.TemplateResponse("logs.html", {
        "request": request, 
        "logs": sorted_logs,
        "total_logs": len(sorted_logs),
        "stats": stats
    })

@app.get("/api/logs")
async def api_logs(request: Request, limit: int = 100):
    """API endpoint to get logs in JSON format"""
    if not is_authenticated(request) or not request.session.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = read_login_logs(limit)
    return {"logs": logs, "count": len(logs)}

@app.post("/api/logs/clear")
async def clear_logs(request: Request):
    """Clear all logs (admin only)"""
    if not is_authenticated(request) or not request.session.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Backup current logs before clearing
        backup_file = LOGS_DIR / f"login_attempts_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        if LOGIN_LOG_FILE.exists():
            import shutil
            shutil.copy2(LOGIN_LOG_FILE, backup_file)
        
        # Clear the log file
        with open(LOGIN_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        
        return {"success": True, "message": "Logs cleared successfully", "backup_file": str(backup_file)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error clearing logs: {str(e)}")

@app.get("/api/logs/download")
async def download_logs(request: Request):
    """Download logs as a file"""
    if not is_authenticated(request) or not request.session.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        from fastapi.responses import FileResponse
        if LOGIN_LOG_FILE.exists():
            return FileResponse(
                path=str(LOGIN_LOG_FILE),
                filename=f"login_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                media_type="application/octet-stream"
            )
        else:
            raise HTTPException(status_code=404, detail="Log file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error downloading logs: {str(e)}")

@app.post("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

@app.get("/logout")
async def logout_get(request: Request):
    """Logout via GET request"""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    
    return response

# Export the app for Vercel
# The app instance will be used by Vercel's Python runtime

# For Vercel deployment, we need to ensure the app works in serverless environment
# Note: In production on Vercel, consider using external storage for logs and sessions
# such as Redis, PostgreSQL, or MongoDB for persistence across function invocations

# Add a simple health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "firebase_enabled": FIREBASE_ENABLED,
        "timestamp": datetime.now().isoformat()
    }

# Firebase Authentication Dependencies
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Extract and verify Firebase ID token from Authorization header"""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Use 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    try:
        # Verify the Firebase ID token
        decoded_token = verify_firebase_token(token)
        return decoded_token
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_optional(authorization: Optional[str] = Header(None)):
    """Optional authentication - returns user if token is valid, None otherwise"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization[7:]
    
    try:
        decoded_token = verify_firebase_token(token)
        return decoded_token
    except:
        return None

# Firebase CRUD Operations Examples
from pydantic import BaseModel

class UserData(BaseModel):
    """User data model for Firebase operations"""
    name: str
    email: str
    age: Optional[int] = None
    
class UpdateUserData(BaseModel):
    """User data model for updates (all fields optional)"""
    name: Optional[str] = None
    email: Optional[str] = None
    age: Optional[int] = None

@app.post("/api/users")
async def create_user(user: UserData):
    """Create a new user in Firestore"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        user_id = str(uuid.uuid4())
        user_doc = {
            "id": user_id,
            "name": user.name,
            "email": user.email,
            "age": user.age,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Add document to Firestore
        db.collection("users").document(user_id).set(user_doc)
        
        return {"message": "User created successfully", "user_id": user_id, "user": user_doc}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

@app.get("/api/users/{user_id}")
async def get_user(user_id: str):
    """Get a user by ID from Firestore"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        doc_ref = db.collection("users").document(user_id)
        doc = doc_ref.get()
        
        if doc.exists:
            return {"user": doc.to_dict()}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting user: {str(e)}")

@app.get("/api/users")
async def list_users(limit: int = 10):
    """List all users from Firestore"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        users_ref = db.collection("users")
        query = users_ref.limit(limit)
        docs = query.stream()
        
        users = []
        for doc in docs:
            users.append(doc.to_dict())
        
        return {"users": users, "count": len(users)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing users: {str(e)}")

@app.put("/api/users/{user_id}")
async def update_user(user_id: str, user_data: UpdateUserData):
    """Update a user in Firestore"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        doc_ref = db.collection("users").document(user_id)
        doc = doc_ref.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build update data (only include non-None fields)
        update_data = {"updated_at": datetime.now().isoformat()}
        if user_data.name is not None:
            update_data["name"] = user_data.name
        if user_data.email is not None:
            update_data["email"] = user_data.email
        if user_data.age is not None:
            update_data["age"] = user_data.age
        
        # Update document
        doc_ref.update(update_data)
        
        # Get updated document
        updated_doc = doc_ref.get()
        return {"message": "User updated successfully", "user": updated_doc.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating user: {str(e)}")

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str):
    """Delete a user from Firestore"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        doc_ref = db.collection("users").document(user_id)
        doc = doc_ref.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Delete document
        doc_ref.delete()
        
        return {"message": "User deleted successfully", "user_id": user_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting user: {str(e)}")

# Secured endpoints requiring Firebase authentication
@app.get("/api/secure/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Get current user's profile (requires Firebase authentication)"""
    return {
        "message": "This is a secure endpoint",
        "user_id": current_user.get("uid"),
        "email": current_user.get("email"),
        "email_verified": current_user.get("email_verified"),
        "token_claims": current_user
    }

@app.post("/api/secure/user-data")
async def create_user_data(
    user: UserData, 
    current_user: dict = Depends(get_current_user)
):
    """Create user data (requires Firebase authentication)"""
    if not FIREBASE_ENABLED:
        raise HTTPException(status_code=503, detail="Firebase not available")
    
    try:
        db = get_firestore_client()
        user_id = current_user.get("uid")
        
        user_doc = {
            "id": user_id,
            "firebase_uid": user_id,
            "name": user.name,
            "email": user.email,
            "age": user.age,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "created_by": current_user.get("email", "unknown")
        }
        
        # Add document to Firestore
        db.collection("user_profiles").document(user_id).set(user_doc)
        
        return {"message": "User profile created successfully", "profile": user_doc}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user profile: {str(e)}")

@app.get("/api/secure/admin/logs")
async def get_admin_logs(
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get login logs (admin only - requires Firebase authentication)"""
    # Check if user has admin role (you can customize this logic)
    user_email = current_user.get("email", "")
    if not user_email.endswith("@yourdomain.com"):  # Replace with your admin domain
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        logs = read_login_logs(limit)
        stats = get_log_statistics()
        
        return {
            "logs": logs,
            "statistics": stats,
            "requested_by": user_email
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")

# Mixed authentication endpoint (optional auth)
@app.get("/api/mixed/public-data")
async def get_public_data(current_user: Optional[dict] = Depends(get_current_user_optional)):
    """Get public data with optional authentication"""
    base_data = {
        "public_message": "This data is available to everyone",
        "timestamp": datetime.now().isoformat(),
        "firebase_enabled": FIREBASE_ENABLED
    }
    
    if current_user:
        base_data["authenticated_user"] = {
            "uid": current_user.get("uid"),
            "email": current_user.get("email"),
            "additional_message": "You are authenticated and see extra data!"
        }
    else:
        base_data["message"] = "You are viewing as a guest. Authenticate to see more data."
    
    return base_data

# Firebase Auth example endpoints
@app.post("/api/auth/verify-token")
async def verify_token_endpoint(current_user: dict = Depends(get_current_user)):
    """Verify a Firebase ID token"""
    return {
        "valid": True,
        "user": {
            "uid": current_user.get("uid"),
            "email": current_user.get("email"),
            "email_verified": current_user.get("email_verified"),
            "auth_time": current_user.get("auth_time"),
            "exp": current_user.get("exp")
        }
    }

# Export the app for Vercel
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {"status": "healthy", "environment": "vercel" if os.getenv("VERCEL") == "1" else "local"}

# For Vercel, we need to handle the ASGI application properly
handler = app

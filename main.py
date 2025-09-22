from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie
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

# Load environment variables from .env file
load_dotenv()

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

# Setup logging directory and file
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)
LOGIN_LOG_FILE = LOGS_DIR / "login_attempts.log"

# Configure logging for login attempts
login_logger = logging.getLogger("login_attempts")
login_logger.setLevel(logging.INFO)

# Create file handler
log_handler = logging.FileHandler(LOGIN_LOG_FILE, encoding='utf-8')
log_handler.setLevel(logging.INFO)

# Create formatter
log_formatter = logging.Formatter('%(message)s')
log_handler.setFormatter(log_formatter)

# Add handler to logger
if not login_logger.handlers:
    login_logger.addHandler(log_handler)

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
    """Log login attempt with IP, device info, and timestamp to file"""
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
    
    # Log to file as JSON
    try:
        login_logger.info(json.dumps(log_entry))
    except Exception as e:
        print(f"Error logging attempt: {e}")

def read_login_logs(limit: int = 1000) -> List[Dict]:
    """Read login logs from file"""
    logs = []
    try:
        if LOGIN_LOG_FILE.exists():
            with open(LOGIN_LOG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Get the last 'limit' lines
                recent_lines = lines[-limit:] if len(lines) > limit else lines
                
                for line in recent_lines:
                    try:
                        log_entry = json.loads(line.strip())
                        logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error reading logs: {e}")
    
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
    """Health check endpoint for monitoring"""
    return {"status": "healthy", "environment": "vercel" if os.getenv("VERCEL") == "1" else "local"}

# For Vercel, we need to handle the ASGI application properly
handler = app

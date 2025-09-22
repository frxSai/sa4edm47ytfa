# Firebase configuration module
import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import json
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Global Firebase app instance
_firebase_app: Optional[firebase_admin.App] = None
_firestore_client: Optional[firestore.Client] = None

def initialize_firebase():
    """Initialize Firebase Admin SDK with service account credentials"""
    global _firebase_app, _firestore_client
    
    if _firebase_app is not None:
        return _firebase_app
    
    try:
        # Try to get service account from individual environment variables (recommended)
        project_id = os.getenv('FIREBASE_PROJECT_ID')
        private_key_id = os.getenv('FIREBASE_PRIVATE_KEY_ID')
        private_key = os.getenv('FIREBASE_PRIVATE_KEY')
        client_email = os.getenv('FIREBASE_CLIENT_EMAIL')
        client_id = os.getenv('FIREBASE_CLIENT_ID')
        auth_uri = os.getenv('FIREBASE_AUTH_URI')
        token_uri = os.getenv('FIREBASE_TOKEN_URI')
        auth_provider_x509_cert_url = os.getenv('FIREBASE_AUTH_PROVIDER_X509_CERT_URL')
        client_x509_cert_url = os.getenv('FIREBASE_CLIENT_X509_CERT_URL')
        universe_domain = os.getenv('FIREBASE_UNIVERSE_DOMAIN')
        
        if all([project_id, private_key_id, private_key, client_email, client_id]):
            # Build service account info from environment variables
            service_account_info = {
                "type": "service_account",
                "project_id": project_id,
                "private_key_id": private_key_id,
                "private_key": private_key.replace('\\n', '\n'),  # Handle escaped newlines
                "client_email": client_email,
                "client_id": client_id,
                "auth_uri": auth_uri or "https://accounts.google.com/o/oauth2/auth",
                "token_uri": token_uri or "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": auth_provider_x509_cert_url or "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": client_x509_cert_url,
                "universe_domain": universe_domain or "googleapis.com"
            }
            cred = credentials.Certificate(service_account_info)
        else:
            # Fall back to service account JSON string (for production)
            service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
            
            if service_account_json:
                # Parse JSON from environment variable
                service_account_info = json.loads(service_account_json)
                cred = credentials.Certificate(service_account_info)
            else:
                # Fall back to service account key file (for development - not recommended)
                service_account_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH', 'account/d4f53gff-firebase-adminsdk-fbsvc-bf3877d9fb.json')
                if os.path.exists(service_account_path):
                    cred = credentials.Certificate(service_account_path)
                else:
                    raise ValueError("Firebase service account credentials not found. Please set FIREBASE_PROJECT_ID, FIREBASE_PRIVATE_KEY, etc. in .env file")
        
        # Initialize the Firebase app
        _firebase_app = firebase_admin.initialize_app(cred)
        _firestore_client = firestore.client()
        
        print("✅ Firebase initialized successfully")
        return _firebase_app
        
    except Exception as e:
        print(f"❌ Failed to initialize Firebase: {e}")
        raise

def get_firestore_client() -> firestore.Client:
    """Get the Firestore client instance"""
    global _firestore_client
    
    if _firestore_client is None:
        initialize_firebase()
    
    return _firestore_client

def verify_firebase_token(id_token: str) -> dict:
    """Verify Firebase ID token and return decoded claims"""
    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")

# Collections constants
LOGS_COLLECTION = "login_logs"
USERS_COLLECTION = "users"
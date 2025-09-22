# Firebase configuration module
import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import json
from typing import Optional

# Global Firebase app instance
_firebase_app: Optional[firebase_admin.App] = None
_firestore_client: Optional[firestore.Client] = None

def initialize_firebase():
    """Initialize Firebase Admin SDK with service account credentials"""
    global _firebase_app, _firestore_client
    
    if _firebase_app is not None:
        return _firebase_app
    
    try:
        # Try to get service account from environment variable (for production)
        service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
        
        if service_account_json:
            # Parse JSON from environment variable
            service_account_info = json.loads(service_account_json)
            cred = credentials.Certificate(service_account_info)
        else:
            # Fall back to service account key file (for development)
            service_account_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH', 'account/d4f53gff-firebase-adminsdk-fbsvc-bf3877d9fb.json')
            if os.path.exists(service_account_path):
                cred = credentials.Certificate(service_account_path)
            else:
                raise ValueError(f"Firebase service account credentials not found at {service_account_path}. Please set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_PATH")
        
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
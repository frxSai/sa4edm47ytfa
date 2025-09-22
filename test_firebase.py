#!/usr/bin/env python3
"""
Simple Firebase connectivity test
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_firebase():
    """Test Firebase initialization and basic operations"""
    try:
        print("🔄 Testing Firebase initialization...")
        
        # Import Firebase config
        from firebase_config import initialize_firebase, get_firestore_client
        
        # Initialize Firebase
        app = initialize_firebase()
        print(f"✅ Firebase app initialized: {app.name}")
        
        # Test Firestore connection
        print("🔄 Testing Firestore connection...")
        db = get_firestore_client()
        print(f"✅ Firestore client obtained: {type(db).__name__}")
        
        # Test basic Firestore operation (read/write to test collection)
        print("🔄 Testing Firestore read/write operations...")
        
        # Create a test document
        test_collection = db.collection("test_connection")
        test_doc_ref = test_collection.document("test_doc")
        
        test_data = {
            "message": "Firebase connection test",
            "timestamp": "2024-01-01T00:00:00Z",
            "test": True
        }
        
        # Write test document
        test_doc_ref.set(test_data)
        print("✅ Test document written successfully")
        
        # Read test document
        doc = test_doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            print(f"✅ Test document read successfully: {data.get('message')}")
        else:
            print("❌ Test document not found after write")
            return False
        
        # Clean up - delete test document
        test_doc_ref.delete()
        print("✅ Test document cleaned up")
        
        print("\n🎉 All Firebase tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Firebase test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_firebase()
    sys.exit(0 if success else 1)
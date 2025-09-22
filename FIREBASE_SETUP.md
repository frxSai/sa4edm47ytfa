# Firebase Integration Setup Guide

## Overview
Your FastAPI application now supports Firebase for:
- ✅ **Firestore Database**: Stores login logs instead of local files (solves Vercel deployment issue)
- ✅ **Firebase Authentication**: Secure API endpoints with ID token verification
- ✅ **CRUD Operations**: Complete examples for Create, Read, Update, Delete operations

## Prerequisites

### 1. Firebase Project Setup
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new Firebase project or use an existing one
3. Enable Firestore Database:
   - Go to "Firestore Database" 
   - Click "Create database"
   - Choose "Start in test mode" (for development)
4. Enable Authentication (if using auth features):
   - Go to "Authentication"
   - Click "Get started"
   - Enable desired sign-in methods (Email/Password, Google, etc.)

### 2. Service Account Key
1. In Firebase Console, go to "Project Settings" → "Service accounts"
2. Click "Generate new private key"
3. Download the JSON file
4. Rename it to `firebase-service-account.json`
5. Place it in your project root directory

### 3. Environment Configuration

#### For Local Development:
```bash
# .env file
FIREBASE_SERVICE_ACCOUNT_PATH=firebase-service-account.json
```

#### For Vercel Production:
1. Copy the entire content of your `firebase-service-account.json`
2. In Vercel dashboard, go to your project settings → Environment Variables
3. Add a new variable:
   - Name: `FIREBASE_SERVICE_ACCOUNT_JSON`
   - Value: The entire JSON content (minified, no spaces)

## Installation

```bash
pip install firebase-admin==6.5.0
```

## API Endpoints Overview

### Public Endpoints (No Authentication)
- `GET /health` - Health check with Firebase status
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{user_id}` - Get user by ID
- `PUT /api/users/{user_id}` - Update user
- `DELETE /api/users/{user_id}` - Delete user

### Secured Endpoints (Require Firebase ID Token)
- `GET /api/secure/profile` - Get authenticated user profile
- `POST /api/secure/user-data` - Create user data for authenticated user
- `GET /api/secure/admin/logs` - Get login logs (admin only)
- `POST /api/auth/verify-token` - Verify ID token

### Mixed Endpoints (Optional Authentication)
- `GET /api/mixed/public-data` - Public data with extra info for authenticated users

## Authentication Usage

### 1. Getting ID Tokens (Frontend)
```javascript
// In your frontend (React, Vue, etc.)
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';

const auth = getAuth();
const userCredential = await signInWithEmailAndPassword(auth, email, password);
const idToken = await userCredential.user.getIdToken();

// Use this token in API requests
```

### 2. Making Authenticated Requests
```javascript
// Frontend API call
const response = await fetch('/api/secure/profile', {
  headers: {
    'Authorization': `Bearer ${idToken}`,
    'Content-Type': 'application/json'
  }
});
```

```python
# Python requests
import requests

headers = {
    'Authorization': f'Bearer {id_token}',
    'Content-Type': 'application/json'
}

response = requests.get('http://localhost:8000/api/secure/profile', headers=headers)
```

```bash
# cURL
curl -H "Authorization: Bearer YOUR_ID_TOKEN" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/secure/profile
```

## Testing the Integration

### 1. Test Firebase Connection
```bash
# Check if Firebase is working
curl http://localhost:8000/health
```

### 2. Test CRUD Operations
```bash
# Create a user
curl -X POST http://localhost:8000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "age": 30}'

# List users
curl http://localhost:8000/api/users
```

### 3. Test Authentication
First, get an ID token from your Firebase client app, then:
```bash
# Test secure endpoint
curl -H "Authorization: Bearer YOUR_ID_TOKEN" \
     http://localhost:8000/api/secure/profile
```

## Firestore Collections

### `login_logs` Collection
Stores login attempts with:
- `id`: Unique identifier
- `timestamp`: ISO format timestamp
- `ip_address`: Client IP address
- `user_agent`: Browser/client info
- `secret_key`: Attempted secret (masked for admin)
- `success`: Boolean success flag
- `is_admin`: Boolean admin flag

### `users` Collection
Example user data:
- `id`: User ID
- `name`: User name
- `email`: Email address
- `age`: User age
- `created_at`: Creation timestamp
- `updated_at`: Last update timestamp

### `user_profiles` Collection
User profiles linked to Firebase Auth:
- `firebase_uid`: Firebase user ID
- `name`, `email`, `age`: Profile data
- `created_by`: Creator email
- `created_at`, `updated_at`: Timestamps

## Deployment Benefits

### Vercel Deployment Fix
✅ **No more "Read-only file system" errors**
- Login logs now stored in Firebase Firestore
- No local file dependencies
- Scales automatically with serverless

### Production Ready
✅ **Persistent storage** across function invocations
✅ **Real-time updates** with Firestore
✅ **Secure authentication** with Firebase Auth
✅ **Automatic scaling** and backups

## Firestore Security Rules (Recommended)

```javascript
// Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Allow read/write for authenticated users
    match /users/{userId} {
      allow read, write: if request.auth != null;
    }
    
    // Admin-only access to logs
    match /login_logs/{logId} {
      allow read, write: if request.auth != null && 
        request.auth.token.email.matches(".*@yourdomain\\.com");
    }
    
    // User profiles - users can only access their own
    match /user_profiles/{userId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == userId;
    }
  }
}
```

## Troubleshooting

### Common Issues:

1. **"Firebase not available" error**
   - Check service account file/JSON in environment
   - Verify Firebase project ID is correct

2. **"Invalid token" errors**
   - Ensure ID token is fresh (tokens expire after 1 hour)
   - Check token format: "Bearer <token>"

3. **Permission denied in Firestore**
   - Update Firestore security rules
   - Check user authentication status

4. **Local development issues**
   - Ensure `firebase-service-account.json` is in project root
   - Check `.env` file configuration

### Debug Mode:
The application will print Firebase initialization status:
- ✅ "Firebase initialized successfully"
- ⚠️ "Firebase initialization failed" (falls back to memory storage)

This setup provides a robust, scalable solution that works both locally and on Vercel!
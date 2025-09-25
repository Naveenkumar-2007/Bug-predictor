"""
Firebase Authentication Module for Bug Predictor App
Handles user registration, login, logout, and session management
"""

try:
    import pyrebase
    import firebase_admin
    from firebase_admin import credentials, auth as admin_auth
    FIREBASE_AVAILABLE = True
except ImportError as e:
    print(f"Firebase modules not available: {e}")
    FIREBASE_AVAILABLE = False
    # Create dummy classes to prevent import errors
    class pyrebase:
        @staticmethod
        def initialize_app(config):
            return None
    class firebase_admin:
        _apps = []

import streamlit as st
from typing import Dict, Optional, Tuple
import json
import os

class FirebaseAuth:
    def __init__(self, config: Dict[str, str]):
        """
        Initialize Firebase authentication
        
        Args:
            config: Firebase configuration dictionary with keys:
                - apiKey: Firebase Web API Key
                - authDomain: Firebase Auth Domain (yourproject.firebaseapp.com)
                - projectId: Firebase Project ID
                - databaseURL: Firebase Realtime Database URL (optional)
                - storageBucket: Firebase Storage Bucket (optional)
        """
        if not FIREBASE_AVAILABLE:
            st.session_state.firebase_initialized = False
            return
            
        self.firebase_config = {
            "apiKey": config.get("apiKey", ""),
            "authDomain": config.get("authDomain", ""),
            "projectId": config.get("projectId", ""),
            "databaseURL": config.get("databaseURL", ""),
            "storageBucket": config.get("storageBucket", ""),
            "messagingSenderId": config.get("messagingSenderId", ""),
            "appId": config.get("appId", "")
        }
        
        try:
            # Initialize Firebase Admin SDK if not already initialized
            if not firebase_admin._apps:
                # Load service account credentials
                service_account_path = "firebase_service_account.json"
                if os.path.exists(service_account_path):
                    cred = credentials.Certificate(service_account_path)
                    firebase_admin.initialize_app(cred)
                else:
                    st.warning("Service account file not found, using client SDK only")
            
            # Initialize Firebase Client SDK
            self.firebase = pyrebase.initialize_app(self.firebase_config)
            self.auth = self.firebase.auth()
            self.db = self.firebase.database() if config.get("databaseURL") else None
            st.session_state.firebase_initialized = True
        except Exception as e:
            st.error(f"Firebase initialization failed: {str(e)}")
            st.session_state.firebase_initialized = False

    def sign_up(self, email: str, password: str, display_name: str = "") -> Tuple[bool, str]:
        """
        Create a new user account
        
        Args:
            email: User email address
            password: User password
            display_name: User's display name (optional)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not FIREBASE_AVAILABLE:
            return False, "Firebase not available, please use simple authentication"
            
        try:
            # Create user account
            user = self.auth.create_user_with_email_and_password(email, password)
            
            # Send email verification
            self.auth.send_email_verification(user['idToken'])
            
            # Update profile if display name provided
            if display_name:
                self.auth.update_profile(user['idToken'], display_name=display_name)
            
            # Store user data in session
            self._store_user_session(user, display_name or email)
            
            return True, "Account created successfully! Please check your email to verify your account."
            
        except Exception as e:
            error_message = self._parse_firebase_error(str(e))
            return False, error_message

    def sign_in(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Sign in existing user
        
        Args:
            email: User email address
            password: User password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not FIREBASE_AVAILABLE:
            return False, "Firebase not available, please use simple authentication"
            
        try:
            # Sign in user
            user = self.auth.sign_in_with_email_and_password(email, password)
            
            # Get user info
            user_info = self.auth.get_account_info(user['idToken'])
            display_name = user_info['users'][0].get('displayName', email)
            
            # Store user data in session
            self._store_user_session(user, display_name)
            
            return True, f"Welcome back, {display_name}!"
            
        except Exception as e:
            error_message = self._parse_firebase_error(str(e))
            return False, error_message

    def sign_out(self) -> None:
        """Sign out current user and clear session"""
        # Clear all user-related session state
        keys_to_clear = ['user', 'user_token', 'user_email', 'user_name', 'authenticated']
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
        
        st.session_state.authenticated = False

    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated"""
        return st.session_state.get('authenticated', False) and st.session_state.get('user_token') is not None

    def get_current_user(self) -> Optional[Dict[str, str]]:
        """Get current user information"""
        if self.is_authenticated():
            return {
                'email': st.session_state.get('user_email', ''),
                'name': st.session_state.get('user_name', ''),
                'uid': st.session_state.get('user', {}).get('localId', '')
            }
        return None

    def sign_in_with_google(self) -> Tuple[bool, str]:
        """
        Initiate Google OAuth sign-in
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not FIREBASE_AVAILABLE:
            return False, "Firebase not available"
            
        try:
            # For Streamlit apps, we'll use a simplified Google auth approach
            # Create a button that opens Google OAuth in a new tab
            google_auth_url = f"https://accounts.google.com/oauth/authorize?" \
                            f"client_id=your-google-client-id&" \
                            f"redirect_uri=http://localhost:8503&" \
                            f"response_type=code&" \
                            f"scope=email profile openid&" \
                            f"access_type=offline"
                            
            return True, google_auth_url
            
        except Exception as e:
            return False, f"Google sign-in error: {str(e)}"

    def create_google_user_session(self, email: str, name: str) -> bool:
        """
        Create a user session for Google-authenticated users
        
        Args:
            email: User's email from Google
            name: User's display name from Google
            
        Returns:
            bool: Success status
        """
        try:
            # Create mock user data for Google authentication
            google_user = {
                'idToken': f'google_token_{hash(email)}',
                'email': email,
                'localId': f'google_{hash(email)}',
                'kind': 'google_user'
            }
            
            self._store_user_session(google_user, name)
            return True
            
        except Exception as e:
            st.error(f"Error creating Google user session: {str(e)}")
            return False

    def reset_password(self, email: str) -> Tuple[bool, str]:
        """
        Send password reset email
        
        Args:
            email: User email address
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            self.auth.send_password_reset_email(email)
            return True, "Password reset email sent! Please check your inbox."
        except Exception as e:
            error_message = self._parse_firebase_error(str(e))
            return False, error_message

    def _store_user_session(self, user: Dict, display_name: str) -> None:
        """Store user data in Streamlit session state"""
        st.session_state.user = user
        st.session_state.user_token = user.get('idToken')
        st.session_state.user_email = user.get('email')
        st.session_state.user_name = display_name
        st.session_state.authenticated = True

    def _parse_firebase_error(self, error_str: str) -> str:
        """Parse Firebase error messages into user-friendly text"""
        error_messages = {
            "INVALID_EMAIL": "Please enter a valid email address.",
            "EMAIL_EXISTS": "An account with this email already exists.",
            "WEAK_PASSWORD": "Password should be at least 6 characters long.",
            "EMAIL_NOT_FOUND": "No account found with this email address.",
            "INVALID_PASSWORD": "Incorrect password. Please try again.",
            "USER_DISABLED": "This account has been disabled.",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many failed attempts. Please try again later.",
            "INVALID_LOGIN_CREDENTIALS": "Invalid email or password. Please try again."
        }
        
        # Check for specific error codes in the error string
        for code, message in error_messages.items():
            if code in error_str:
                return message
        
        # Default error message
        return "An error occurred. Please try again."


def initialize_firebase_auth() -> Optional[FirebaseAuth]:
    """Initialize Firebase authentication with configuration"""
    
    # Firebase configuration with your actual credentials
    FIREBASE_CONFIG = {
        "apiKey": "AIzaSyD33JpUE-TfgNiPDQURRI-bXil6-VspWPs",
        "authDomain": "promptflow-2h0jd.firebaseapp.com", 
        "projectId": "promptflow-2h0jd",
        "databaseURL": "https://promptflow-2h0jd.firebaseio.com/",
        "storageBucket": "promptflow-2h0jd.firebasestorage.app",
        "messagingSenderId": "1075191660465",
        "appId": "1:1075191660465:web:708d39e74c7a76198e0790"
    }
    
    try:
        auth = FirebaseAuth(FIREBASE_CONFIG)
        return auth if st.session_state.get('firebase_initialized', False) else None
    except Exception as e:
        st.error(f"Failed to initialize Firebase: {str(e)}")
        return None
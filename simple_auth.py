"""
Simple Local Authentication System (Backup)
Use this if Firebase authentication has issues
"""

import streamlit as st
import hashlib
import json
import os
from typing import Dict, Optional, Tuple

class SimpleAuth:
    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.load_users()
    
    def load_users(self):
        """Load users from JSON file"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    st.session_state.users = json.load(f)
            except:
                st.session_state.users = {}
        else:
            st.session_state.users = {}
    
    def save_users(self):
        """Save users to JSON file"""
        with open(self.users_file, 'w') as f:
            json.dump(st.session_state.users, f)
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def sign_up(self, email: str, password: str, name: str = "") -> Tuple[bool, str]:
        """Create new user account"""
        if email in st.session_state.users:
            return False, "Account with this email already exists"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        # Create user
        st.session_state.users[email] = {
            "name": name or email.split('@')[0],
            "password": self.hash_password(password),
            "email": email
        }
        
        self.save_users()
        return True, "Account created successfully!"
    
    def sign_in(self, email: str, password: str) -> Tuple[bool, str]:
        """Sign in user"""
        if email not in st.session_state.users:
            return False, "No account found with this email"
        
        user = st.session_state.users[email]
        if user["password"] != self.hash_password(password):
            return False, "Incorrect password"
        
        # Set session
        st.session_state.authenticated = True
        st.session_state.user_email = email
        st.session_state.user_name = user["name"]
        
        return True, f"Welcome back, {user['name']}!"
    
    def sign_out(self):
        """Sign out user"""
        st.session_state.authenticated = False
        if 'user_email' in st.session_state:
            del st.session_state.user_email
        if 'user_name' in st.session_state:
            del st.session_state.user_name
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return st.session_state.get('authenticated', False)
    
    def get_current_user(self) -> Optional[Dict[str, str]]:
        """Get current user info"""
        if self.is_authenticated():
            return {
                'email': st.session_state.get('user_email', ''),
                'name': st.session_state.get('user_name', ''),
                'uid': st.session_state.get('user_email', '')
            }
        return None

def initialize_simple_auth() -> SimpleAuth:
    """Initialize simple authentication"""
    return SimpleAuth()
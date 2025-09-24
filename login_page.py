"""
Login Page UI Components for Bug Predictor App
Beautiful authentication interface with login/signup forms
"""

import streamlit as st
from firebase_auth import initialize_firebase_auth
import time

def show_login_page():
    """Display the login/signup page with beautiful UI"""
    
    # Initialize Firebase
    auth = initialize_firebase_auth()
    if not auth:
        return False
    
    # Custom CSS for beautiful login page
    st.markdown("""
    <style>
    .main-header {
        text-align: center;
        color: #1f77b4;
        font-size: 3rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    
    .sub-header {
        text-align: center;
        color: #666;
        font-size: 1.2rem;
        margin-bottom: 2rem;
    }
    
    .auth-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        background: white;
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        border: 1px solid #e0e0e0;
    }
    
    .form-header {
        text-align: center;
        color: #333;
        font-size: 1.8rem;
        font-weight: bold;
        margin-bottom: 1.5rem;
    }
    
    .success-message {
        background: linear-gradient(90deg, #4CAF50, #45a049);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin: 1rem 0;
        font-weight: bold;
    }
    
    .error-message {
        background: linear-gradient(90deg, #f44336, #da190b);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin: 1rem 0;
        font-weight: bold;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 60px;
        padding: 0 2rem;
        font-size: 1.1rem;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # App header
    st.markdown('<h1 class="main-header">� Killer Bug Predictor Pro</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">AI-Powered Website Analysis & Bug Detection</p>', unsafe_allow_html=True)
    
    # Create columns for centering
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Authentication tabs
        login_tab, signup_tab, reset_tab = st.tabs(["🔑 Login", "👤 Sign Up", "🔒 Reset Password"])
        
        with login_tab:
            st.markdown('<div class="form-header">Welcome Back!</div>', unsafe_allow_html=True)
            
            with st.form("login_form", clear_on_submit=True):
                email = st.text_input("📧 Email Address", placeholder="Enter your email")
                password = st.text_input("🔐 Password", type="password", placeholder="Enter your password")
                
                col_login1, col_login2 = st.columns([1, 1])
                with col_login1:
                    login_submitted = st.form_submit_button("🚀 Sign In", use_container_width=True)
                with col_login2:
                    remember_me = st.checkbox("Remember me")
                
                if login_submitted:
                    if email and password:
                        with st.spinner("Signing you in..."):
                            success, message = auth.sign_in(email, password)
                            
                        if success:
                            st.markdown(f'<div class="success-message">✅ {message}</div>', unsafe_allow_html=True)
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-message">⚠️ Please fill in all fields</div>', unsafe_allow_html=True)
        
        with signup_tab:
            st.markdown('<div class="form-header">Create Your Account</div>', unsafe_allow_html=True)
            
            with st.form("signup_form", clear_on_submit=True):
                new_name = st.text_input("👤 Full Name", placeholder="Enter your full name")
                new_email = st.text_input("📧 Email Address", placeholder="Enter your email")
                new_password = st.text_input("🔐 Password", type="password", placeholder="Create a password (min 6 chars)")
                confirm_password = st.text_input("🔐 Confirm Password", type="password", placeholder="Confirm your password")
                
                terms_agreed = st.checkbox("I agree to the Terms of Service and Privacy Policy")
                signup_submitted = st.form_submit_button("🎉 Create Account", use_container_width=True)
                
                if signup_submitted:
                    if new_name and new_email and new_password and confirm_password:
                        if new_password != confirm_password:
                            st.markdown('<div class="error-message">❌ Passwords do not match</div>', unsafe_allow_html=True)
                        elif len(new_password) < 6:
                            st.markdown('<div class="error-message">❌ Password must be at least 6 characters</div>', unsafe_allow_html=True)
                        elif not terms_agreed:
                            st.markdown('<div class="error-message">❌ Please agree to the terms and conditions</div>', unsafe_allow_html=True)
                        else:
                            with st.spinner("Creating your account..."):
                                success, message = auth.sign_up(new_email, new_password, new_name)
                            
                            if success:
                                st.markdown(f'<div class="success-message">✅ {message}</div>', unsafe_allow_html=True)
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-message">⚠️ Please fill in all fields</div>', unsafe_allow_html=True)
        
        with reset_tab:
            st.markdown('<div class="form-header">Reset Password</div>', unsafe_allow_html=True)
            st.markdown("Enter your email address and we'll send you a link to reset your password.")
            
            with st.form("reset_form", clear_on_submit=True):
                reset_email = st.text_input("📧 Email Address", placeholder="Enter your email address")
                reset_submitted = st.form_submit_button("📤 Send Reset Link", use_container_width=True)
                
                if reset_submitted:
                    if reset_email:
                        with st.spinner("Sending reset email..."):
                            success, message = auth.reset_password(reset_email)
                        
                        if success:
                            st.markdown(f'<div class="success-message">✅ {message}</div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="error-message">⚠️ Please enter your email address</div>', unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 1rem;">
        <p>🔒 Your data is secure and encrypted • 🌟 Join thousands of users already using Killer Bug Predictor Pro</p>
    </div>
    """, unsafe_allow_html=True)
    
    return False  # Not authenticated yet


def show_user_profile(auth, user_info):
    """Display user profile in sidebar"""
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 User Profile")
        st.markdown(f"**Name:** {user_info['name']}")
        st.markdown(f"**Email:** {user_info['email']}")
        
        if st.button("🚪 Logout", use_container_width=True):
            auth.sign_out()
            st.success("Logged out successfully!")
            time.sleep(1)
            st.rerun()
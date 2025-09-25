"""
Simple Login Page with      
           #    # Simple header
            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")
        else:💀 Killer Bug Predictor")
    st.write("Professional Website Security Analysis")mple header
            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")
        else:💀 Killer Bug Predictor")
    st.write("Professional Website Security Analysis")imple header
            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")"💀 Killer Bug Predictor")
    st.write("Professional Website Security Analysis")Simple header            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")
        else:
            st.error("Google OAuth not available. Please install google-auth-oauthlib")"💀 Killer Bug Predictor")
    st.write("Professional Website Security Analysis")
    
    # Create columns for centeringimple header
    st.title("💀 Killer Bug Predictor")
    st.write("Professional Website Security Analysis")l Google Au            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")
        else:
            st.error("Google OAuth not available. Installing required libraries...")
            st.code("pip install google-auth-oauthlib", language="bash")r Firebase
"""

import streamlit as st
from firebase_auth import initialize_firebase_auth
import time

# Import Google OAuth functionality
try:
    from google_oauth import show_google_login_button
    GOOGLE_OAUTH_AVAILABLE = True
except ImportError:
    GOOGLE_OAUTH_AVAILABLE = False

def show_login_page():
    """Display the login/signup page with Google authentication"""
    
    # Initialize Firebase
    auth = initialize_firebase_auth()
    if not auth:
        return False
    
    # Simple header
    st.title("�️killer Website Bug Predictor")
    st.write("Professional Website Security Analysis")
    
    # Create columns for centering
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Real Google Authentication with your Firebase credentials
        st.markdown("### 🚀 Sign In")
        
        # Show real Google authentication
        if GOOGLE_OAUTH_AVAILABLE:
            try:
                google_login_shown = show_google_login_button()
                
                if google_login_shown:
                    st.markdown('<p style="color: #999; margin: 1rem 0; text-align: center;">━━━━━━ OR ━━━━━━</p>', unsafe_allow_html=True)
                
            except Exception as e:
                st.error(f"Google OAuth error: {str(e)}")
                st.info("Using email login instead.")
            
        else:
            st.warning("Google OAuth library not available. Please install: `pip install google-auth-oauthlib`")
        
        # Authentication tabs
        login_tab, signup_tab = st.tabs(["🔑 Email Login", "👤 Sign Up"])
        
        with login_tab:
            st.markdown("### Email Login")
            
            with st.form("login_form"):
                email = st.text_input("📧 Email Address", placeholder="Enter your email")
                password = st.text_input("🔐 Password", type="password", placeholder="Enter your password")
                login_submitted = st.form_submit_button("🚀 Sign In", use_container_width=True)
                
                if login_submitted:
                    if email and password:
                        with st.spinner("Signing you in..."):
                            success, message = auth.sign_in(email, password)
                            
                        if success:
                            st.success(f"✅ {message}")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.error("⚠️ Please fill in all fields")
        
        with signup_tab:
            st.markdown("### Create Account")
            
            with st.form("signup_form"):
                new_name = st.text_input("👤 Full Name", placeholder="Enter your full name")
                new_email = st.text_input("📧 Email Address", placeholder="Enter your email")
                new_password = st.text_input("🔐 Password", type="password", placeholder="Create password (6+ chars)")
                signup_submitted = st.form_submit_button("🎉 Create Account", use_container_width=True)
                
                if signup_submitted:
                    if new_name and new_email and new_password:
                        if len(new_password) < 6:
                            st.error("⚠️ Password must be at least 6 characters long")
                        else:
                            with st.spinner("Creating your account..."):
                                success, message = auth.sign_up(new_email, new_password, new_name)
                            
                            if success:
                                st.success(f"✅ {message}")
                                st.info("Please check your email to verify your account.")
                            else:
                                st.error(f"❌ {message}")
                    else:
                        st.error("⚠️ Please fill in all fields")

def show_user_profile(auth, user_info):
    """Display user profile in sidebar"""
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 User Profile")
        st.markdown(f"**Name:** {user_info.get('name', 'User')}")
        st.markdown(f"**Email:** {user_info.get('email', 'N/A')}")
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            auth.sign_out()
            st.rerun()

# Additional Google Authentication Setup Instructions
def show_google_setup_info():
    """Show information about setting up Google authentication"""
    st.info("""
    **🚀 Google Authentication Ready**
    
    Your Google Sign-In is configured and ready to use.
    Simply click the Google Sign-In button above to authenticate.
    """)
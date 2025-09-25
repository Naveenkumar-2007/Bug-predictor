import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from bug_predictor import analyze_website

# Try Firebase first, fallback to simple auth
try:
    from firebase_auth import initialize_firebase_auth
    from login_page import show_login_page, show_user_profile
    USE_FIREBASE = True
except Exception as e:
    USE_FIREBASE = False
    st.error(f"Firebase not available, using simple auth: {e}")

# Import simple auth regardless (needed for fallback)
try:
    from simple_auth import initialize_simple_auth
except ImportError:
    st.error("Simple auth module not found. Please check your setup.")
    st.stop()

# --- Streamlit UI ---
st.set_page_config(page_title="Killer Bug Predictor", layout="wide")

# Initialize Auth
if 'auth_system' not in st.session_state:
    if USE_FIREBASE:
        st.session_state.auth_system = initialize_firebase_auth()
        if not st.session_state.auth_system:
            # Firebase failed, fallback to simple auth
            st.session_state.auth_system = initialize_simple_auth()
            USE_FIREBASE = False
    else:
        st.session_state.auth_system = initialize_simple_auth()

auth = st.session_state.auth_system

# Check authentication status
if not auth or not auth.is_authenticated():
    # Show login page
    if USE_FIREBASE:
        show_login_page()
    else:
        # Simple login page
        st.markdown('<h1 style="text-align: center; color: #1f77b4;">💀 Killer Bug Predictor</h1>', unsafe_allow_html=True)
        st.markdown('<p style="text-align: center; color: #666; font-size: 1.2rem;">AI-Powered Website Analysis & Bug Detection</p>', unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            login_tab, signup_tab = st.tabs(["🔑 Login", "👤 Sign Up"])
            
            with login_tab:
                st.markdown("### Welcome Back!")
                with st.form("login_form"):
                    email = st.text_input("📧 Email", placeholder="Enter your email")
                    password = st.text_input("🔐 Password", type="password", placeholder="Enter your password")
                    login_clicked = st.form_submit_button("🚀 Sign In", use_container_width=True)
                    
                    if login_clicked and email and password:
                        success, message = auth.sign_in(email, password)
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
            
            with signup_tab:
                st.markdown("### Create Account")
                with st.form("signup_form"):
                    new_name = st.text_input("👤 Name", placeholder="Enter your name")
                    new_email = st.text_input("📧 Email", placeholder="Enter your email")
                    new_password = st.text_input("🔐 Password", type="password", placeholder="Create password (6+ chars)")
                    signup_clicked = st.form_submit_button("🎉 Create Account", use_container_width=True)
                    
                    if signup_clicked and new_name and new_email and new_password:
                        success, message = auth.sign_up(new_email, new_password, new_name)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
    st.stop()

# User is authenticated - show main app
user_info = auth.get_current_user()
if USE_FIREBASE:
    show_user_profile(auth, user_info)
else:
    # Simple user profile
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 User Profile")
        st.markdown(f"**Name:** {user_info['name']}")
        st.markdown(f"**Email:** {user_info['email']}")
        if st.button("🚪 Logout", use_container_width=True):
            auth.sign_out()
            st.rerun()

# Simple welcome message
st.title(f"� Welcome back, {user_info['name']}!")
st.write("🎯 **Killer Bug Predictor** - Your personalized dashboard")
st.write("Enter a website URL and get real-time bug analysis with ML + heuristics.")

# Input box
url = st.text_input("Enter Website URL", placeholder="https://example.com")

# Auto-refresh option
refresh = st.checkbox("Auto-refresh every 60s")

if st.button("Analyze Website") or refresh:
    # Enhanced URL validation
    if not url.strip():
        st.error("❌ Please enter a website URL")
        st.stop()
    
    # Check for proper URL format
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            st.error("❌ Please enter a valid URL format (e.g., https://google.com)")
            st.stop()
        
        if parsed.scheme not in ['http', 'https']:
            st.error("❌ URL must start with http:// or https://")
            st.stop()
            
        # Check for incomplete URLs like "https://.."
        if parsed.netloc in ['.', '..', '...'] or len(parsed.netloc.strip('.')) < 3:
            st.error("❌ Please enter a complete website URL (e.g., https://google.com)")
            st.stop()
            
    except Exception:
        st.error("❌ Invalid URL format. Please enter a correct URL (e.g., https://google.com)")
        st.stop()
    
    with st.spinner("🔍 Analyzing website security..."):
        results = analyze_website(url)

    # Convert results to DataFrame
    df = pd.DataFrame(results, columns=["Category", "Message", "Severity"])
    
    # Check for analysis errors first
    error_messages = df[df["Severity"] == "Error"]
    if len(error_messages) > 0:
        st.error(f"❌ {error_messages.iloc[0]['Message']}")
        st.info("💡 **Tip:** Make sure the URL is correct and the website is accessible.")
        st.stop()
    
    # Check if there are any actual security vulnerabilities (exclude "Error", "Clean", "Safe")
    actual_bugs = df[~df["Severity"].isin(["Error", "Clean", "Safe", "Info"])]

    # --- Color severity ---
    def highlight_severity(val):
        colors = {
            "High": "background-color: #ff4d4d; color:white",
            "Medium": "background-color: #ffa64d; color:black",
            "Low": "background-color: #ffff66; color:black",
            "Safe": "background-color: #66ff66; color:black",
            "Critical": "background-color: #cc0000; color:white"
        }
        return colors.get(val, "")

    st.subheader("🔎 Bug Report")
    
    # Show results based on what was found
    if len(actual_bugs) == 0:
        st.success("✅ No security vulnerabilities detected!")
        st.info("This website appears to be secure based on our analysis.")
        # Don't show any charts or health analysis for clean websites
    else:
        st.dataframe(actual_bugs.style.map(highlight_severity, subset=["Severity"]))
        
        # --- CSV Export (only if bugs found) ---
        csv = actual_bugs.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Report (CSV)", csv, "bug_report.csv", "text/csv")

        # --- Enhanced Severity Chart (only show if bugs found) ---
        if len(actual_bugs) > 0:
            severity_counts = actual_bugs["Severity"].value_counts()
            st.subheader("📊 Bug Severity Distribution")
            
            # Create two columns for better layout
            col1, col2 = st.columns([2, 1])
            
            with col1:
                # Enhanced Pie Chart
                fig, ax = plt.subplots(figsize=(8, 6))
                
                # Define colors for each severity level
                severity_colors = {
                    "Critical": "#8B0000",  # Dark Red
                    "High": "#FF4444",      # Red
                    "Medium": "#FF8C00",    # Orange
                    "Low": "#FFD700",       # Gold
                    "Safe": "#32CD32"       # Green
                }
                
                colors = [severity_colors.get(sev, "#808080") for sev in severity_counts.index]
                
                # Create the pie chart with better styling
                wedges, texts, autotexts = ax.pie(
                    severity_counts.values,
                    labels=severity_counts.index,
                    colors=colors,
                    autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100*severity_counts.sum())} bugs)',
                    startangle=90,
                    explode=[0.05 if sev == "High" else 0 for sev in severity_counts.index],  # Explode high severity
                    shadow=True,
                    textprops={'fontsize': 10, 'weight': 'bold'}
                )
                
                # Enhance text appearance
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_weight('bold')
                    
                ax.set_title("Bug Severity Breakdown", fontsize=14, fontweight='bold', pad=20)
                plt.tight_layout()
                st.pyplot(fig)
            
            with col2:
                # Severity Summary Stats
                st.markdown("### 📋 Summary")
                total_bugs = len(actual_bugs)
                st.metric("Total Issues Found", total_bugs)
                
                for severity in ["Critical", "High", "Medium", "Low"]:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        percentage = (count / total_bugs) * 100
                        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                        st.metric(f"{emoji} {severity}", f"{count} ({percentage:.1f}%)")
            
            # --- Bar Chart Alternative ---
            st.markdown("### 📊 Detailed Breakdown")
            fig, ax = plt.subplots(figsize=(10, 6))
            
            bars = ax.bar(severity_counts.index, severity_counts.values, 
                          color=[severity_colors.get(sev, "#808080") for sev in severity_counts.index],
                          edgecolor='black', linewidth=1, alpha=0.8)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{int(height)}', ha='center', va='bottom', fontweight='bold')
            
            ax.set_xlabel('Severity Level', fontsize=12, fontweight='bold')
            ax.set_ylabel('Number of Issues', fontsize=12, fontweight='bold')
            ax.set_title('Bug Count by Severity Level', fontsize=14, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='y')
            plt.xticks(rotation=45)
            plt.tight_layout()
            st.pyplot(fig)

            # --- Enhanced Health Score Display ---
            score = 100
            penalty = {"High": 20, "Medium": 10, "Low": 5, "Critical": 30}
            for _, row in actual_bugs.iterrows():
                score -= penalty.get(row["Severity"], 0)
            score = max(score, 0)
            
            # Create a more visual health score display
            st.subheader("💡 Website Health Analysis")
            
            # Health score with gauge-like visualization
            col1, col2, col3 = st.columns([1, 2, 1])
            
            with col1:
                # Health score metric
                score_color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🟠" if score >= 40 else "🔴"
                st.metric("Health Score", f"{score_color} {score}/100")
                
                # Score interpretation
                if score >= 80:
                    st.success("🎉 Excellent! Your website is in great shape!")
                elif score >= 60:
                    st.info("👍 Good! Minor improvements needed.")
                elif score >= 40:
                    st.warning("⚠️ Fair. Several issues need attention.")
                else:
                    st.error("🚨 Poor. Critical issues require immediate action!")
            
            with col2:
                # Create a visual health gauge
                fig, ax = plt.subplots(figsize=(8, 4), subplot_kw=dict(projection='polar'))
                
                # Create gauge
                theta = np.linspace(0, np.pi, 100)
                
                # Background sectors
                ax.fill_between(theta[0:25], 0, 1, alpha=0.3, color='red', label='Poor (0-40)')
                ax.fill_between(theta[25:50], 0, 1, alpha=0.3, color='orange', label='Fair (40-60)')
                ax.fill_between(theta[50:75], 0, 1, alpha=0.3, color='gold', label='Good (60-80)')
                ax.fill_between(theta[75:100], 0, 1, alpha=0.3, color='green', label='Excellent (80-100)')
                
                # Score pointer
                score_angle = np.pi * (score / 100)
                ax.plot([score_angle, score_angle], [0, 0.8], color='black', linewidth=4)
                ax.plot(score_angle, 0.8, 'ko', markersize=8)
                
                ax.set_ylim(0, 1)
                ax.set_theta_zero_location('W')
                ax.set_theta_direction(1)
                ax.set_thetagrids([0, 45, 90, 135, 180], ['100', '75', '50', '25', '0'])
                ax.set_title(f'Health Score: {score}/100', pad=20, fontsize=14, fontweight='bold')
                ax.set_rticks([])  # Remove radial ticks
                
                plt.tight_layout()
                st.pyplot(fig)
            
            with col3:
                # Score breakdown
                st.markdown("#### 📊 Score Impact")
                total_penalty = 100 - score
                if total_penalty > 0:
                    critical_penalty = (actual_bugs["Severity"] == "Critical").sum() * 30
                    high_penalty = (actual_bugs["Severity"] == "High").sum() * 20
                    medium_penalty = (actual_bugs["Severity"] == "Medium").sum() * 10
                    low_penalty = (actual_bugs["Severity"] == "Low").sum() * 5
                    
                    if critical_penalty > 0:
                        st.write(f"🔴 Critical: -{critical_penalty} pts")
                    if high_penalty > 0:
                        st.write(f"🔴 High: -{high_penalty} pts")
                    if medium_penalty > 0:
                        st.write(f"🟠 Medium: -{medium_penalty} pts")
                    if low_penalty > 0:
                        st.write(f"🟡 Low: -{low_penalty} pts")
                    st.write(f"**Total: -{total_penalty} pts**")
                else:
                    st.write("✅ No penalties!")

            # --- Bug Category Breakdown ---
            st.subheader("🔍 Bug Categories Analysis")
            
            category_counts = actual_bugs["Category"].value_counts()
            
            # Create columns for category visualization
            cat_col1, cat_col2 = st.columns([2, 1])
            
            with cat_col1:
                # Horizontal bar chart for categories
                fig, ax = plt.subplots(figsize=(10, 6))
                
                category_colors = {
                    "🚨 XSS VULNERABILITY": "#dc3545",
                    "💉 SQL INJECTION": "#8B0000", 
                    "🛡️ CSRF VULNERABILITY": "#6f42c1",
                    "🎯 IDOR VULNERABILITY": "#20c997",
                    "🌐 SSRF VULNERABILITY": "#6c757d",
                    "📁 LFI/RFI VULNERABILITY": "#0d6efd",
                    "🖼️ CLICKJACKING VULNERABILITY": "#ffc107",
                    "📤 FILE UPLOAD VULNERABILITY": "#e83e8c",
                    "⚡ OS COMMAND INJECTION": "#495057",
                    "🔐 CRYPTOGRAPHY FAILURE": "#343a40",
                    "Security": "#dc3545",
                    "Performance": "#fd7e14", 
                    "Accessibility": "#6f42c1",
                    "SEO": "#20c997",
                    "Code Quality": "#6c757d",
                    "Link": "#0d6efd",
                    "Form": "#ffc107",
                    "Mobile": "#e83e8c"
                }
                
                colors = [category_colors.get(cat, "#6c757d") for cat in category_counts.index]
                
                bars = ax.barh(category_counts.index, category_counts.values, color=colors, alpha=0.8)
                
                # Add value labels
                for bar in bars:
                    width = bar.get_width()
                    ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                            f'{int(width)}', ha='left', va='center', fontweight='bold')
                
                ax.set_xlabel('Number of Issues', fontsize=12, fontweight='bold')
                ax.set_title('Issues by Category', fontsize=14, fontweight='bold')
                ax.grid(True, alpha=0.3, axis='x')
                
                plt.tight_layout()
                st.pyplot(fig)
            
            with cat_col2:
                # Category summary with emojis
                st.markdown("#### 📋 Category Summary")
                
                category_emojis = {
                    "🚨 XSS VULNERABILITY": "🚨",
                    "💉 SQL INJECTION": "💉", 
                    "🛡️ CSRF VULNERABILITY": "🛡️",
                    "🎯 IDOR VULNERABILITY": "🎯",
                    "🌐 SSRF VULNERABILITY": "🌐",
                    "📁 LFI/RFI VULNERABILITY": "📁",
                    "🖼️ CLICKJACKING VULNERABILITY": "🖼️",
                    "📤 FILE UPLOAD VULNERABILITY": "📤",
                    "⚡ OS COMMAND INJECTION": "⚡",
                    "🔐 CRYPTOGRAPHY FAILURE": "🔐",
                    "Security": "🔒",
                    "Performance": "⚡",
                    "Accessibility": "♿",
                    "SEO": "📈", 
                    "Code Quality": "🔧",
                    "Link": "🔗"
                }
                
                for category, count in category_counts.items():
                    emoji = category_emojis.get(category, "⚪")
                    percentage = (count / len(actual_bugs)) * 100
                    st.write(f"{emoji} **{category}**: {count} ({percentage:.1f}%)")
            
            # Show critical/high issues only if they exist
            critical_issues = actual_bugs[actual_bugs["Severity"] == "Critical"]
            high_severity = actual_bugs[actual_bugs["Severity"] == "High"]
            
            if len(critical_issues) > 0:
                st.error("🚨 **Critical Security Issues:**")
                for _, bug in critical_issues.head(3).iterrows():
                    st.write(f"• **{bug['Category']}**: {bug['Message']}")
            
            if len(high_severity) > 0:
                st.warning("⚠️ **High-Priority Issues:**")
                for _, bug in high_severity.head(2).iterrows():
                    st.write(f"• **{bug['Category']}**: {bug['Message']}")

    # --- Analysis Complete ---
    st.subheader("📈 Analysis Summary")
    
    # Show analysis timestamp
    import datetime
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.caption(f"Last analyzed: {current_time}")
    
    # Final summary based on findings (only for bug cases)
    if len(actual_bugs) > 0:
        total_issues = len(actual_bugs)
        critical_count = len(critical_issues) if 'critical_issues' in locals() else 0
        high_count = len(high_severity) if 'high_severity' in locals() else 0
        
        if critical_count > 0:
            st.error(f"🚨 **{total_issues} security issues detected** - {critical_count} critical, requires immediate attention!")
        elif high_count > 0:
            st.warning(f"⚠️ **{total_issues} security issues detected** - {high_count} high priority, should be addressed soon.")
        else:
            st.info(f"ℹ️ **{total_issues} minor issues detected** - Low priority improvements recommended.")

# --- PDF Generation ---
def generate_pdf_report(df, url):
    """Generate a PDF report of the bug analysis"""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Website Security Analysis Report")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"URL: {url}")
    c.drawString(50, height - 100, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Report content
    y_position = height - 140
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "Findings Summary:")
    
    y_position -= 30
    c.setFont("Helvetica", 10)
    
    for index, row in df.iterrows():
        if y_position < 100:  # New page if needed
            c.showPage()
            y_position = height - 50
        
        severity_color = "RED" if row["Severity"] in ["Critical", "High"] else "ORANGE" if row["Severity"] == "Medium" else "BLACK"
        c.drawString(50, y_position, f"• {row['Category']}: {row['Message']} [{row['Severity']}]")
        y_position -= 20
    
    c.save()
    buffer.seek(0)
    return buffer

# Auto-refresh functionality
if refresh:
    import time
    time.sleep(60)  # Wait 60 seconds
    st.rerun()
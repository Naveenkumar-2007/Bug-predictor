import requests
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
import streamlit as st
import time
import os
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import ssl
import socket

class EnhancedBugPredictor:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.load_and_train_model()
    
    def load_and_train_model(self):
        """Load your real dataset and train ML models using ALL available features"""
        try:
            # Load the real USA gov sites dataset
            if os.path.exists('usa_gov_sites_dataset.csv'):
                df = pd.read_csv('usa_gov_sites_dataset.csv')
                print(f"📊 Loaded real dataset with {len(df)} websites and {len(df.columns)} features")
            else:
                raise FileNotFoundError("Real dataset not found")
            
            # Use ALL numeric/boolean columns as features (excluding target)
            # Target: domain_enforces_https (main security indicator)
            target_col = 'domain_enforces_https'
            
            if target_col not in df.columns:
                raise ValueError(f"Target column '{target_col}' not found")
            
            # Select ALL numeric and boolean columns as features
            numeric_cols = df.select_dtypes(include=['bool', 'int64', 'float64', 'int32', 'float32']).columns.tolist()
            
            # Remove target column from features
            if target_col in numeric_cols:
                numeric_cols.remove(target_col)
            
            self.feature_columns = numeric_cols
            
            # Prepare features (use ALL available columns)
            X = df[self.feature_columns].fillna(0)  # Fill missing values
            y = df[target_col].fillna(0)  # Target: HTTPS enforcement
            
            print(f"🎯 Training with {len(self.feature_columns)} features from real dataset:")
            print(f"   Features include: {', '.join(self.feature_columns[:10])}...")
            
            # Scale features for better performance
            X_scaled = self.scaler.fit_transform(X)
            
            # Train-test split
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
            
            # Train advanced model with your real data
            self.model = GradientBoostingClassifier(
                n_estimators=200, 
                learning_rate=0.1, 
                max_depth=6,
                random_state=42
            )
            self.model.fit(X_train, y_train)
            
            # Evaluate model
            train_score = self.model.score(X_train, y_train)
            test_score = self.model.score(X_test, y_test)
            
            print(f"✅ ML model trained successfully!")
            print(f"   Training accuracy: {train_score:.3f}")
            print(f"   Testing accuracy: {test_score:.3f}")
            print(f"   Using {len(self.feature_columns)} real dataset features")
            
        except Exception as e:
            print(f"⚠️ ML model training failed: {e}")
            print("   Falling back to heuristic analysis only")
            self.model = None
    
    def extract_features_from_url(self, url, content=None, api_results=None):
        """Extract features that match your real dataset columns"""
        features = {}
        parsed = urlparse(url)
        domain = parsed.netloc
        
        try:
            # Basic domain features (matching your dataset)
            features['domain_canonically_https'] = 1 if url.startswith('https://') else 0
            features['domain_enforces_https'] = 1 if url.startswith('https://') else 0  # We'll predict this
            features['domain_https'] = 1 if url.startswith('https://') else 0
            features['domain_up'] = 1  # Assume it's up if we can analyze it
            features['domain_responds'] = 1
            
            # URL structure analysis
            features['domain_canonically_www'] = 1 if domain.startswith('www.') else 0
            features['domain_www'] = 1 if 'www' in domain else 0
            
            # Content analysis (if available)
            if content:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Security headers simulation
                features['hsts_enabled'] = 1 if 'strict-transport-security' in str(content).lower() else 0
                features['content_proper_404s'] = 1 if '404' not in content else 0
                features['content_security_txt'] = 1 if 'security.txt' in content.lower() else 0
                
                # Technology detection
                features['sniffer_javascript'] = 1 if soup.find('script') else 0
                features['sniffer_analytics'] = 1 if any(keyword in content.lower() for keyword in ['analytics', 'gtag', 'ga(']) else 0
                
                # CMS and framework detection
                features['wappalyzer_cms'] = 1 if any(cms in content.lower() for cms in ['wordpress', 'drupal', 'joomla']) else 0
                features['wappalyzer_javascript_libraries'] = 1 if any(lib in content.lower() for lib in ['jquery', 'angular', 'react']) else 0
                features['wappalyzer_web_frameworks'] = 1 if soup.find('meta', {'name': 'generator'}) else 0
                
            # API integration results
            if api_results:
                # Google Safe Browsing
                features['api_safe_browsing_threat'] = 1 if api_results.get('gsb_status') == 'threat' else 0
                
                # VirusTotal
                vt = api_results.get('virustotal', {})
                features['api_virustotal_malicious'] = 1 if vt.get('malicious', 0) > 0 else 0
                features['api_virustotal_suspicious'] = 1 if vt.get('suspicious', 0) > 0 else 0
                
                # SSL Labs
                ssl = api_results.get('ssl_labs', {})
                ssl_grade = ssl.get('grade', 'F')
                features['api_ssl_grade_good'] = 1 if ssl_grade in ['A+', 'A', 'A-'] else 0
                features['api_ssl_grade_bad'] = 1 if ssl_grade in ['F', 'T'] else 0
                
                # Mozilla Observatory
                obs = api_results.get('mozilla_obs', {})
                obs_score = obs.get('score', 0)
                features['api_mozilla_score_good'] = 1 if obs_score >= 70 else 0
                features['api_mozilla_score_bad'] = 1 if obs_score < 30 else 0
            
            # Fill missing features with 0 (matching your dataset structure)
            for col in self.feature_columns:
                if col not in features:
                    features[col] = 0
                    
            return features
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            # Return zeros for all features if extraction fails
            return {col: 0 for col in self.feature_columns}
    
    def predict_security_score(self, url, content=None, api_results=None):
        """Predict security score using your real dataset model + API results"""
        if not self.model:
            return {"score": 50, "prediction": "Unknown", "confidence": 0.5}
        
        try:
            # Extract features
            features = self.extract_features_from_url(url, content, api_results)
            
            # Create feature vector matching training data
            feature_vector = []
            for col in self.feature_columns:
                feature_vector.append(features.get(col, 0))
            
            feature_vector = np.array([feature_vector])
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Predict security (HTTPS enforcement as proxy for overall security)
            prediction_proba = self.model.predict_proba(feature_vector_scaled)[0]
            prediction = self.model.predict(feature_vector_scaled)[0]
            confidence = max(prediction_proba)
            
            # Calculate composite security score (0-100)
            base_score = confidence * 100
            
            # Adjust score based on API results
            if api_results:
                # Penalize for threats
                if api_results.get('gsb_status') == 'threat':
                    base_score -= 40
                
                vt = api_results.get('virustotal', {})
                if vt.get('malicious', 0) > 0:
                    base_score -= 30
                elif vt.get('suspicious', 0) > 0:
                    base_score -= 15
                
                # Reward for good SSL
                ssl = api_results.get('ssl_labs', {})
                if ssl.get('grade') in ['A+', 'A']:
                    base_score += 10
                elif ssl.get('grade') in ['F', 'T']:
                    base_score -= 20
                
                # Mozilla Observatory adjustment
                obs = api_results.get('mozilla_obs', {})
                obs_score = obs.get('score', 50)
                base_score += (obs_score - 50) * 0.3  # Scale observatory score
            
            # Ensure score is between 0-100
            final_score = max(0, min(100, base_score))
            
            # Determine risk level
            if final_score >= 80:
                risk_level = "Low Risk"
            elif final_score >= 60:
                risk_level = "Medium Risk"
            elif final_score >= 40:
                risk_level = "High Risk"
            else:
                risk_level = "Critical Risk"
            
            return {
                "score": round(final_score, 1),
                "prediction": risk_level,
                "confidence": round(confidence, 3),
                "ml_prediction": bool(prediction),
                "api_enhanced": bool(api_results)
            }
            
        except Exception as e:
            print(f"ML prediction error: {e}")
            return {"score": 50, "prediction": "Analysis Error", "confidence": 0.0}

# API Integration Functions (unchanged but optimized)
def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    try:
        api_key = st.secrets.get("GSB_KEY") if hasattr(st, 'secrets') else os.getenv("GSB_KEY", "AIzaSyC49LBbiJzfqPr2qxFjr7b7jRFJiRTYxCQ")
        if not api_key:
            return {"status": "error", "message": "API key not configured"}
        
        body = {
            "client": {"clientId": "killer-bug-predictor", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("matches"):
                return {"status": "threat", "details": data["matches"]}
            return {"status": "safe"}
        else:
            return {"status": "error", "message": f"API error: {response.status_code}"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_virustotal(url):
    """Check URL reputation with VirusTotal API"""
    try:
        vt_key = st.secrets.get("VT_KEY") if hasattr(st, 'secrets') else os.getenv("VT_KEY", "7ccf1c892080dbd7cb2e6ddf65865f8c465d44053ccaffe9eb3c9a03ba94e9cf")
        if not vt_key:
            return {"status": "error", "message": "API key not configured"}
        
        headers = {"x-apikey": vt_key}
        
        # Submit URL for analysis
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            
            # Wait and get results
            time.sleep(2)
            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            
            if result_response.status_code == 200:
                result = result_response.json()
                stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                
                return {
                    "status": "completed",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("clean", 0),
                    "total_scans": sum(stats.values()) if stats else 0
                }
        
        return {"status": "pending"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_ssl_labs(domain):
    """Check SSL configuration with SSL Labs API"""
    try:
        response = requests.get(
            f"https://api.ssllabs.com/api/v3/analyze?host={domain}&publish=off",
            timeout=20
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("status") == "READY" and data.get("endpoints"):
                endpoint = data["endpoints"][0]
                return {
                    "status": "completed",
                    "grade": endpoint.get("grade", "Unknown"),
                    "ip": endpoint.get("ipAddress", "Unknown"),
                    "has_warnings": bool(endpoint.get("hasWarnings", False))
                }
            else:
                return {"status": "pending", "message": f"Status: {data.get('status', 'Unknown')}"}
        
        return {"status": "error", "message": "API request failed"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_mozilla_observatory(domain):
    """Check security headers with Mozilla HTTP Observatory"""
    try:
        # Trigger fresh scan
        response = requests.post(
            f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}&rescan=true",
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("state") == "FINISHED":
                return {
                    "status": "completed",
                    "score": data.get("score", 0),
                    "grade": data.get("grade", "F"),
                    "tests_passed": data.get("tests_passed", 0),
                    "tests_failed": data.get("tests_failed", 0),
                    "tests_quantity": data.get("tests_quantity", 0)
                }
            else:
                return {"status": "pending", "state": data.get("state")}
        
        return {"status": "error", "message": "API request failed"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Initialize the enhanced predictor with your real data
predictor = EnhancedBugPredictor()

def is_valid_url(url):
    """Validate if the input is a proper URL"""
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc and (parsed.scheme in ['http', 'https']))
    except:
        return False

def analyze_website(url):
    """BUGS ONLY - Only report actual security vulnerabilities detected"""
    
    # Validate URL first
    if not is_valid_url(url):
        return [("❌ Invalid URL", "Please enter a correct URL format (e.g., https://example.com)", "Error")]
    
    bug_report = []
    
    try:
        # Get website content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        domain = urlparse(url).netloc
        
        # === ONLY REPORT ACTUAL SECURITY VULNERABILITIES ===
        
        # 1. Insecure HTTP Protocol
        if not url.startswith("https://"):
            bug_report.append(("🔓 INSECURE PROTOCOL", "Website transmits data over unencrypted HTTP", "Critical"))
        
        # 2. Critical Security Headers Missing
        if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
            bug_report.append(("🛡️ CLICKJACKING VULNERABILITY", "Website can be embedded in malicious frames", "High"))
            
        if 'X-Content-Type-Options' not in response.headers:
            bug_report.append(("🛡️ MIME SNIFFING RISK", "Browser may interpret files as executable code", "Medium"))
        
        # 3. Cookie Security Issues - ONLY if cookies exist and have problems
        if 'Set-Cookie' in response.headers:
            cookie_header = response.headers.get('Set-Cookie', '')
            
            if 'Secure' not in cookie_header and url.startswith('https://'):
                bug_report.append(("🍪 COOKIE VULNERABILITY", "Cookies not marked as Secure - interception risk", "Medium"))
            if 'HttpOnly' not in cookie_header:
                bug_report.append(("🍪 XSS COOKIE RISK", "Cookies accessible via JavaScript - XSS vulnerability", "Medium"))
            if 'SameSite' not in cookie_header:
                bug_report.append(("🍪 CSRF VULNERABILITY", "Cookies vulnerable to cross-site attacks", "Medium"))
        
        # 4. Form Security Vulnerabilities
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            
            # Check for insecure form submission
            if form_action and form_action.startswith('http://') and not form_action.startswith('https://'):
                bug_report.append(("🔓 INSECURE FORM", "Form submits data over unencrypted HTTP", "High"))
            
            # Check for password fields over HTTP - CRITICAL vulnerability
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields and not url.startswith('https://'):
                bug_report.append(("🚨 PASSWORD RISK", "Login credentials transmitted without encryption", "Critical"))
        
        # 5. Mixed Content Vulnerabilities (HTTPS pages loading HTTP resources)
        if url.startswith('https://'):
            mixed_content_count = 0
            
            # Check scripts, images, stylesheets
            for element in soup.find_all(['script', 'img', 'link'], src=True) + soup.find_all('link', href=True):
                resource_url = element.get('src') or element.get('href')
                if resource_url and resource_url.startswith('http://'):
                    mixed_content_count += 1
            
            if mixed_content_count > 0:
                bug_report.append(("⚠️ MIXED CONTENT", f"Loading {mixed_content_count} insecure resources on HTTPS page", "Medium"))
        
        # === RETURN ONLY BUGS FOUND ===
        if not bug_report:
            return [("✅ No Security Issues", "No security vulnerabilities detected", "Clean")]
        
        return bug_report
        
    except requests.exceptions.SSLError:
        return [("🔒 SSL ERROR", "SSL certificate validation failed", "High")]
    except requests.exceptions.ConnectionError:
        return [("🌐 CONNECTION ERROR", "Website unreachable", "Critical")]
    except requests.exceptions.Timeout:
        return [("⏱️ TIMEOUT ERROR", "Website response timeout", "Medium")]
    except Exception as e:
        return [("❌ ANALYSIS ERROR", f"Analysis failed: {str(e)}", "Medium")]
    bug_report = []
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10)
        load_time = time.time() - start_time

        if response.status_code != 200:
            bug_report.append(("Page Error", f"Status code {response.status_code}", "High"))
            return bug_report

        soup = BeautifulSoup(response.text, 'html.parser')

        # --- Performance ---
        if load_time > 3:
            bug_report.append(("Performance", f"Slow load time: {load_time:.2f}s", "Medium"))
        if len(response.content) > 2 * 1024 * 1024:  # >2 MB
            bug_report.append(("Performance", "Large page size (>2 MB)", "Medium"))

        # --- Accessibility ---
        for img in soup.find_all("img"):
            if not img.get("alt"):
                bug_report.append(("Accessibility", "Image missing alt attribute", "Medium"))
        if not soup.find("h1"):
            bug_report.append(("Accessibility", "Missing <h1> heading", "Low"))
        for input_tag in soup.find_all("input"):
            if not soup.find("label", attrs={"for": input_tag.get("id")}):
                bug_report.append(("Accessibility", f"Input without label (id={input_tag.get('id')})", "Low"))
        if not soup.find(attrs={"role": True}):
            bug_report.append(("Accessibility", "No ARIA roles detected", "Low"))

        # --- Links ---
        for a in soup.find_all("a", href=True):
            full_url = urljoin(url, a['href'])
            try:
                r = requests.head(full_url, timeout=5)
                if r.status_code == 404:
                    bug_report.append(("Link", f"Broken link: {full_url}", "High"))
            except:
                bug_report.append(("Link", f"Unreachable link: {full_url}", "Medium"))

        # --- Forms ---
        for form in soup.find_all("form"):
            if not form.find("input", {"type": "submit"}) and not form.find("button"):
                bug_report.append(("Form", "Form without submit button", "Medium"))
            if form.get("action") and form['action'].startswith("http://"):
                bug_report.append(("Security", f"Insecure form action: {form['action']}", "High"))

        # --- Code Quality ---
        if re.search(r'style=', response.text):
            bug_report.append(("Code Quality", "Inline CSS detected", "Low"))
        for tag in ["font", "center", "marquee"]:
            if soup.find(tag):
                bug_report.append(("Code Quality", f"Deprecated tag <{tag}> used", "Low"))

        # --- SEO ---
        title = soup.find("title")
        if not title:
            bug_report.append(("SEO", "Missing <title> tag", "Medium"))
        else:
            if len(title.get_text()) < 10:
                bug_report.append(("SEO", "Title too short", "Low"))
            if len(title.get_text()) > 60:
                bug_report.append(("SEO", "Title too long", "Low"))
        if not soup.find("meta", attrs={"name": "description"}):
            bug_report.append(("SEO", "Missing meta description", "Medium"))
        if not soup.find("meta", attrs={"name": "keywords"}):
            bug_report.append(("SEO", "Missing meta keywords", "Low"))

        # --- Security ---
        if not url.startswith("https://"):
            bug_report.append(("Security", "Website not using HTTPS", "High"))
        if "Set-Cookie" in response.headers:
            cookie = response.headers["Set-Cookie"]
            if "Secure" not in cookie or "HttpOnly" not in cookie:
                bug_report.append(("Security", "Insecure cookie attributes detected", "High"))
        for script in soup.find_all("script", src=True):
            if script["src"].startswith("http://"):
                bug_report.append(("Security", f"Insecure script source: {script['src']}", "High"))

        # --- Mobile Friendly ---
        if not soup.find("meta", attrs={"name": "viewport"}):
            bug_report.append(("Mobile", "Missing viewport meta tag", "Medium"))

        # --- ML text prediction ---
        if MODEL_AVAILABLE:
            page_text = " ".join([p.get_text() for p in soup.find_all("p")])
            if page_text.strip():
                try:
                    # Use a simple heuristic based on text content
                    suspicious_keywords = ['error', 'bug', 'broken', 'failed', 'warning', '404', '500']
                    text_lower = page_text.lower()
                    suspicious_count = sum(1 for keyword in suspicious_keywords if keyword in text_lower)
                    
                    if suspicious_count > 2:
                        bug_report.append(("ML Analysis", "Page content suggests potential issues", "Low"))
                except Exception as e:
                    print(f"ML prediction error: {e}")
        else:
            # Fallback text analysis
            page_text = " ".join([p.get_text() for p in soup.find_all("p")])
            if "error" in page_text.lower() or "broken" in page_text.lower():
                bug_report.append(("Text Analysis", "Error keywords found in content", "Low"))

        if not bug_report:
            bug_report.append(("Info", "No major bugs detected", "Safe"))

        return bug_report

    except Exception as e:
        return [("System", f"Error analyzing website: {str(e)}", "Critical")]

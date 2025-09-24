import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import re
import time
import pandas as pd

# --- Train Simple ML Model for HTTPS prediction ---
try:
    df = pd.read_csv("usa_gov_sites_dataset.csv")  # Use local CSV file
    
    # Select only numeric/boolean columns for the model
    numeric_cols = df.select_dtypes(include=['bool', 'int64', 'float64']).columns.tolist()
    if 'domain_enforces_https' in numeric_cols:
        numeric_cols.remove('domain_enforces_https')
    
    # Prepare features and target
    X = df[numeric_cols].fillna(0)  # Fill NaN values with 0
    y = df['domain_enforces_https']
    
    # Train-test split
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    
    # For text analysis, we'll use a separate vectorizer
    vectorizer = TfidfVectorizer(max_features=100)
    
    print(f"Model trained successfully with {len(numeric_cols)} features")
    MODEL_AVAILABLE = True
    
except Exception as e:
    print(f"Warning: Could not train ML model: {e}")
    MODEL_AVAILABLE = False
    model = None
    vectorizer = TfidfVectorizer()


def analyze_website(url):
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

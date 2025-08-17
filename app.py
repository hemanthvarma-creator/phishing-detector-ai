# ========================= PART 1: Imports, constants, utils =========================
import streamlit as st
import joblib
import re
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from streamlit_lottie import st_lottie
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import os
import json
import time
from typing import Tuple


# Known short URL domains
SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly", "is.gd",
    "adf.ly", "shorte.st", "rebrand.ly", "bl.ink", "cutt.ly", "t.ly", "rb.gy"
}

def load_lottie_file(filepath: str):
    """Load a Lottie animation from a local JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.warning(f"Could not load Lottie file: {e}")
        return None

# ------------------- Model Handling -------------------
def train_and_save_model():
    """Train a simple RandomForest on dummy data and save it."""
    st.info("No model file found. Training a new model with dummy data...")
    X_dummy = pd.DataFrame([[1]*30, [-1]*30, [1, -1]*15])
    y_dummy = np.array([1, -1, -1])  # 1=Legit, -1=Phishy
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_dummy, y_dummy)
    joblib.dump(model, "phishing_model.pkl")
    st.success("New model trained and saved as phishing_model.pkl")
    return model

@st.cache_resource
def load_model():
    """Load phishing detection model, or train a new one if it doesn't exist."""
    if not os.path.exists("phishing_model.pkl"):
        return train_and_save_model()
    return joblib.load("phishing_model.pkl")

# ------------------- URL Utilities -------------------
def ensure_scheme(url: str) -> str:
    if not re.match(r'^https?://', url, flags=re.I):
        return 'http://' + url.strip()
    return url.strip()

def is_shortener_domain(domain: str) -> bool:
    dom = domain.lower()
    return any(dom == s or dom.endswith("." + s) for s in SHORT_URL_DOMAINS)

def expand_short_url_if_needed(url: str) -> Tuple[str, bool]:
    candidate = ensure_scheme(url)
    domain = urlparse(candidate).netloc.replace("www.", "").lower()
    if not is_shortener_domain(domain):
        return candidate, False

    final_url = candidate
    try:
        r = requests.head(candidate, allow_redirects=True, timeout=7)
        if r.url and isinstance(r.url, str):
            final_url = r.url
    except Exception:
        pass

    if final_url == candidate:
        try:
            r = requests.get(candidate, allow_redirects=True, timeout=10, stream=True)
            if r.url and isinstance(r.url, str):
                final_url = r.url
        except Exception:
            pass

    return final_url, (final_url != candidate)

def get_html_content(url: str):
    try:
        url = ensure_scheme(url)
        response = requests.get(url, timeout=8)
        return response.text
    except Exception:
        return None
# ========================= PART 2: Feature extraction =========================
def extract_features(url: str):
    """
    Build 30 features (int: 1/-1) and a detail log.
    Returns: (pd.DataFrame shape (1,30), details_list)
    """
    features = [1]*30
    details = []

    # Ensure scheme up front
    url = ensure_scheme(url)

    # Parse to see domain; expand ONLY for shorteners
    try:
        parsed_pre = urlparse(url)
        domain_pre = parsed_pre.netloc.replace('www.', '')
    except Exception as e:
        details.append(f"❌ **Critical Error:** URL parsing failed before expand ({e})")
        return pd.DataFrame([[-1]*30]), details

    # Expand only if it is a known shortener
    if is_shortener_domain(domain_pre):
        expanded_url, changed = expand_short_url_if_needed(url)
        if changed:
            url = expanded_url
            details.append(f"🔁 Shortened URL expanded to: {url}")

    # Parse URL (final)
    try:
        url = ensure_scheme(url)
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        path = parsed.path
    except Exception as e:
        details.append(f"❌ **Critical Error:** URL parsing failed ({e})")
        return pd.DataFrame([[-1]*30]), details

    # WHOIS
    info = None
    try:
        info = whois.whois(domain)
    except Exception as e:
        details.append(f"🔴 **WHOIS Lookup Failed:** {e}")

    # HTML
    html = get_html_content(url)
    soup = BeautifulSoup(html, 'html.parser') if html else None

    # --------- Core URL features ---------
    # 0: IP URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        features[0] = -1
        details.append("🔴 **IP Address URL:** The link uses an IP address instead of a domain.")

    # 1: URL Length
    if len(url) >= 75:
        features[1] = -1
        details.append("🔴 **Excessively Long URL:** URL length suspiciously long.")
    elif len(url) < 54:
        details.append("✅ **Short URL:** Length appears safe.")

    # 2: Short URL (by length, not shortener)
    features[2] = -1 if len(url) <= 20 else 1

    # 3: '@' symbol
    if "@" in url:
        features[3] = -1
        details.append("🔴 **'@' Symbol Found:** URL contains '@' symbol.")

    # 4: Double Slash position (beyond protocol)
    if url.rfind('//') > 7:
        features[4] = -1
        details.append("🔴 **Double Slash Redirect:** Suspicious '//' found in URL.")

    # 5: Hyphen in domain
    if '-' in domain:
        features[5] = -1
        details.append("🔴 **Hyphen in Domain:** Domain contains a hyphen.")

    # 6: Sub-domains
    dots = domain.count('.')
    if dots >= 3:
        features[6] = -1
        details.append("🔴 **Excessive Sub-domains:** Too many sub-domains.")
    elif dots <= 1:
        details.append("✅ **Simple Domain Structure:** Few subdomains.")

    # 7: HTTPS
    features[7] = 1 if parsed.scheme.lower() == 'https' else -1
    details.append("✅ **Secure Protocol:** HTTPS is used." if features[7] == 1 else "🔴 **Insecure Protocol:** HTTPS not detected.")

    # 8: Domain registration length
    try:
        if info and info.expiration_date and info.creation_date:
            exp = info.expiration_date[0] if isinstance(info.expiration_date, list) else info.expiration_date
            create = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
            reg_len = (exp - create).days
            features[8] = -1 if reg_len <= 365 else 1
            details.append(
                f"🔴 **Short Registration:** Domain registered for only {reg_len} days."
                if reg_len <= 365 else
                f"✅ **Long Registration:** Domain registered for {reg_len} days."
            )
        else:
            raise ValueError("Missing creation or expiration")
    except Exception:
        features[8] = -1
        details.append("🔴 **Domain Registration Info Missing.**")

    # 9–11: simple placeholders you had
    features[9]  = 1
    features[10] = -1 if ':' in domain else 1
    features[11] = 1 if 'https' in domain else -1

    # 12–15: soup-dependent
    if not soup:
        for i in range(12, 15):
            features[i] = -1
        details.append("❌ **HTML Parsing Failed:** Unable to analyze page content.")
    else:
        features[12] = features[13] = features[14] = 1
        details.append("✅ **HTML Content Retrieved:** Page structure successfully parsed.")
    features[15] = 1 if soup else -1

    # 16: mailto
    features[16] = -1 if 'mailto:' in url else 1
    # 17: domain mismatch (simple heuristic)
    features[17] = -1 if domain not in url else 1

    # 18–22: placeholders
    features[18] = features[19] = features[20] = features[21] = features[22] = 1

    # 23: Age of domain
    try:
        if info and info.creation_date:
            create = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
            age = (datetime.now() - create).days
            features[23] = -1 if age < 180 else 1
            details.append(
                f"🔴 **New Domain:** Only {age} days old."
                if age < 180 else
                f"✅ **Established Domain:** Age {age} days."
            )
        else:
            raise ValueError("Missing creation date")
    except Exception:
        features[23] = -1
        details.append("🔴 **Domain Age Info Missing.**")

    # 24: DNS Record present?
    try:
        if info and (info.domain_name or info.creation_date or info.registrar):
            features[24] = 1
            details.append("✅ **DNS Record Found.**")
        else:
            features[24] = -1
            details.append("🔴 **DNS Record Missing or Incomplete.**")
    except Exception as e:
        features[24] = -1
        details.append(f"🔴 **DNS Check Failed:** {e}")

    # 25–29: placeholders
    features[25] = features[26] = features[27] = features[28] = features[29] = 1

    return pd.DataFrame([features]), details
# ========================= PART 3: Main App =========================
def main():
    st.set_page_config(page_title="Phishing Detector", page_icon="🕵️", layout="centered")
    st.title("Phishing Website Detector")
    st.write("AI-powered URL analysis for phishing detection.")
    add_logo("Logo.png", height=60)

    model = load_model()
    lottie_success = load_lottie_file("success.json")
    lottie_alert = load_lottie_file("alert.json")

    # Create a form so Enter submits automatically
    with st.form("phish_form", clear_on_submit=False):
        url_to_check = st.text_input(
            "Enter URL (with or without http/https)", 
            placeholder="www.example.com"
        )
        submit = st.form_submit_button("Analyze")

    if submit:
        if url_to_check.strip() == "":
            st.warning("⚠️ Please enter a URL before submitting.")
        else:
            with st.spinner("Analyzing URL..."):
                features, details = extract_features(url_to_check)
                prediction = model.predict(features)
            time.sleep(0.1)  # Prevent flicker

            st.write("---")
            st.subheader("Verdict:")

            if prediction[0] == -1:
                if lottie_alert:
                    st_lottie(lottie_alert, height=200, key="phishy_anim")
                st.error("🚨 PHISHING SITE DETECTED")
            else:
                if lottie_success:
                    st_lottie(lottie_success, height=200, key="success_anim")
                st.success("✅ SAFE SITE")

            with st.expander("🔬 Detective's Report"):
                for detail in details:
                    st.write(detail)

    def add_logo(logo_path: str, height: int = 60):
        """Read and encode logo to place top-left"""
        with open(logo_path, "rb") as f:
            img_data = f.read()
        encoded = base64.b64encode(img_data).decode()
        st.markdown(
            f"""
            <style>
            .logo-container {{
                position: fixed;
                top: 15px;
                left: 20px;
                z-index: 999;
            }}
            .logo-container img {{
                height: {height}px;
            }}
            </style>
            <div class="logo-container">
                <img src="data:image/png;base64,{encoded}" alt="NetHook Logo">
            </div>
            """,
            unsafe_allow_html=True
        )


            # 📌 Footer inside main()
    st.markdown(
        """
        <style>
        /* Push footer to bottom */
        .stApp {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        .main-content {
            flex: 1 0 auto;
            padding-bottom: 40px; /* Gap before footer */
        }
        .footer {
            flex-shrink: 0;
            text-align: center;
            padding: 20px 0;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Add a spacer before footer
    st.markdown('<div class="main-content"></div>', unsafe_allow_html=True)

        # 📌 Footer styling
    st.markdown(
        """
        <style>
        /* Make app take full height so footer stays at bottom */
        .stApp {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        /* Main content grows, footer stays down */
        .main-content {
            flex: 1 0 auto;
            padding-bottom: 40px; /* gap before footer */
        }
        .footer {
            flex-shrink: 0;
            text-align: center;
            padding: 20px 0;
        }
        .footer-links {
            display: flex;
            justify-content: center; /* center horizontally */
            gap: 100px; /* space between columns */
            flex-wrap: wrap; /* stack on small screens */
        }
        .footer-column {
            text-align: left; /* keep bullets aligned */
        }
        .footer h3 {
            margin-bottom: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Spacer before footer
    st.markdown('<div class="main-content"></div>', unsafe_allow_html=True)

    # Footer container
    with st.container():
        st.markdown("---")  # Divider line

        st.markdown(
            """
            <div class="footer">
                <h3> Quick Links</h3>
                <div class="footer-links">
                    <div class="footer-column">
                        <ul>
                            <li><a href="#">Privacy Policy</a></li>
                            <li><a href="#">Terms of Service</a></li>
                            <li><a href="#">About Us</a></li>
                            <li><a href="#">FAQ</a></li>
                        </ul>
                    </div>
                    <div class="footer-column">
                        <ul>
                            <li><a href="#">Contact / Feedback</a></li>
                            <li><a href="#">Phishing Explained</a></li>
                            <li><a href="#">Blog / Updates</a></li>
                        </ul>
                    </div>
                </div>
                <p>© 2025 NetHook. All rights reserved.</p>
            </div>
            """,
            unsafe_allow_html=True
        )





# -------------------- Run App --------------------
if __name__ == "__main__":
    main()





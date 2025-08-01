import streamlit as st
import sqlite3
from datetime import datetime
import pandas as pd
import re
from textblob import TextBlob
import logging
import csv
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import threading

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set page config as the first Streamlit command
st.set_page_config(page_title="Phishing Prevention Tool", layout="wide")

# Initialize database
def init_db():
    try:
        conn = sqlite3.connect("phishing_protection.db")
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            role TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            email_content TEXT,
            extensions_detected TEXT,
            domains_detected TEXT,
            spelling_errors INTEGER,
            is_phishing INTEGER,
            confidence FLOAT,
            block_status TEXT,
            timestamp TIMESTAMP
        )""")
        # Add block_status column if missing
        c.execute("PRAGMA table_info(email_logs)")
        columns = [info[1] for info in c.fetchall()]
        if 'block_status' not in columns:
            c.execute("ALTER TABLE email_logs ADD COLUMN block_status TEXT")
            logger.info("Added block_status column to email_logs")
        # Insert mock users
        c.execute("INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'employee1', 'employee')")
        c.execute("INSERT OR IGNORE INTO users (id, username, role) VALUES (2, 'employee2', 'employee')")
        c.execute("INSERT OR IGNORE INTO users (id, username, role) VALUES (3, 'admin1', 'admin')")
        conn.commit()
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
    finally:
        conn.close()

init_db()

# Unwanted file extensions
UNWANTED_EXTENSIONS = [
    r'\.htm', r'\.html', r'\.exe', r'\.js', r'\.vbs', r'\.bat',
    r'\.scr', r'\.pif', r'\.com', r'\.zip', r'\.rar', r'\.msi'
]

# Suspicious domain patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    r'g[o0]{2,3}gle\.com',  # Misspellings like g00gle.com
    r'm[i1l]{2,}crosoft\.com',  # Misspellings like miicrosoft.com
    r'[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{1,2}$',  # Short or non-standard TLDs
    r'(\w+\.)+[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}',  # Multiple subdomains
]

# Expanded blocklist
DOMAIN_BLOCKLIST = {
    'example-bad.com', 'phish-site.net', 'fake-login.org',
    'secure-update.info', 'account-verify.biz'
}

# Detect unwanted extensions
def detect_extensions(email_content):
    try:
        extensions = []
        for ext in UNWANTED_EXTENSIONS:
            if re.search(ext, email_content, re.IGNORECASE):
                extensions.append(ext[2:])
        return extensions
    except Exception as e:
        logger.error(f"Extension detection failed: {str(e)}")
        return []

# Detect suspicious domains
def detect_domains(email_content):
    try:
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
        domains = []
        for url in urls:
            match = re.search(r'(?:https?://|www\.)([^/]+)', url)
            if match:
                domain = match.group(1)
                domains.append(domain)
                for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
                    if re.match(pattern, domain, re.IGNORECASE):
                        domains.append(f"{domain} (suspicious pattern)")
                if domain.lower() in DOMAIN_BLOCKLIST:
                    domains.append(f"{domain} (blocklisted)")
        return domains
    except Exception as e:
        logger.error(f"Domain detection failed: {str(e)}")
        return []

# Detect spelling and grammar errors
def detect_spelling_errors(email_content):
    try:
        blob = TextBlob(email_content)
        errors = sum(1 for word, conf in blob.spellcheck() if conf < 0.9)
        return errors
    except Exception as e:
        logger.error(f"Spelling check failed: {str(e)}")
        return 0

# Analyze email for phishing indicators
def analyze_email(email_content):
    try:
        extensions = detect_extensions(email_content)
        domains = detect_domains(email_content)
        spelling_errors = detect_spelling_errors(email_content)
        
        is_phishing = 0
        confidence = 0.0
        reasons = []
        if extensions:
            is_phishing = 1
            confidence += 0.4
            reasons.append(f"Risky extensions detected: {', '.join(extensions)}")
        if any("suspicious" in d or "blocklisted" in d for d in domains):
            is_phishing = 1
            confidence += 0.4
            reasons.append(f"Suspicious domains: {', '.join(d for d in domains if 'suspicious' in d or 'blocklisted' in d)}")
        if spelling_errors > 5:
            is_phishing = 1
            confidence += 0.2
            reasons.append(f"High spelling errors: {spelling_errors}")
        confidence = min(confidence, 1.0)
        
        # Simulate automatic blocking
        block_status = "Blocked" if is_phishing and confidence > 0.7 else "Allowed"
        
        return {
            "extensions": ", ".join(extensions) if extensions else "None",
            "domains": ", ".join(domains) if domains else "None",
            "spelling_errors": spelling_errors,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "reasons": reasons if reasons else ["No major issues detected"],
            "block_status": block_status
        }
    except Exception as e:
        logger.error(f"Email analysis failed: {str(e)}")
        return {
            "extensions": "Error",
            "domains": "Error",
            "spelling_errors": 0,
            "is_phishing": 0,
            "confidence": 0.0,
            "reasons": [f"Analysis failed: {str(e)}"],
            "block_status": "Allowed"
        }

# Log email analysis
def log_email(user_id, email_content, analysis, manual_block=False):
    block_status = "Blocked" if manual_block else analysis["block_status"]
    try:
        conn = sqlite3.connect("phishing_protection.db")
        c = conn.cursor()
        c.execute("INSERT INTO email_logs (user_id, email_content, extensions_detected, domains_detected, spelling_errors, is_phishing, confidence, block_status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (user_id, email_content, analysis["extensions"], analysis["domains"], analysis["spelling_errors"], analysis["is_phishing"], analysis["confidence"], block_status, datetime.now()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Logging failed: {str(e)}")

# Export logs as CSV
def export_logs():
    try:
        conn = sqlite3.connect("phishing_protection.db")
        logs = pd.read_sql_query("SELECT u.username, e.email_content, e.extensions_detected, e.domains_detected, e.spelling_errors, e.is_phishing, e.confidence, e.block_status, e.timestamp FROM email_logs e JOIN users u ON e.user_id = u.id", conn)
        conn.close()
        logs.to_csv("phishing_logs.csv", index=False)
        return "phishing_logs.csv"
    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        return None

# FastAPI setup
app = FastAPI()

class EmailRequest(BaseModel):
    email_content: str
    user_id: int
    manual_block: bool = False

@app.post("/analyze_email")
async def api_analyze_email(request: EmailRequest):
    try:
        analysis = analyze_email(request.email_content)
        log_email(request.user_id, request.email_content, analysis, request.manual_block)
        return {
            "is_phishing": bool(analysis["is_phishing"]),
            "confidence": analysis["confidence"],
            "extensions": analysis["extensions"],
            "domains": analysis["domains"],
            "spelling_errors": analysis["spelling_errors"],
            "reasons": analysis["reasons"],
            "block_status": "Blocked" if request.manual_block else analysis["block_status"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Run FastAPI in a separate thread
def run_fastapi():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

threading.Thread(target=run_fastapi, daemon=True).start()

# Streamlit app
st.title("Phishing Prevention Tool")

# Mock user login
if "user_id" not in st.session_state:
    st.session_state.user_id = None
    st.session_state.role = None

# Sidebar for user selection and training
with st.sidebar:
    st.header("User Login (Mock)")
    user_choice = st.selectbox("Select User", ["employee1 (Employee)", "employee2 (Employee)", "admin1 (Admin)"])
    if user_choice == "employee1 (Employee)":
        st.session_state.user_id = 1
        st.session_state.role = "employee"
    elif user_choice == "employee2 (Employee)":
        st.session_state.user_id = 2
        st.session_state.role = "employee"
    elif user_choice == "admin1 (Admin)":
        st.session_state.user_id = 3
        st.session_state.role = "admin"
    
    # Training tips
    st.header("Phishing Prevention Tips")
    st.write("- Check for suspicious file extensions (.htm, .exe).")
    st.write("- Verify domain names (e.g., avoid g00gle.com).")
    st.write("- Watch for spelling or grammar errors.")
    st.write("- Use the 'Block Email' button for suspicious emails.")
    st.write("**API Endpoint**: POST to `http://localhost:8000/analyze_email`")

# Main content based on role
if st.session_state.role == "employee":
    st.header("Email Phishing Analyzer")
    email_content = st.text_area("Paste the email content here (including links or attachments):", height=200)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Analyze Email"):
            if email_content and st.session_state.user_id:
                analysis = analyze_email(email_content)
                log_email(st.session_state.user_id, email_content, analysis)
                st.session_state.last_analysis = analysis
                st.session_state.last_email_content = email_content
                if analysis["is_phishing"]:
                    st.error(f"Warning: This email is likely phishing (Confidence: {analysis['confidence']:.2%}).")
                    st.write(f"**Action**: Email {analysis['block_status'].lower()} automatically.")
                    st.write("**Reasons**:\n- " + "\n- ".join(analysis["reasons"]))
                    st.write(f"**Details**:\n- Extensions: {analysis['extensions']}\n- Domains: {analysis['domains']}\n- Spelling Errors: {analysis['spelling_errors']}")
                    st.write("Tip: Use the 'Block Email' button to confirm blocking or report to IT.")
                else:
                    st.success(f"This email appears legitimate (Confidence: {analysis['confidence']:.2%}).")
                    st.write(f"**Action**: Email {analysis['block_status'].lower()}.")
                    st.write("**Reasons**:\n- " + "\n- ".join(analysis["reasons"]))
                    st.write(f"**Details**:\n- Extensions: {analysis['extensions']}\n- Domains: {analysis['domains']}\n- Spelling Errors: {analysis['spelling_errors']}")
                    st.write("Tip: Always verify the sender before taking action.")
            else:
                st.error("Please enter email content and ensure you are logged in.")
    with col2:
        if st.button("Block Email", disabled="last_analysis" not in st.session_state):
            if st.session_state.user_id and st.session_state.last_email_content:
                log_email(st.session_state.user_id, st.session_state.last_email_content, st.session_state.last_analysis, manual_block=True)
                st.success("Email manually blocked and logged.")
            else:
                st.error("No email analyzed yet or user not logged in.")

elif st.session_state.role == "admin":
    st.header("Admin Dashboard")
    
    # Display email logs
    st.subheader("Email Analysis Logs")
    try:
        conn = sqlite3.connect("phishing_protection.db")
        logs = pd.read_sql_query("SELECT u.username, e.email_content, e.extensions_detected, e.domains_detected, e.spelling_errors, e.is_phishing, e.confidence, e.block_status, e.timestamp FROM email_logs e JOIN users u ON e.user_id = u.id", conn)
        
        # Text-based summary
        c = conn.cursor()
        c.execute("SELECT is_phishing, COUNT(*) FROM email_logs GROUP BY is_phishing")
        phishing_metrics = c.fetchall()
        c.execute("SELECT block_status, COUNT(*) FROM email_logs GROUP BY block_status")
        block_metrics = c.fetchall()
        conn.close()
        
        phishing_count = sum(count for is_phishing, count in phishing_metrics if is_phishing == 1)
        legit_count = sum(count for is_phishing, count in phishing_metrics if is_phishing == 0)
        blocked_count = sum(count for status, count in block_metrics if status == "Blocked")
        allowed_count = sum(count for status, count in block_metrics if status == "Allowed")
        
        st.write("**Email Analysis Summary**")
        st.write(f"- Total Emails Analyzed: {phishing_count + legit_count}")
        st.write(f"- Phishing Emails: {phishing_count}")
        st.write(f"- Legitimate Emails: {legit_count}")
        st.write(f"- Blocked Emails: {blocked_count}")
        st.write(f"- Allowed Emails: {allowed_count}")
        
        st.dataframe(logs)
        
        # Filter logs
        st.subheader("Filter Logs")
        filter_user = st.selectbox("Filter by User", ["All"] + ["employee1", "employee2"])
        filter_phishing = st.selectbox("Filter by Phishing Status", ["All", "Phishing", "Legitimate"])
        filter_block = st.selectbox("Filter by Block Status", ["All", "Blocked", "Allowed"])
        filtered_logs = logs
        if filter_user != "All":
            filtered_logs = filtered_logs[filtered_logs["username"] == filter_user]
        if filter_phishing != "All":
            filtered_logs = filtered_logs[filtered_logs["is_phishing"] == (1 if filter_phishing == "Phishing" else 0)]
        if filter_block != "All":
            filtered_logs = filtered_logs[filtered_logs["block_status"] == filter_block]
        st.dataframe(filtered_logs)
        
        # Export logs
        if st.button("Export Logs as CSV"):
            csv_file = export_logs()
            if csv_file:
                st.success(f"Logs exported to {csv_file}")
                with open(csv_file, "rb") as f:
                    st.download_button("Download CSV", f, file_name=csv_file)
            else:
                st.error("Failed to export logs.")
    except Exception as e:
        st.error(f"Error loading logs: {str(e)}")


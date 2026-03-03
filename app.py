# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from fpdf import FPDF
from datetime import datetime

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("AI Website Security Scanner")

url = st.text_input("Enter your website URL (include https://)")

# ===============================
# Safe PDF Text (ASCII only)
# ===============================
def safe_text(text):
    """Convert any text to PDF-safe ASCII text."""
    if not text:
        return ""
    text = str(text)
    # Replace common symbols that break FPDF
    replacements = {
        "⚠️": "WARNING:",
        "✅": "OK:",
        "—": "-",
        "…": "..."
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Encode to latin-1 and decode
    return text.encode("latin-1", "replace").decode("latin-1")

# ===============================
# CSP Evaluation
# ===============================
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "No Content-Security-Policy header found"

    warnings = []
    csp = csp_header.lower()

    if "unsafe-inline" in csp:
        warnings.append("Uses unsafe-inline")
    if "unsafe-eval" in csp:
        warnings.append("Uses unsafe-eval")
    if "*" in csp:
        warnings.append("Uses wildcard *")
    if "script-src" not in csp and "default-src" not in csp:
        warnings.append("Missing script-src/default-src")

    if not warnings:
        return "Strong CSP configuration"
    return "Weak CSP: " + ", ".join(warnings)

# ===============================
# Severity Logic
# ===============================
def severity_label(issue_type, result):
    if not result or "No" in str(result):
        return "None"
    if issue_type in ["SQLi", "XSS"]:
        return "High"
    if issue_type == "CSP":
        return "Medium"
    if issue_type == "AI":
        return "Medium"
    if issue_type == "Form":
        return "Low"
    return "Low"

def severity_color(sev):
    if sev == "High":
        return (255, 0, 0)
    if sev == "Medium":
        return (255, 140, 0)
    if sev == "Low":
        return (0, 128, 0)
    return (0, 0, 0)

# ===============================
# PDF Class (Built-in Fonts Only)
# ===============================
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# ===============================
# Scan Button
# ===============================
if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Please enter valid URL including http:// or https://")
        st.stop()

    st.info("Crawling website...")
    pages, forms = crawl(url)
    st.success(f"Found {len(pages)} pages and {len(forms)} forms!")

    scan_results = []
    lock = threading.Lock()
    progress_bar = st.progress(0)
    total_pages = len(pages)

    # ---------------------------
    # Page scanning
    # ---------------------------
    def scan_page(page):
        page_res = {"page": page}

        page_res["SQLi"] = "WARNING: Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        page_res["XSS"] = "WARNING: Possible XSS" if test_xss(page) else "No XSS"

        try:
            response = requests.get(page, timeout=5)
            page_res["AI"] = analyze_response(response.text)
        except:
            page_res["AI"] = "AI analysis failed"

        try:
            resp = requests.get(page, timeout=5)
            csp_header = resp.headers.get("Content-Security-Policy", "")
            page_res["CSP"] = evaluate_csp_header(csp_header)
        except:
            page_res["CSP"] = "CSP check failed"

        with lock:
            scan_results.append(page_res)
            progress_bar.progress(len(scan_results) / total_pages)

        st.write(f"Scanned: {page}")
        st.json(page_res)

    threads = []
    for pg in pages:
        t = threading.Thread(target=scan_page, args=(pg,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # ---------------------------
    # Form Testing
    # ---------------------------
    for frm in forms:
        res = test_form(frm)
        st.write(f"Form on {frm['page']}:")
        st.json(res)
        scan_results.append({"page": frm["page"], "Form": res})

    # ---------------------------
    # PDF Generation
    # ---------------------------
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Cover Page ---
    pdf.add_page()
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "AI Website Security Scanner Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Target URL: {safe_text(url)}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)

    # --- Summary ---
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(5)

    high = medium = low = 0
    for item in scan_results:
        for k, v in item.items():
            if k == "page":
                continue
            sev = severity_label(k, v)
            if sev == "High":
                high += 1
            elif sev == "Medium":
                medium += 1
            elif sev == "Low":
                low += 1

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Pages/Forms Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Issues: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Issues: {medium}", ln=True)
    pdf.cell(0, 8, f"Low Severity Issues: {low}", ln=True)

    # --- Detailed Findings ---
    for item in scan_results:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(5)

        for k, v in item.items():
            if k == "page":
                continue

            sev = severity_label(k, v)
            r, g, b = severity_color(sev)
            pdf.set_text_color(r, g, b)
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, f"{k} - Severity: {sev}", ln=True)

            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, safe_text(v))
            pdf.ln(3)

    filename = "scan_report.pdf"
    pdf.output(filename)
    st.success("Scan Complete!")

    with open(filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=filename)

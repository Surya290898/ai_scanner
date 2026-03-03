# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from fpdf import FPDF
from datetime import datetime
import csv

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (Startup MVP)")

url = st.text_input("Enter your website URL (include https://)")

# -------------------------------
# Safe text for PDF (ASCII only)
# -------------------------------
def safe_text(text):
    if not text:
        return ""
    text = str(text)
    replacements = {"⚠️": "WARNING:", "✅": "OK:", "—": "-", "…": "..."}
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")

# -------------------------------
# CSP Evaluation
# -------------------------------
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "No Content-Security-Policy header found"
    warnings = []
    csp = csp_header.lower()
    if "unsafe-inline" in csp: warnings.append("Uses unsafe-inline")
    if "unsafe-eval" in csp: warnings.append("Uses unsafe-eval")
    if "*" in csp: warnings.append("Uses wildcard *")
    if "script-src" not in csp and "default-src" not in csp: warnings.append("Missing script-src/default-src")
    return "Strong CSP configuration" if not warnings else "Weak CSP: " + ", ".join(warnings)

# -------------------------------
# Severity Logic
# -------------------------------
def severity_label(issue_type, result):
    if not result or "No" in str(result): return "None"
    if issue_type in ["SQLi", "XSS"]: return "High"
    if issue_type == "CSP": return "Medium"
    if issue_type == "AI": return "Medium"
    if issue_type == "Form": return "Low"
    return "Low"

def severity_color(sev):
    if sev == "High": return (255, 0, 0)
    if sev == "Medium": return (255, 140, 0)
    if sev == "Low": return (0, 128, 0)
    return (0, 0, 0)

# -------------------------------
# PDF Class
# -------------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# -------------------------------
# Scan Button
# -------------------------------
if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Please enter a valid URL including http:// or https://")
        st.stop()

    st.info("🔍 Crawling website...")
    pages, forms = crawl(url)
    st.success(f"Found {len(pages)} pages and {len(forms)} forms!")

    scan_results = []
    lock = threading.Lock()
    progress_bar = st.progress(0)
    total_pages = len(pages)

    # -------------------------------
    # Page Scanner
    # -------------------------------
    def scan_page(page):
        page_res = {"page": page}
        page_res["SQLi"] = "Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        page_res["XSS"] = "Possible XSS" if test_xss(page) else "No XSS"

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
    for t in threads: t.join()

    # -------------------------------
    # Form Testing
    # -------------------------------
    for frm in forms:
        res = test_form(frm)
        st.write(f"Form on {frm['page']}:")
        st.json(res)
        scan_results.append({"page": frm["page"], "Form": res})

    # -------------------------------
    # Compute Risk Score
    # -------------------------------
    high = medium = low = 0
    for item in scan_results:
        for k, v in item.items():
            if k == "page": continue
            sev = severity_label(k, v)
            if sev == "High": high += 1
            elif sev == "Medium": medium += 1
            elif sev == "Low": low += 1

    risk_score = high*10 + medium*5 + low*2
    if risk_score >= 50: risk_level = "Critical"
    elif risk_score >= 30: risk_level = "High"
    elif risk_score >= 10: risk_level = "Medium"
    else: risk_level = "Low"

    # -------------------------------
    # Streamlit Dashboard
    # -------------------------------
    st.subheader("Scan Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("High Severity", high, delta_color="inverse")
    col2.metric("Medium Severity", medium, delta_color="inverse")
    col3.metric("Low Severity", low, delta_color="inverse")
    col4.metric("Risk Score", risk_score, risk_level)

    # -------------------------------
    # CSV Export
    # -------------------------------
    csv_filename = "scan_report.csv"
    with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["page", "issue_type", "severity", "details"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in scan_results:
            page_name = item.get("page")
            for k, v in item.items():
                if k == "page": continue
                writer.writerow({
                    "page": page_name,
                    "issue_type": k,
                    "severity": severity_label(k, v),
                    "details": str(v)
                })
    with open(csv_filename, "rb") as f:
        st.download_button("Download CSV Report", f, file_name=csv_filename)

    # -------------------------------
    # PDF Generation
    # -------------------------------
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Cover Page
    pdf.add_page()
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "AI Website Security Scanner Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Target URL: {safe_text(url)}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 8, f"Overall Risk Score: {risk_score} ({risk_level})", ln=True)

    # Executive Summary
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Pages/Forms Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Issues: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Issues: {medium}", ln=True)
    pdf.cell(0, 8, f"Low Severity Issues: {low}", ln=True)

    # Detailed Findings
    for item in scan_results:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(5)

        for k, v in item.items():
            if k == "page": continue
            sev = severity_label(k, v)
            r, g, b = severity_color(sev)
            pdf.set_text_color(r, g, b)
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(0, 8, f"{k} - Severity: {sev}")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, safe_text(v))
            pdf.ln(3)

    pdf_filename = "scan_report.pdf"
    pdf.output(pdf_filename)
    st.success("✅ Scan Complete!")
    with open(pdf_filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=pdf_filename)

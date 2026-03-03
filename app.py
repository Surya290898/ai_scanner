# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (MVP with PDF)")

url = st.text_input("Enter your website URL (include https://)")

# -------------------------------
# Safe Text
# -------------------------------
def safe_text(text):
    if not text:
        return ""
    return str(text).replace("⚠️", "WARNING:").replace("✅", "OK:").replace("—", "-").replace("…", "...")

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
# Severity
# -------------------------------
def severity_label(issue_type, result):
    if not result or "No" in str(result): return "None"
    if issue_type in ["SQLi", "XSS"]: return "High"
    if issue_type == "CSP": return "Medium"
    if issue_type == "AI": return "Medium"
    if issue_type == "Form": return "Low"
    return "Low"

def severity_color(sev):
    if sev == "High": return colors.red
    if sev == "Medium": return colors.orange
    if sev == "Low": return colors.green
    return colors.black

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
    col1.metric("High Severity", high)
    col2.metric("Medium Severity", medium)
    col3.metric("Low Severity", low)
    col4.metric("Risk Score", risk_score, risk_level)

    # -------------------------------
    # PDF Generation with ReportLab
    # -------------------------------
    pdf_filename = "scan_report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Cover Page
    title_style = styles['Title']
    story.append(Paragraph("AI Website Security Scanner Report", title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Target URL: {safe_text(url)}", styles['Normal']))
    story.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 30))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"Total Pages/Forms Scanned: {len(scan_results)}", styles['Normal']))
    story.append(Paragraph(f"High Severity Issues: {high}", styles['Normal']))
    story.append(Paragraph(f"Medium Severity Issues: {medium}", styles['Normal']))
    story.append(Paragraph(f"Low Severity Issues: {low}", styles['Normal']))
    story.append(Paragraph(f"Overall Risk Level: {risk_level}", styles['Normal']))
    story.append(Spacer(1, 20))

    # Detailed Findings
    for item in scan_results:
        story.append(Paragraph(f"Page: {safe_text(item.get('page'))}", styles['Heading3']))
        story.append(Spacer(1, 5))
        for k, v in item.items():
            if k == "page": continue
            sev = severity_label(k, v)
            tbl = Table([[k, sev, str(v)]], colWidths=[100, 80, 350])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), colors.lightgrey),
                ('TEXTCOLOR', (1,0), (1,0), severity_color(sev)),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOX', (0,0), (-1,-1), 0.5, colors.black),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.black),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica')
            ]))
            story.append(tbl)
            story.append(Spacer(1,5))

    doc.build(story)
    st.success("✅ Scan Complete! PDF report generated.")

    with open(pdf_filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=pdf_filename)

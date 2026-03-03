# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss
import requests
import threading
from fpdf import FPDF
from datetime import datetime

st.set_page_config(page_title="Website Security Scanner", layout="wide")
st.title("Website Security Scanner")

url = st.text_input("Enter your website URL (include https://)")

# ===============================
# Safe PDF Text
# ===============================
def safe_text(text, max_len=500):
    """Convert text to PDF-safe ASCII text and truncate long lines."""
    if not text:
        return ""
    text = str(text)
    replacements = {"—": "-", "…": "..."}
    for k, v in replacements.items():
        text = text.replace(k, v)
    text = text.encode("latin-1", "replace").decode("latin-1")
    if len(text) > max_len:
        text = text[:max_len] + " ..."
    return text

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
    return "Low"

def severity_color(sev):
    if sev == "High":
        return (255, 0, 0)
    if sev == "Medium":
        return (255, 165, 0)
    if sev == "Low":
        return (0, 128, 0)
    return (0, 0, 0)

def severity_fill_color(sev):
    if sev == "High":
        return (255, 200, 200)
    if sev == "Medium":
        return (255, 230, 180)
    if sev == "Low":
        return (200, 255, 200)
    return (255, 255, 255)

# ===============================
# PDF Class with Table
# ===============================
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "Website Security Scan Report", ln=True, align="C")
        self.ln(5)

    def table_row(self, row_data, col_widths, colors=None):
        """Draw one row with optional background color for each cell."""
        max_height = 8
        self.set_font("Arial", "", 11)
        for i, text in enumerate(row_data):
            fill_color = (255, 255, 255)
            if colors and colors[i]:
                fill_color = colors[i]
            self.set_fill_color(*fill_color)
            self.multi_cell(col_widths[i], max_height, safe_text(str(text)), border=1, ln=3, fill=True, max_line_height=self.font_size)
            x = self.get_x()
            y = self.get_y()
            self.set_xy(x + col_widths[i], y - max_height)
        self.ln(max_height)

# ===============================
# Scan Button
# ===============================
if st.button("Scan"):

    if not url.startswith("http"):
        st.error("Please enter a valid URL including http:// or https://")
        st.stop()

    st.info("Crawling website...")
    pages, _ = crawl(url)
    st.success(f"Found {len(pages)} pages!")

    scan_results = []
    lock = threading.Lock()
    progress_bar = st.progress(0)
    total_pages = len(pages)

    # ---------------------------
    # Page scanning
    # ---------------------------
    def scan_page(page):
        page_res = {"page": page}
        page_res["SQLi"] = "Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        page_res["XSS"] = "Possible XSS" if test_xss(page) else "No XSS"
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
    # PDF Generation
    # ---------------------------
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Cover Page ---
    pdf.add_page()
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "Website Security Scan Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Target URL: {safe_text(url)}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)

    # --- Summary ---
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(5)

    high = medium = 0
    for item in scan_results:
        for k, v in item.items():
            if k == "page":
                continue
            sev = severity_label(k, v)
            if sev == "High":
                high += 1
            elif sev == "Medium":
                medium += 1

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Pages Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Issues: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Issues: {medium}", ln=True)

    # --- Detailed Findings Table ---
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Detailed Findings", ln=True)
    pdf.ln(5)

    col_widths = [60, 40, 80]  # Page | Issue | Result
    pdf.set_font("Arial", "B", 12)
    pdf.set_fill_color(200, 200, 200)
    headers = ["Page", "Issue", "Result"]
    pdf.table_row(headers, col_widths, colors=[(200,200,200)]*3)

    pdf.set_font("Arial", "", 11)
    for item in scan_results:
        page = item["page"]
        for issue_type in ["SQLi", "XSS", "CSP"]:
            if issue_type not in item:
                continue
            result = item[issue_type]
            sev = severity_label(issue_type, result)
            color = severity_fill_color(sev)
            pdf.table_row([page, issue_type, result], col_widths, colors=[None, color, None])

    # --- Output PDF ---
    filename = "scan_report.pdf"
    pdf.output(filename)
    st.success("Scan Complete! Download your professional report below:")

    with open(filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=filename)

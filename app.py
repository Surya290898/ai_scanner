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
# Safe PDF Text
# ===============================
def safe_text(text):
    if not text:
        return ""
    text = str(text)
    replacements = {
        "⚠️": "WARNING:",
        "✅": "OK:",
        "—": "-",
        "…": "..."
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")

# ===============================
# CSP Evaluation
# ===============================
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "No Content-Security-Policy header found"
    warnings = []
    csp = csp_header.lower()
    if "unsafe-inline" in csp: warnings.append("Uses unsafe-inline")
    if "unsafe-eval" in csp: warnings.append("Uses unsafe-eval")
    if "*" in csp: warnings.append("Uses wildcard *")
    if "script-src" not in csp and "default-src" not in csp: warnings.append("Missing script-src/default-src")
    if not warnings: return "Strong CSP configuration"
    return "Weak CSP: " + ", ".join(warnings)

# ===============================
# Severity
# ===============================
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

# ===============================
# PDF Class with Table
# ===============================
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

    def table_header(self, col_widths, headers):
        self.set_font("Arial", "B", 12)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 8, safe_text(h), border=1, align="C")
        self.ln()

    def table_row(self, col_widths, row_data, fill=False, colors=None):
        self.set_font("Arial", "", 11)
        y_start = self.get_y()
        max_lines = 0
        wrapped_cols = []
        for i, txt in enumerate(row_data):
            txt = safe_text(txt)
            lines = self.multi_cell_split(col_widths[i], txt)
            wrapped_cols.append(lines)
            if len(lines) > max_lines:
                max_lines = len(lines)

        # Draw cells
        for line_idx in range(max_lines):
            for i, lines in enumerate(wrapped_cols):
                txt = lines[line_idx] if line_idx < len(lines) else ""
                if colors and colors[i]:
                    r, g, b = colors[i]
                    self.set_text_color(r, g, b)
                else:
                    self.set_text_color(0, 0, 0)
                self.multi_cell(col_widths[i], 6, txt, border=1, ln=3 if i == len(wrapped_cols)-1 else 0)
            self.ln(0)
        if fill:
            self.set_fill_color(230, 230, 230)

    def multi_cell_split(self, w, txt):
        # split text to fit width w
        cw = self.get_string_width
        words = txt.split(" ")
        lines = []
        line = ""
        for word in words:
            test_line = line + (" " if line else "") + word
            if cw(test_line) <= w:
                line = test_line
            else:
                if line: lines.append(line)
                line = word
        if line: lines.append(line)
        return lines

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
            if k == "page": continue
            sev = severity_label(k, v)
            if sev == "High": high += 1
            elif sev == "Medium": medium += 1
            elif sev == "Low": low += 1

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Pages/Forms Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Issues: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Issues: {medium}", ln=True)
    pdf.cell(0, 8, f"Low Severity Issues: {low}", ln=True)

    # --- Detailed Findings Table ---
    col_widths = [50, 30, 110]  # Vulnerability | Severity | Details
    headers = ["Vulnerability", "Severity", "Details"]

    for item in scan_results:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(3)
        pdf.table_header(col_widths, headers)
        fill = False
        for k, v in item.items():
            if k == "page": continue
            sev = severity_label(k, v)
            r, g, b = severity_color(sev)
            pdf.table_row(col_widths, [k, sev, str(v)], fill=fill, colors=[None, (r,g,b), None])
            fill = not fill

    filename = "scan_report.pdf"
    pdf.output(filename)
    st.success("Scan Complete!")
    with open(filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=filename)

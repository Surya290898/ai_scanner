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
st.title("🛡 AI Website Security Scanner - Wrapped PDF")

url = st.text_input("Enter your website URL (include https://)")

# ---------------------------
# Safe Text for PDF
# ---------------------------
def safe_text(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")

# ---------------------------
# CSP Evaluation
# ---------------------------
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "⚠️ No Content-Security-Policy header found"
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
        return "✅ Strong CSP configuration"
    return "⚠️ Weak CSP: " + ", ".join(warnings)

# ---------------------------
# Severity Mapping
# ---------------------------
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
    if sev=="High": return (255,0,0)
    if sev=="Medium": return (255,140,0)
    if sev=="Low": return (0,128,0)
    return (0,0,0)

# ---------------------------
# PDF Class - Wrapped Cells
# ---------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_fill_color(200, 200, 200)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C", fill=True)
        self.ln(5)

    def table_row(self, col_widths, data, fill=False, colors=None):
        max_height = 0
        nb_lines = []
        # Calculate number of lines for each cell
        for i, txt in enumerate(data):
            lines = self.multi_cell_lines(col_widths[i], txt)
            nb_lines.append(lines)
            if lines * 6 > max_height:
                max_height = lines * 6  # line height = 6
        # Save current position
        x_start = self.get_x()
        y_start = self.get_y()
        # Draw cells
        for i, txt in enumerate(data):
            self.set_xy(x_start + sum(col_widths[:i]), y_start)
            if colors and colors[i]:
                self.set_text_color(*colors[i])
            else:
                self.set_text_color(0,0,0)
            self.multi_cell(col_widths[i], 6, safe_text(txt), border=1, ln=3, fill=fill)
        # Move to next line
        self.set_y(y_start + max_height)

    def multi_cell_lines(self, w, txt):
        # Estimate number of lines a multi_cell will take
        if not txt:
            return 1
        return len(self.multi_cell_split(txt, w))

    def multi_cell_split(self, txt, w):
        # Split text into lines for multi_cell
        cw = self.get_string_width
        words = txt.split()
        lines = []
        current = ""
        for word in words:
            test_line = current + (" " if current else "") + word
            if cw(test_line) <= w:
                current = test_line
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines

# ---------------------------
# Scan Button
# ---------------------------
if st.button("Scan"):

    if not url.startswith("http"):
        st.error("Please enter a valid URL including https://")
        st.stop()

    st.info("🔍 Crawling website...")
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
        page_res["SQLi"] = "⚠️ Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        page_res["XSS"] = "⚠️ Possible XSS" if test_xss(page) else "No XSS"
        try:
            response = requests.get(page, timeout=5)
            page_res["AI"] = analyze_response(response.text)
        except:
            page_res["AI"] = "Failed AI analysis"
        try:
            resp = requests.get(page, timeout=5)
            csp_header = resp.headers.get("Content-Security-Policy", "")
            page_res["CSP"] = evaluate_csp_header(csp_header)
        except:
            page_res["CSP"] = "Failed CSP check"

        with lock:
            scan_results.append(page_res)
            progress_bar.progress(len(scan_results)/total_pages)
        st.write(f"### Page: {page}")
        st.json(page_res)

    threads = []
    for pg in pages:
        t = threading.Thread(target=scan_page, args=(pg,))
        t.start()
        threads.append(t)
    for t in threads: t.join()

    # ---------------------------
    # Form Testing
    # ---------------------------
    st.write("📝 Testing forms…")
    for frm in forms:
        res = test_form(frm)
        st.write(f"Form on {frm['page']}:")
        st.json(res)
        scan_results.append({"page": frm['page'], "Form": res})

    # ---------------------------
    # PDF Generation - Wrapped Table
    # ---------------------------
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Cover Page ---
    pdf.add_page()
    pdf.set_font("Arial","B",20)
    pdf.cell(0,15,"AI Website Security Scanner Report",ln=True,align="C")
    pdf.ln(10)
    pdf.set_font("Arial","",12)
    pdf.cell(0,8,f"URL Scanned: {safe_text(url)}",ln=True)
    pdf.cell(0,8,f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",ln=True)
    pdf.ln(10)

    # --- Executive Summary ---
    pdf.add_page()
    pdf.set_font("Arial","B",16)
    pdf.cell(0,10,"Executive Summary",ln=True)
    pdf.ln(5)

    high = sum(1 for r in scan_results if any(severity_label(k,v)=="High" for k,v in r.items()))
    medium = sum(1 for r in scan_results if any(severity_label(k,v)=="Medium" for k,v in r.items()))
    low = sum(1 for r in scan_results if any(severity_label(k,v)=="Low" for k,v in r.items()))

    pdf.set_font("Arial","B",12)
    col_widths = [80,30]
    pdf.table_row(col_widths, ["Metric","Count"], fill=True)
    pdf.set_font("Arial","",12)
    pdf.table_row(col_widths, ["Total Pages Scanned", str(len(scan_results))])
    pdf.table_row(col_widths, ["High Severity Issues", str(high)], colors=[severity_color("High"), None])
    pdf.table_row(col_widths, ["Medium Severity Issues", str(medium)], colors=[severity_color("Medium"), None])
    pdf.table_row(col_widths, ["Low Severity Issues", str(low)], colors=[severity_color("Low"), None])

    # --- Detailed Findings ---
    pdf.add_page()
    pdf.set_font("Arial","B",14)
    pdf.cell(0,10,"Detailed Findings",ln=True)
    pdf.ln(5)

    col_widths = [50,30,110]
    for item in scan_results:
        pdf.set_font("Arial","B",12)
        pdf.cell(0,8,f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(2)

        # Header row
        pdf.set_font("Arial","B",11)
        pdf.set_fill_color(200,200,200)
        pdf.table_row(col_widths, ["Vulnerability","Severity","Details"], fill=True)

        pdf.set_font("Arial","",11)
        fill = False
        for k,v in item.items():
            if k=="page": continue
            sev = severity_label(k,v)
            pdf.set_fill_color(245,245,245) if fill else pdf.set_fill_color(255,255,255)
            pdf.table_row(col_widths, [k, sev, str(v)], fill=fill, colors=[None, severity_color(sev), None])
            fill = not fill
        pdf.ln(3)

    filename="scan_report_wrapped.pdf"
    pdf.output(filename)
    st.success("✅ Scan Complete - PDF with wrapped text")
    with open(filename,"rb") as f:
        st.download_button("Download PDF Report",f,file_name=filename)

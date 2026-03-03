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
st.title("🛡 AI Website Security Scanner - OWASP Style PDF")

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
# PDF Class - OWASP Style
# ---------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_fill_color(220, 220, 220)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C", fill=True)
        self.ln(5)

    def table_row(self, cols, widths, fill=False, text_color=(0,0,0)):
        self.set_text_color(*text_color)
        for i, col in enumerate(cols):
            self.cell(widths[i], 8, safe_text(col), border=1, ln=0, align='L', fill=fill)
        self.ln()

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
    # PDF Generation - OWASP Style
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

    # --- Executive Summary Table ---
    pdf.add_page()
    pdf.set_font("Arial","B",16)
    pdf.cell(0,10,"Executive Summary",ln=True)
    pdf.ln(5)

    high = sum(1 for r in scan_results if any(severity_label(k,v)=="High" for k,v in r.items()))
    medium = sum(1 for r in scan_results if any(severity_label(k,v)=="Medium" for k,v in r.items()))
    low = sum(1 for r in scan_results if any(severity_label(k,v)=="Low" for k,v in r.items()))

    pdf.set_font("Arial","B",12)
    pdf.table_row(["Metric","Count"], [70,30], fill=True)
    pdf.table_row(["Total Pages Scanned", str(len(scan_results))], [70,30])
    pdf.table_row(["High Severity Issues", str(high)], [70,30], text_color=severity_color("High"))
    pdf.table_row(["Medium Severity Issues", str(medium)], [70,30], text_color=severity_color("Medium"))
    pdf.table_row(["Low Severity Issues", str(low)], [70,30], text_color=severity_color("Low"))

    # --- Detailed Findings with alternating row colors ---
    pdf.add_page()
    pdf.set_font("Arial","B",14)
    pdf.cell(0,10,"Detailed Findings",ln=True)
    pdf.ln(5)

    for item in scan_results:
        pdf.set_font("Arial","B",12)
        pdf.cell(0,8,f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(2)

        # Table header
        pdf.set_font("Arial","B",11)
        pdf.set_fill_color(200,200,200)
        pdf.table_row(["Vulnerability","Severity","Details"], [50,30,110], fill=True)

        pdf.set_font("Arial","",11)
        fill = False
        for k,v in item.items():
            if k=="page": continue
            sev = severity_label(k,v)
            pdf.set_fill_color(245,245,245) if fill else pdf.set_fill_color(255,255,255)
            pdf.table_row([k, sev, str(v)], [50,30,110], fill=fill, text_color=severity_color(sev))
            fill = not fill
        pdf.ln(3)

    filename="scan_report_owasp_style.pdf"
    pdf.output(filename)
    st.success("✅ OWASP-Style Professional Scan Complete")
    with open(filename,"rb") as f:
        st.download_button("Download OWASP-Style PDF Report",f,file_name=filename)

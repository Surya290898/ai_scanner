# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from fpdf import FPDF
from datetime import datetime
import os

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (Unicode Safe PDF)")

url = st.text_input("Enter your website URL (include https://)")

# ---------------------------
# CSP Evaluation
# ---------------------------
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "⚠️ No Content-Security-Policy header found — add a strict CSP."
    warnings = []
    csp = csp_header.lower()
    if "unsafe-inline" in csp:
        warnings.append("avoid 'unsafe-inline', use nonces or hashes")
    if "unsafe-eval" in csp:
        warnings.append("avoid 'unsafe-eval', restrict scripts")
    if "* " in csp or "*;" in csp:
        warnings.append("avoid wildcard '*' in directives")
    if "script-src" not in csp and "default-src" not in csp:
        warnings.append("add script-src or default-src directive")
    if not warnings:
        return f"✅ Strong CSP: {csp_header}"
    return f"⚠️ Weak CSP: {', '.join(warnings)}. Suggested: default-src 'self'; script-src 'self' 'nonce-<random>'; img-src 'self'; style-src 'self';"

# ---------------------------
# Severity Mapping
# ---------------------------
def severity_label(issue_type, detected):
    if not detected or "No" in detected:
        return "None"
    if issue_type in ["SQLi", "XSS"]:
        return "High"
    if issue_type == "CSP":
        return "Medium" if "⚠️" in detected else "Low"
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
# PDF Class
# ---------------------------
class PDF(FPDF):
    def header(self):
        self.set_font(self.font_family, 'B', 16)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# ---------------------------
# Scan Button
# ---------------------------
if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Please enter a valid URL including http:// or https://")
    else:
        st.info("🔍 Crawling website...")
        pages, forms = crawl(url)
        st.success(f"Found {len(pages)} pages and {len(forms)} forms!")

        scan_results = []
        lock = threading.Lock()
        page_container = st.container()
        progress_bar = st.progress(0)
        total_pages = len(pages)
        progress = {"completed":0}

        # ---------------------------
        # Page scanning
        # ---------------------------
        def scan_page(page):
            page_res = {"page": page, "SQLi": None, "XSS": None, "AI": None, "CSP": None}
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
                progress["completed"] +=1
                progress_bar.progress(progress["completed"]/total_pages)

            with page_container:
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
        # Generate PDF (Unicode-safe)
        # ---------------------------
        pdf = PDF()

        # --- Register Unicode font before any page ---
        FONT_PATH = "fonts/DejaVuSans.ttf"
        if os.path.exists(FONT_PATH):
            pdf.add_font("DejaVuSans", "", FONT_PATH, uni=True)
            pdf.font_family = "DejaVuSans"
        else:
            pdf.font_family = "Arial"
            st.warning("DejaVuSans.ttf not found. Using Arial (Unicode may fail).")

        # Cover Page
        pdf.add_page()
        pdf.set_font(pdf.font_family,'B',20)
        pdf.cell(0,15,"AI Website Security Scanner Report",ln=True,align="C")
        pdf.ln(10)
        pdf.set_font(pdf.font_family,'',12)
        pdf.cell(0,8,f"URL Scanned: {url}",ln=True)
        pdf.cell(0,8,f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",ln=True)
        pdf.ln(10)

        # Summary Page
        pdf.add_page()
        pdf.set_font(pdf.font_family,'B',16)
        pdf.cell(0,10,"Summary",ln=True)
        pdf.ln(5)
        total_pages_count=len(scan_results)
        high=sum(1 for r in scan_results if "High" in r.values())
        medium=sum(1 for r in scan_results if "Medium" in r.values())
        low=sum(1 for r in scan_results if "Low" in r.values())
        pdf.set_font(pdf.font_family,'',12)
        pdf.cell(0,8,f"Total Pages Scanned: {total_pages_count}",ln=True)
        pdf.cell(0,8,f"High Severity Issues: {high}",ln=True)
        pdf.cell(0,8,f"Medium Severity Issues: {medium}",ln=True)
        pdf.cell(0,8,f"Low Severity Issues: {low}",ln=True)
        pdf.ln(5)

        # Detailed Findings
        for item in scan_results:
            pdf.add_page()
            pdf.set_font(pdf.font_family,'B',14)
            pdf.cell(0,10,f"Page: {item.get('page','')}",ln=True)
            pdf.ln(2)
            pdf.set_font(pdf.font_family,'B',12)
            pdf.cell(50,8,"Vulnerability",border=1)
            pdf.cell(30,8,"Severity",border=1)
            pdf.cell(0,8,"Details",border=1,ln=True)
            pdf.set_font(pdf.font_family,'',12)
            for k,v in item.items():
                if k=="page": continue
                sev=severity_label(k,v)
                r,g,b=severity_color(sev)
                pdf.set_text_color(r,g,b)
                pdf.cell(50,8,k,border=1)
                pdf.cell(30,8,sev,border=1)
                # Use multi_cell (Unicode-safe)
                pdf.multi_cell(0,8,str(v),border=1)
            pdf.set_text_color(0,0,0) # reset color

        fname="scan_report_unicode_safe.pdf"
        pdf.output(fname)
        st.success("✅ Scanning complete!")
        with open(fname,"rb") as f:
            st.download_button("Download PDF Report",f,file_name=fname)

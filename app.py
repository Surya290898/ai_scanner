# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from fpdf import FPDF

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (UTF-8 PDF)")

url = st.text_input("Enter your website URL (include https://)")

# ---------------------------
# CSP Evaluation
# ---------------------------
def evaluate_csp_header(csp_header: str):
    """
    Check CSP and give best practice remediation
    """
    if not csp_header:
        return "⚠️ No Content-Security-Policy header found — add a strict CSP."
    
    warnings = []
    csp = csp_header.lower()

    if "unsafe-inline" in csp:
        warnings.append("avoid 'unsafe-inline', use nonces or hashes instead")
    if "unsafe-eval" in csp:
        warnings.append("avoid 'unsafe-eval', restrict scripts")
    if "* " in csp or "*;" in csp:
        warnings.append("avoid wildcard '*' in directives")

    if not warnings:
        return f"✅ Strong CSP: {csp_header}"
    # Add remediation guide
    guide = ", ".join(warnings)
    return f"⚠️ Weak CSP: {guide}. Suggested: default-src 'self'; script-src 'self' 'nonce-<random>'; img-src 'self'; style-src 'self';"

# ---------------------------
# PDF Class with UTF-8 Support
# ---------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("DejaVuSans", size=14)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Please enter a valid URL including http:// or https://")
    else:
        st.info("🔍 Crawling website...")
        pages, forms = crawl(url)
        st.success(f"Found {len(pages)} pages and {len(forms)} forms!")

        scan_results = []
        lock = threading.Lock()

        # Containers
        page_container = st.container()
        progress_bar = st.progress(0)
        total_pages = len(pages)
        progress = {"completed": 0}

        def scan_page(page):
            page_res = {
                "page": page,
                "SQLi": None,
                "XSS": None,
                "AI": None,
                "CSP": None
            }

            page_res["SQLi"] = (
                "⚠️ Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
            )
            page_res["XSS"] = (
                "⚠️ Possible XSS" if test_xss(page) else "No XSS"
            )

            try:
                response = requests.get(page, timeout=5)
                page_res["AI"] = analyze_response(response.text)
            except:
                page_res["AI"] = "Failed AI"

            try:
                resp = requests.get(page, timeout=5)
                csp_header = resp.headers.get("Content-Security-Policy", "")
                page_res["CSP"] = evaluate_csp_header(csp_header)
            except:
                page_res["CSP"] = "Failed CSP check"

            with lock:
                scan_results.append(page_res)
                progress["completed"] += 1
                progress_bar.progress(progress["completed"] / total_pages)

            with page_container:
                st.write(f"### Page: {page}")
                st.json(page_res)

        threads = []
        for pg in pages:
            t = threading.Thread(target=scan_page, args=(pg,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        st.write("📝 Testing forms…")
        for frm in forms:
            res = test_form(frm)
            st.write(f"Form on {frm['page']}:")
            st.json(res)
            scan_results.append({"page": frm['page'], "form_result": res})

        # ---------------------------
        # Generate UTF-8 PDF
        # ---------------------------
        pdf = PDF()
        pdf.add_page()

        # Load Unicode font (e.g., DejaVu Sans)
        pdf.add_font("DejaVuSans", "", "fonts/DejaVuSans.ttf", uni=True)
        pdf.set_font("DejaVuSans", size=12)

        for item in scan_results:
            # Write each result
            pdf.multi_cell(0, 8, str(item))
            pdf.ln(3)

        fname = "scan_report_utf8.pdf"
        pdf.output(fname)

        st.success("✅ Scanning complete!")
        with open(fname, "rb") as f:
            st.download_button("Download UTF-8 PDF Report", f, file_name=fname)

# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss, test_form
from ai_engine import analyze_response
import requests
import threading
from fpdf import FPDF

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (Unicode-safe)")

url = st.text_input("Enter your website URL (include https://)")

# ---------------------------
# CSP Evaluation Function
# ---------------------------
def evaluate_csp_header(csp_header: str):
    """
    Evaluate a CSP header string and return a security warning if weak.
    """
    if not csp_header:
        return "⚠️ No Content-Security-Policy header found"

    warnings = []
    csp = csp_header.lower()

    if "unsafe-inline" in csp:
        warnings.append("contains 'unsafe-inline'")
    if "unsafe-eval" in csp:
        warnings.append("contains 'unsafe-eval'")
    if "* " in csp or "*;" in csp:
        warnings.append("contains wildcard '*' in policy")
    if "script-src" not in csp and "default-src" not in csp:
        warnings.append("no script-src or default-src directive")

    if not warnings:
        return f"✅ Strong CSP: {csp_header}"
    return f"⚠️ Weak CSP ({', '.join(warnings)}): {csp_header}"

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

        # Store results for PDF
        scan_results = []
        lock = threading.Lock()

        # Container for real-time updates
        page_container = st.container()
        progress_bar = st.progress(0)
        total_pages = len(pages)
        progress = {"completed": 0}  # mutable dict for thread-safe counting

        # ---------------------------
        # Page Scanning Function
        # ---------------------------
        def scan_page(page):
            page_result = {"page": page, "SQLi": None, "XSS": None, "AI": None, "CSP": None}

            # SQLi test
            page_result["SQLi"] = "⚠️ Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
            # XSS test
            page_result["XSS"] = "⚠️ Possible XSS" if test_xss(page) else "No XSS"

            # AI business logic analysis
            try:
                response = requests.get(page, timeout=5)
                page_result["AI"] = analyze_response(response.text)
            except:
                page_result["AI"] = "Failed AI analysis"

            # CSP header evaluation
            try:
                resp = requests.get(page, timeout=5)
                csp_header = resp.headers.get("Content-Security-Policy", "")
                page_result["CSP"] = evaluate_csp_header(csp_header)
            except:
                page_result["CSP"] = "Failed to fetch page for CSP"

            # Append results and update progress safely
            with lock:
                scan_results.append(page_result)
                progress["completed"] += 1
                progress_bar.progress(progress["completed"] / total_pages)

            # Display per-page results
            with page_container:
                st.write(f"### Page: {page}")
                st.json(page_result)

        # ---------------------------
        # Start Multi-threaded Scan
        # ---------------------------
        threads = []
        for page in pages:
            t = threading.Thread(target=scan_page, args=(page,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        # ---------------------------
        # Form Testing
        # ---------------------------
        st.write("📝 Testing forms...")
        for form in forms:
            result = test_form(form)
            st.write(f"Form on {form['page']}:")
            st.json(result)
            scan_results.append({"page": form['page'], "form_result": result})

        # ---------------------------
        # Generate Unicode-safe PDF
        # ---------------------------
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        pdf.set_font("Arial", size=12)

        for res in scan_results:
            pdf.ln(5)
            safe_text = str(res).encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 8, safe_text)

        pdf_file = "scan_report.pdf"
        pdf.output(pdf_file)

        st.success("✅ Scanning complete!")
        st.success(f"PDF report generated: {pdf_file}")
        with open(pdf_file, "rb") as f:
            st.download_button("Download PDF Report", f, file_name="scan_report.pdf")

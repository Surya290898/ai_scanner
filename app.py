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

if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Please enter a valid URL including http:// or https://")
    else:
        st.info("🔍 Crawling website...")
        pages, forms = crawl(url)
        st.success(f"Found {len(pages)} pages and {len(forms)} forms!")

        # Store results for PDF
        scan_results = []

        # Thread-safe list append
        lock = threading.Lock()

        def scan_page(page):
            page_result = {"page": page, "SQLi": None, "XSS": None, "AI": None}
            # SQLi test
            if test_sqli(page):
                page_result["SQLi"] = "⚠️ Possible SQL Injection"
            else:
                page_result["SQLi"] = "No SQL Injection"

            # XSS test
            if test_xss(page):
                page_result["XSS"] = "⚠️ Possible XSS"
            else:
                page_result["XSS"] = "No XSS"

            # AI analysis
            try:
                response = requests.get(page, timeout=5)
                page_result["AI"] = analyze_response(response.text)
            except:
                page_result["AI"] = "Failed AI analysis"

            # Append result safely
            with lock:
                scan_results.append(page_result)

            # Display on Streamlit
            st.write(f"Page: {page}")
            st.write(page_result)

        # Multi-threaded scanning
        threads = []
        for page in pages:
            t = threading.Thread(target=scan_page, args=(page,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        # Form testing
        st.write("📝 Testing forms...")
        for form in forms:
            result = test_form(form)
            st.write(f"Form on {form['page']}: {result}")
            scan_results.append({"page": form['page'], "form_result": result})

        # Generate PDF report (Unicode-safe)
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        pdf.set_font("Arial", size=12)

        for res in scan_results:
            pdf.ln(5)
            # Replace unsupported characters to avoid crash
            safe_text = str(res).encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 8, safe_text)

        pdf_file = "scan_report.pdf"
        pdf.output(pdf_file)
        st.success(f"✅ PDF report generated: {pdf_file}")
        with open(pdf_file, "rb") as f:
            st.download_button("Download PDF Report", f, file_name="scan_report.pdf")

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
        lock = threading.Lock()

        # Container for real-time updates
        page_container = st.container()
        progress_bar = st.progress(0)
        total_pages = len(pages)
        completed_pages = 0

        def scan_page(page):
            nonlocal completed_pages
            page_result = {"page": page, "SQLi": None, "XSS": None, "AI": None}

            # SQLi test
            page_result["SQLi"] = "⚠️ Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
            # XSS test
            page_result["XSS"] = "⚠️ Possible XSS" if test_xss(page) else "No XSS"

            # AI analysis
            try:
                response = requests.get(page, timeout=5)
                page_result["AI"] = analyze_response(response.text)
            except:
                page_result["AI"] = "Failed AI analysis"

            # Append result safely
            with lock:
                scan_results.append(page_result)
                completed_pages += 1
                progress_bar.progress(completed_pages / total_pages)

            # Display dynamically
            with page_container:
                st.write(f"### Page: {page}")
                st.json(page_result)

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
            st.write(f"Form on {form['page']}:")
            st.json(result)
            scan_results.append({"page": form['page'], "form_result": result})

        # Generate Unicode-safe PDF report
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

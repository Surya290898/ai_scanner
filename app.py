# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss
from datetime import datetime
import threading
import requests
from fpdf import FPDF
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from PIL import Image
import io
import os

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 Website Security Scanner")

url = st.text_input("Enter your website URL (include https://)")

# ------------------------------
# Safe PDF Text
# ------------------------------
def safe_text(text):
    if not text:
        return ""
    text = str(text)
    replacements = {"⚠️": "WARNING:", "✅": "OK:", "—": "-", "…": "..."}
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")

# ------------------------------
# CSP Evaluation
# ------------------------------
def evaluate_csp_header(csp_header: str):
    if not csp_header:
        return "No CSP header found"
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

# ------------------------------
# Severity Logic
# ------------------------------
def severity_label(issue_type, result):
    if not result or "No" in str(result):
        return "None"
    if issue_type in ["SQLi", "XSS"]:
        return "High"
    if issue_type == "CSP":
        return "Medium"
    return "Low"

def severity_color(sev):
    if sev == "High": return (255, 0, 0)
    if sev == "Medium": return (255, 140, 0)
    if sev == "Low": return (0, 128, 0)
    return (0, 0, 0)

# ------------------------------
# PDF Class
# ------------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# ------------------------------
# Screenshot Function
# ------------------------------
def capture_screenshot(target_url):
    """Capture full-page screenshot of a URL with Selenium"""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(1200, 2000)
        driver.get(target_url)
        screenshot = driver.get_screenshot_as_png()
        driver.quit()
        return screenshot
    except:
        return None

# ------------------------------
# Scan Button
# ------------------------------
if st.button("Scan"):
    if not url.startswith("http"):
        st.error("Enter a valid URL including https://")
        st.stop()

    st.info("Crawling website...")
    pages, _ = crawl(url)
    st.success(f"Found {len(pages)} pages!")

    scan_results = []
    lock = threading.Lock()
    progress_bar = st.progress(0)
    total_pages = len(pages)

    def scan_page(page_url):
        page_res = {"page": page_url}

        page_res["SQLi"] = "Possible SQL Injection" if test_sqli(page_url) else "No SQL Injection"
        page_res["XSS"] = "Possible XSS" if test_xss(page_url) else "No XSS"

        # CSP Header
        try:
            resp = requests.get(page_url, timeout=5)
            csp_header = resp.headers.get("Content-Security-Policy", "")
            page_res["CSP"] = evaluate_csp_header(csp_header)
        except:
            page_res["CSP"] = "CSP check failed"

        # Screenshot evidence
        screenshot = capture_screenshot(page_url)
        page_res["Screenshot"] = screenshot

        with lock:
            scan_results.append(page_res)
            progress_bar.progress(len(scan_results)/total_pages)

        st.write(f"Scanned: {page_url}")
        st.json({k:v for k,v in page_res.items() if k!="Screenshot"})

    # Multithreading scan
    threads = []
    for pg in pages:
        t = threading.Thread(target=scan_page, args=(pg,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # ------------------------------
    # PDF Generation
    # ------------------------------
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Cover Page
    pdf.add_page()
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "Website Security Scanner Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Target URL: {safe_text(url)}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)

    # Summary
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Summary of Findings", ln=True)
    pdf.ln(5)

    high = medium = low = 0
    for item in scan_results:
        for k, v in item.items():
            if k in ["page", "Screenshot"]:
                continue
            sev = severity_label(k, v)
            if sev=="High": high+=1
            elif sev=="Medium": medium+=1
            elif sev=="Low": low+=1

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Pages Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0, 8, f"High Severity: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity: {medium}", ln=True)
    pdf.cell(0, 8, f"Low Severity: {low}", ln=True)

    # Detailed Findings
    for item in scan_results:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(5)

        # Table style
        pdf.set_font("Arial", "B", 12)
        col_widths = [50, 30, 110]
        pdf.set_fill_color(200, 200, 200)
        pdf.cell(col_widths[0], 8, "Vulnerability", border=1, fill=True)
        pdf.cell(col_widths[1], 8, "Severity", border=1, fill=True)
        pdf.cell(col_widths[2], 8, "Details", border=1, fill=True, ln=True)

        pdf.set_font("Arial", "", 11)
        for k, v in item.items():
            if k in ["page", "Screenshot"]:
                continue
            sev = severity_label(k, v)
            r, g, b = severity_color(sev)
            pdf.set_text_color(r, g, b)
            pdf.cell(col_widths[0], 8, k, border=1)
            pdf.cell(col_widths[1], 8, sev, border=1)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(col_widths[2], 8, safe_text(v), border=1)
        pdf.ln(3)

        # Screenshot embedding
        if item.get("Screenshot"):
            try:
                image = Image.open(io.BytesIO(item["Screenshot"]))
                temp_path = f"screenshot_{hash(item['page'])}.png"
                image.save(temp_path)
                pdf.image(temp_path, w=180)
                pdf.ln(5)
                os.remove(temp_path)
            except Exception as e:
                print(f"Screenshot error: {e}")

    # Output PDF
    filename = "scan_report.pdf"
    pdf.output(filename)
    st.success("Scan Complete!")

    with open(filename, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=filename)

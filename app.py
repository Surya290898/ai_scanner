# app.py
import streamlit as st
from crawler import crawl
from scanner import test_sqli, test_xss
from datetime import datetime
import threading
import os
import io
from fpdf import FPDF
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("🛡 AI Website Security Scanner (Screenshot + PDF)")

url = st.text_input("Enter your website URL (include https://)")

# ===============================
# Safe PDF text
# ===============================
def safe_text(text):
    if not text:
        return ""
    text = str(text)
    replacements = {"⚠️": "WARNING:", "✅": "OK:", "—": "-", "…": "..."}
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
    if "unsafe-inline" in csp:
        warnings.append("Uses unsafe-inline")
    if "unsafe-eval" in csp:
        warnings.append("Uses unsafe-eval")
    if "*" in csp:
        warnings.append("Uses wildcard *")
    if "script-src" not in csp and "default-src" not in csp:
        warnings.append("Missing script-src/default-src")
    return "Strong CSP configuration" if not warnings else "Weak CSP: " + ", ".join(warnings)

# ===============================
# Severity
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
    if sev == "High": return (255,0,0)
    if sev == "Medium": return (255,140,0)
    if sev == "Low": return (0,128,0)
    return (0,0,0)

# ===============================
# PDF Class
# ===============================
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "AI Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# ===============================
# Screenshot Function
# ===============================
def capture_screenshot(target_url):
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(target_url)
        img = driver.get_screenshot_as_png()
    except:
        img = None
    driver.quit()
    return img

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

    def scan_page(page):
        page_res = {"page": page}

        page_res["SQLi"] = "Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        page_res["XSS"] = "Possible XSS" if test_xss(page) else "No XSS"

        # Capture screenshot evidence
        screenshot = capture_screenshot(page)
        page_res["Screenshot"] = screenshot

        # CSP evaluation
        try:
            import requests
            resp = requests.get(page, timeout=5)
            csp_header = resp.headers.get("Content-Security-Policy", "")
            page_res["CSP"] = evaluate_csp_header(csp_header)
        except:
            page_res["CSP"] = "CSP check failed"

        with lock:
            scan_results.append(page_res)
            progress_bar.progress(len(scan_results)/total_pages)

        st.write(f"Scanned: {page}")
        st.json({k:v for k,v in page_res.items() if k != "Screenshot"})

    threads = []
    for pg in pages:
        t = threading.Thread(target=scan_page, args=(pg,))
        t.start()
        threads.append(t)
    for t in threads: t.join()

    # ===============================
    # PDF Generation
    # ===============================
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    temp_screenshots = []

    # --- Cover ---
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
    pdf.cell(0,10,"Executive Summary", ln=True)
    pdf.ln(5)
    high = medium = low = 0
    for item in scan_results:
        for k,v in item.items():
            if k in ["page","Screenshot"]: continue
            sev = severity_label(k,v)
            if sev=="High": high+=1
            elif sev=="Medium": medium+=1
            elif sev=="Low": low+=1
    pdf.set_font("Arial","",12)
    pdf.cell(0,8,f"Total Pages Scanned: {len(scan_results)}", ln=True)
    pdf.cell(0,8,f"High Severity Issues: {high}", ln=True)
    pdf.cell(0,8,f"Medium Severity Issues: {medium}", ln=True)
    pdf.cell(0,8,f"Low Severity Issues: {low}", ln=True)

    # --- Detailed Findings ---
    for item in scan_results:
        pdf.add_page()
        pdf.set_font("Arial","B",14)
        pdf.cell(0,10,f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(5)

        # Table header
        pdf.set_font("Arial","B",12)
        col_widths = [50,30,110]
        pdf.set_fill_color(200,200,200)
        pdf.cell(col_widths[0],8,"Vulnerability", border=1, fill=True)
        pdf.cell(col_widths[1],8,"Severity", border=1, fill=True)
        pdf.cell(col_widths[2],8,"Details", border=1, fill=True, ln=True)

        pdf.set_font("Arial","",11)
        for k,v in item.items():
            if k in ["page","Screenshot"]: continue
            sev = severity_label(k,v)
            r,g,b = severity_color(sev)
            pdf.set_text_color(r,g,b)
            pdf.cell(col_widths[0],8,k,border=1)
            pdf.cell(col_widths[1],8,sev,border=1)
            pdf.set_text_color(0,0,0)
            pdf.multi_cell(col_widths[2],8,safe_text(v),border=1)
        pdf.ln(3)

        # Add screenshot
        if item.get("Screenshot"):
            try:
                img = Image.open(io.BytesIO(item["Screenshot"]))
                max_width = 180
                w,h = img.size
                if w>max_width:
                    ratio = max_width / w
                    w = max_width
                    h = int(h*ratio)
                temp_path = f"screenshot_{hash(item['page'])}.png"
                img.save(temp_path)
                temp_screenshots.append(temp_path)
                pdf.image(temp_path, w=w, h=h)
                pdf.ln(5)
            except Exception as e:
                print(f"Screenshot embed error: {e}")

    # Remove temp screenshots
    for path in temp_screenshots:
        if os.path.exists(path):
            os.remove(path)

    filename="scan_report.pdf"
    pdf.output(filename)
    st.success("Scan Complete!")

    with open(filename,"rb") as f:
        st.download_button("Download PDF Report", f, file_name=filename)

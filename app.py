# app.py
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import streamlit as st
from fpdf import FPDF

from ai_engine import analyze_response
from crawler import crawl

# Robust import (handles stale module caches during hot reload)
try:
    from scanner import (
        headers_analyzer,
        test_sqli,
        test_xss,
        test_form,
        graphql_probe,
        openapi_fetch_and_lint
    )
except Exception:
    import importlib, scanner as _scanner
    importlib.reload(_scanner)
    headers_analyzer = getattr(_scanner, "headers_analyzer")
    test_sqli = getattr(_scanner, "test_sqli")
    test_xss = getattr(_scanner, "test_xss")
    test_form = getattr(_scanner, "test_form")
    graphql_probe = getattr(_scanner, "graphql_probe")
    openapi_fetch_and_lint = getattr(_scanner, "openapi_fetch_and_lint")

st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("AI Website Security Scanner")

# ------------------------------------
# Helpers
# ------------------------------------
def safe_text(text, max_len=500):
    """Convert any text to PDF-safe ASCII text and truncate."""
    if not text:
        return ""
    text = str(text)
    replacements = {"—": "-", "…": "..."}
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Keep to latin-1 to avoid font issues with core PDF fonts
    text = text.encode("latin-1", "replace").decode("latin-1")
    if len(text) > max_len:
        text = text[:max_len] + " ..."
    return text

def _wrap_long_tokens(s: str, max_token_len: int = 30) -> str:
    """
    Insert newlines into very long unbroken tokens so fpdf2 can wrap them.
    Using conservative 30 chars to avoid any width overflow.
    """
    if not s:
        return ""
    out_parts = []
    for tok in s.split():
        if len(tok) > max_token_len:
            chunks = [tok[i:i+max_token_len] for i in range(0, len(tok), max_token_len)]
            out_parts.append("\n".join(chunks))
        else:
            out_parts.append(tok)
    return " ".join(out_parts)

def pdf_block_text(s: str, max_len: int = 8000) -> str:
    """
    Make text PDF-safe (latin-1) and also wrap long tokens to avoid FPDFException.
    """
    return _wrap_long_tokens(safe_text(s, max_len=max_len))

def safe_multicell(pdf: FPDF, w: float, h: float, text: str, **kwargs):
    """
    Wrapper around pdf.multi_cell that:
      - resets X to left margin (fresh line),
      - uses the effective page width if w<=0,
      - pre-wraps long tokens,
      - and on any FPDFException, falls back to hard 30-char line breaks.
    """
    # Compute a safe effective width
    try:
        epw = getattr(pdf, "epw", pdf.w - pdf.l_margin - pdf.r_margin)
    except Exception:
        epw = pdf.w - pdf.l_margin - pdf.r_margin
    if not w or w <= 0:
        w = epw

    # Ensure we start at left margin (so "remaining width" logic never applies)
    try:
        pdf.set_x(pdf.l_margin)
    except Exception:
        pass

    # Prepare text
    prepared = pdf_block_text(text, max_len=8000)
    if not prepared.strip():
        prepared = " "

    # Primary attempt
    try:
        pdf.multi_cell(w, h, prepared, **kwargs)
        return
    except Exception:
        # Fallback: very conservative line splitting
        s = safe_text(text, max_len=8000)
        step = 30
        try:
            pdf.set_x(pdf.l_margin)
        except Exception:
            pass
        for i in range(0, len(s), step):
            chunk = s[i:i+step]
            if not chunk.strip():
                chunk = " "
            pdf.multi_cell(w, h, chunk, **kwargs)

def sev_color(sev: str):
    if sev == "High":
        return (255, 0, 0)
    if sev == "Medium":
        return (255, 140, 0)
    if sev == "Low":
        return (0, 128, 0)
    return (0, 0, 0)

class PDF(FPDF):
    # Use core fonts only to avoid registration issues (Helvetica)
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "Website Security Scan Report", ln=True, align="C")
        self.ln(5)

# ------------------------------------
# UI
# ------------------------------------
with st.sidebar:
    st.subheader("Discovery & Checks")
    do_discovery = st.checkbox("Use internet-assisted discovery (robots/sitemap/Wayback/crt.sh)", value=True)
    do_headers = st.checkbox("Analyze security headers (CSP/HSTS/CORS/etc.)", value=True)
    do_graphql = st.checkbox("Probe GraphQL endpoints (introspection)", value=True)
    do_openapi = st.checkbox("Fetch & basic-lint OpenAPI docs", value=True)
    do_forms = st.checkbox("Test discovered forms for XSS (safe payload)", value=True)
    do_ai = st.checkbox("AI-style page review (local heuristics)", value=True)
    st.caption("All operations use simple HTTP requests with timeouts. No external AI services.")

url = st.text_input("Enter your website URL (include https://)")

if st.button("Scan"):
    if not url or not url.startswith(("http://", "https://")):
        st.error("Please enter a valid URL including http:// or https://")
        st.stop()

    # ------------------------------------
    # Discovery & Crawl
    # ------------------------------------
    st.info("Crawling and discovering endpoints...")
    pages, forms, discovery = crawl(url)
    st.success(f"Crawl complete. Pages: {len(pages)} | Forms: {len(forms)} | OpenAPI: {len(discovery.get('openapi_docs', []))} | GraphQL: {len(discovery.get('graphql_endpoints', []))}")

    if do_discovery:
        with st.expander("Discovery Results"):
            st.write("**robots/sitemap seeds**", discovery.get("robots_seeds", []))
            st.write("**sitemaps**", discovery.get("sitemaps", []))
            st.write("**historical (Wayback)**", discovery.get("historical_urls", []))
            st.write("**subdomains (crt.sh)**", discovery.get("subdomains", []))
            st.write("**OpenAPI docs**", discovery.get("openapi_docs", []))
            st.write("**GraphQL endpoints**", discovery.get("graphql_endpoints", []))
            st.write("**Detected JS libraries**", discovery.get("js_libs", []))

    # ------------------------------------
    # Page scanning (headers + heuristics + simple SQLi/XSS probes)
    # ------------------------------------
    st.info("Scanning pages...")
    progress = st.progress(0)
    results = []

    def scan_single(page: str):
        item = {"page": page}
        # Header analysis
        if do_headers:
            item["headers"] = headers_analyzer(page)
        # Simple param fuzz (URL-only)
        item["sqli"] = "Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        item["xss"] = "Possible XSS" if test_xss(page) else "No XSS"

        # AI-style local analysis on actual GET response
        if do_ai:
            try:
                r = requests.get(page, timeout=8)
                a = analyze_response(r.text, r.headers, page)
                item["ai_findings"] = a
            except Exception:
                item["ai_findings"] = {"status": "analysis failed"}
        return item

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(scan_single, p) for p in pages]
        done = 0
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            progress.progress(int(100 * done / max(1, len(pages))))

    st.success("Page scanning done.")
    if results:
        st.write("Sample page result:", results[0])

    # ------------------------------------
    # Forms testing
    # ------------------------------------
    form_results = []
    if do_forms and forms:
        st.info("Testing forms (safe XSS checks)...")
        for f in forms[:50]:  # cap
            form_results.append({"form": f, "result": test_form(f)})
        st.success(f"Forms tested: {len(form_results)}")

    # ------------------------------------
    # GraphQL probes
    # ------------------------------------
    gql_results = []
    if do_graphql and discovery.get("graphql_endpoints"):
        st.info("Probing GraphQL endpoints...")
        for ep in discovery.get("graphql_endpoints", []):
            gql_results.append(graphql_probe(ep))
        st.success("GraphQL probing complete.")

    # ------------------------------------
    # OpenAPI basic lint
    # ------------------------------------
    openapi_results = []
    if do_openapi and discovery.get("openapi_docs"):
        st.info("Fetching and linting OpenAPI docs (basic checks)...")
        for doc in discovery.get("openapi_docs", [])[:10]:
            openapi_results.append(openapi_fetch_and_lint(doc))
        st.success("OpenAPI checks complete.")

    # ------------------------------------
    # Build PDF
    # ------------------------------------
    st.info("Generating PDF report...")
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Cover
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "Website Security Scan Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, f"Target URL: {safe_text(url)}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)

    # Executive Summary
    high = medium = 0
    for item in results:
        if item.get("sqli") == "Possible SQL Injection" or item.get("xss") == "Possible XSS":
            high += 1
        ai = item.get("ai_findings")
        if isinstance(ai, list):
            for f in ai:
                sev = (f.get("severity") or "").strip()
                if sev == "High":
                    high += 1
                elif sev == "Medium":
                    medium += 1

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, f"Total Pages Scanned: {len(results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Findings: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Findings: {medium}", ln=True)
    pdf.ln(4)
    safe_multicell(
        pdf, 0, 6,
        "Discovery: "
        f"OpenAPI={len(discovery.get('openapi_docs', []))}, "
        f"GraphQL={len(discovery.get('graphql_endpoints', []))}, "
        f"Historical={len(discovery.get('historical_urls', []))}, "
        f"Subdomains={len(discovery.get('subdomains', []))}"
    )

    # Detailed: Pages
    for item in results[:200]:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(2)

        # Simple probes
        pdf.set_font("Helvetica", "B", 12)
        sev = "High" if item.get("sqli") == "Possible SQL Injection" else "None"
        pdf.set_text_color(*sev_color("High" if sev == "High" else "None"))
        pdf.cell(0, 8, f"SQLi: {item.get('sqli')}", ln=True)

        sev = "High" if item.get("xss") == "Possible XSS" else "None"
        pdf.set_text_color(*sev_color("High" if sev == "High" else "None"))
        pdf.cell(0, 8, f"XSS: {item.get('xss')}", ln=True)
        pdf.set_text_color(0, 0, 0)

        # Headers
        h = item.get("headers", {})
        if h:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Header Analysis:", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(h, indent=2))

        # AI-style findings
        af = item.get("ai_findings")
        if isinstance(af, list) and af:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "AI-style Findings:", ln=True)
            for f in af:
                sev = f.get("severity", "Low")
                pdf.set_text_color(*sev_color(sev))
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 6, f"- {safe_text(f.get('type'))} (Severity: {sev})", ln=True)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Helvetica", "", 11)
                safe_multicell(pdf, 0, 5, f"Description: {f.get('description', '')}")
                safe_multicell(pdf, 0, 5, f"Impact: {f.get('impact', '')}")
                safe_multicell(pdf, 0, 5, f"Remediation: {f.get('remediation', '')}")
                pdf.ln(1)
        elif isinstance(af, dict):
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(af, indent=2))

    # Forms section
    if form_results:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Forms Testing", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for fr in form_results[:100]:
            safe_multicell(pdf, 0, 6, json.dumps(fr, indent=2))
            pdf.ln(1)

    # OpenAPI section
    if openapi_results:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "OpenAPI Checks (Basic)", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for oa in openapi_results:
            safe_multicell(pdf, 0, 6, json.dumps(oa, indent=2))
            pdf.ln(1)

    # GraphQL section
    if gql_results:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "GraphQL Probes", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for g in gql_results:
            safe_multicell(pdf, 0, 6, json.dumps(g, indent=2))
            pdf.ln(1)

    filename = "scan_report.pdf"
    try:
        pdf.output(filename)
        st.success("Scan Complete!")
        with open(filename, "rb") as f:
            st.download_button("Download PDF Report", f, file_name=filename)
    except Exception as e:
        st.error(f"Failed to generate PDF: {e}")

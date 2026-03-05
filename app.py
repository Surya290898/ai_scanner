# app.py
# --- ensure local package directory is first on sys.path
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
import streamlit as st
from fpdf import FPDF

from ai_engine import analyze_response
from crawler import crawl

# Robust import (handles stale module caches / name collisions)
try:
    from scanner import (
        # classic checks
        headers_analyzer, test_sqli, test_xss, test_form,
        graphql_probe, openapi_fetch_and_lint,
        cors_tests, redirect_chain,
        analyze_cookies_from_headers, find_mixed_content,
        # NEW: authentication security audit (safe mode)
        auth_security_audit,
    )
except Exception:
    import importlib, scanner as _scanner
    _scanner = importlib.reload(_scanner)
    headers_analyzer = getattr(_scanner, "headers_analyzer")
    test_sqli = getattr(_scanner, "test_sqli")
    test_xss = getattr(_scanner, "test_xss")
    test_form = getattr(_scanner, "test_form")
    graphql_probe = getattr(_scanner, "graphql_probe")
    openapi_fetch_and_lint = getattr(_scanner, "openapi_fetch_and_lint")
    cors_tests = getattr(_scanner, "cors_tests")
    redirect_chain = getattr(_scanner, "redirect_chain")
    analyze_cookies_from_headers = getattr(_scanner, "analyze_cookies_from_headers")
    find_mixed_content = getattr(_scanner, "find_mixed_content")
    auth_security_audit = getattr(_scanner, "auth_security_audit")

# -------------- Streamlit page setup --------------
st.set_page_config(page_title="AI Website Security Scanner", layout="wide")
st.title("AI Website Security Scanner")

# ------------------------------------
# Helpers
# ------------------------------------
def safe_text(text, max_len=500):
    if not text:
        return ""
    text = str(text)
    replacements = {"—": "-", "…": "..."}
    for k, v in replacements.items():
        text = text.replace(k, v)
    text = text.encode("latin-1", "replace").decode("latin-1")
    if len(text) > max_len:
        text = text[:max_len] + " ..."
    return text

def _wrap_long_tokens(s: str, max_token_len: int = 30) -> str:
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
    return _wrap_long_tokens(safe_text(s, max_len=max_len))

def safe_multicell(pdf: FPDF, w: float, h: float, text: str, **kwargs):
    try:
        epw = getattr(pdf, "epw", pdf.w - pdf.l_margin - pdf.r_margin)
    except Exception:
        epw = pdf.w - pdf.l_margin - pdf.r_margin
    if not w or w <= 0:
        w = epw
    try:
        pdf.set_x(pdf.l_margin)
    except Exception:
        pass
    prepared = pdf_block_text(text, max_len=8000)
    if not prepared.strip():
        prepared = " "
    try:
        pdf.multi_cell(w, h, prepared, **kwargs)
        return
    except Exception:
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
    if sev == "High": return (255, 0, 0)
    if sev == "Medium": return (255, 140, 0)
    if sev == "Low": return (0, 128, 0)
    return (0, 0, 0)

class PDF(FPDF):
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
    do_headers   = st.checkbox("Analyze security headers (CSP/HSTS/CORS/etc.)", value=True)
    do_graphql   = st.checkbox("Probe GraphQL endpoints (introspection)", value=True)
    do_openapi   = st.checkbox("Fetch & basic-lint OpenAPI docs", value=True)
    do_forms     = st.checkbox("Test discovered forms for XSS (safe payload)", value=True)
    do_ai        = st.checkbox("AI-style page review (local heuristics)", value=True)

    st.markdown("---")
    st.subheader("Authentication Security Auditor")
    do_auth_audit = st.checkbox("Run Authentication Security Auditor (safe mode)", value=True)

    st.markdown("---")
    st.subheader("Other utilities")
    do_cors      = st.checkbox("CORS tests (preflight + simple)", value=False)
    do_redirects = st.checkbox("Redirect tests (full chain)", value=False)
    do_cookies   = st.checkbox("Cookie security (Set-Cookie flags)", value=False)
    do_mixed     = st.checkbox("Mixed content checks (local)", value=False)

url = st.text_input("Enter your website URL (include https://)")
st.caption("Auth Auditor is non-intrusive: it checks CSRF/HTTPS/session/captcha/lockout/username-enum *signals* with strict caps—no brute‑forcing or exploit attempts.")

# ------------------------------------
# Main workflow
# ------------------------------------
if st.button("Scan"):
    if not url or not url.startswith(("http://", "https://")):
        st.error("Please enter a valid URL including http:// or https://")
        st.stop()

    parsed = urlparse(url)
    host = parsed.hostname or url

    # Discovery & Crawl
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

    # Page scanning
    st.info("Scanning pages...")
    progress = st.progress(0)
    results = []

    def scan_single(page: str):
        item = {"page": page}
        if do_headers:
            item["headers"] = headers_analyzer(page)
        item["sqli"] = "Possible SQL Injection" if test_sqli(page) else "No SQL Injection"
        item["xss"]  = "Possible XSS"          if test_xss(page)  else "No XSS"

        if do_ai or do_cookies or do_mixed:
            try:
                r = requests.get(page, timeout=10)
                a = analyze_response(r.text, r.headers, page) if do_ai else None
                item["ai_findings"] = a if do_ai else None
                if do_cookies:
                    item["cookies"] = analyze_cookies_from_headers(r.headers.get("set-cookie", ""))
                if do_mixed:
                    item["mixed_content_snippets"] = find_mixed_content(r.text) if page.startswith("https://") else []
            except Exception:
                if do_ai:
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

    # Forms testing
    form_results = []
    if do_forms and forms:
        st.info("Testing forms (safe XSS checks)...")
        for f in forms[:50]:
            form_results.append({"form": f, "result": test_form(f)})
        st.success(f"Forms tested: {len(form_results)}")

    # GraphQL probes
    gql_results = []
    if discovery.get("graphql_endpoints") and do_graphql:
        st.info("Probing GraphQL endpoints...")
        for ep in discovery.get("graphql_endpoints", []):
            gql_results.append(graphql_probe(ep))
        st.success("GraphQL probing complete.")

    # OpenAPI basic lint
    openapi_results = []
    if do_openapi and discovery.get("openapi_docs"):
        st.info("Fetching and linting OpenAPI docs (basic checks)...")
        for doc in discovery.get("openapi_docs", [])[:10]:
            openapi_results.append(openapi_fetch_and_lint(doc))
        st.success("OpenAPI checks complete.")

    # -------------------------------
    # Authentication Security Auditor
    # -------------------------------
    auth_audit = {}
    if do_auth_audit:
        st.info("Running Authentication Security Auditor (safe mode)...")
        try:
            auth_audit = auth_security_audit(url, pages)
        except Exception as e:
            auth_audit = {"error": f"auth audit failed: {e}"}
        st.success("Authentication audit complete.")

    # CORS & Redirects
    cors_out = {}
    redirects = []
    if do_cors:
        st.info("Running CORS tests...")
        cors_out = cors_tests(url, test_origin="https://example.com")
        st.success("CORS tests complete.")
    if do_redirects:
        st.info("Tracing redirect chain...")
        redirects = redirect_chain(url)
        st.success("Redirect tracing complete.")

    # Build PDF
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
                if sev == "High":   high += 1
                elif sev == "Medium": medium += 1

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, f"Total Pages Scanned: {len(results)}", ln=True)
    pdf.cell(0, 8, f"High Severity Findings: {high}", ln=True)
    pdf.cell(0, 8, f"Medium Severity Findings: {medium}", ln=True)

    # Auth score (if available)
    if do_auth_audit and isinstance(auth_audit, dict) and auth_audit.get("score") is not None:
        pdf.cell(0, 8, f"Authentication Security Score: {auth_audit['score']}/100", ln=True)

    pdf.ln(4)
    safe_multicell(
        pdf, 0, 6,
        "Discovery: "
        f"OpenAPI={len(discovery.get('openapi_docs', []))}, "
        f"GraphQL={len(discovery.get('graphql_endpoints', []))}, "
        f"Historical={len(discovery.get('historical_urls', []))}, "
        f"Subdomains={len(discovery.get('subdomains', []))}"
    )

    # Authentication Audit Section
    if do_auth_audit:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Authentication Security Auditor (Safe Mode)", ln=True)
        pdf.set_font("Helvetica", "", 11)
        safe_multicell(pdf, 0, 6,
            "Assesses CSRF/HTTPS/session flags, login behavior, username‑enum hints, lockout/rate‑limit signals, "
            "MFA/password policy/session/log‑out CSRF hints, sensitive endpoints and API auth misconfig—all non‑intrusively.")
        safe_multicell(pdf, 0, 6, json.dumps(auth_audit, indent=2))

    # Detailed: Pages
    for item in results[:200]:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Page: {safe_text(item.get('page'))}", ln=True)
        pdf.ln(2)

        pdf.set_font("Helvetica", "B", 12)
        sev = "High" if item.get("sqli") == "Possible SQL Injection" else "None"
        pdf.set_text_color(*sev_color("High" if sev == "High" else "None"))
        pdf.cell(0, 8, f"SQLi: {item.get('sqli')}", ln=True)

        sev = "High" if item.get("xss") == "Possible XSS" else "None"
        pdf.set_text_color(*sev_color("High" if sev == "High" else "None"))
        pdf.cell(0, 8, f"XSS: {item.get('xss')}", ln=True)
        pdf.set_text_color(0, 0, 0)

        h = item.get("headers", {})
        if h:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Header Analysis:", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(h, indent=2))

        if item.get("cookies"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Cookie Security (Set-Cookie analysis):", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(item["cookies"], indent=2))

        if item.get("mixed_content_snippets"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Mixed Content Snippets (http:// on HTTPS page):", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(item["mixed_content_snippets"][:10], indent=2))

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
        elif isinstance(af, dict) and af:
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(af, indent=2))

    if do_cors and cors_out:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "CORS Tests", ln=True)
        pdf.set_font("Helvetica", "", 11)
        safe_multicell(pdf, 0, 6, json.dumps(cors_out, indent=2))

    if do_redirects and redirects:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Redirect Chain", ln=True)
        pdf.set_font("Helvetica", "", 11)
        safe_multicell(pdf, 0, 6, json.dumps(redirects, indent=2))

    filename = "scan_report.pdf"
    try:
        pdf.output(filename)
        st.success("Scan Complete!")
        with open(filename, "rb") as f:
            st.download_button("Download PDF Report", f, file_name=filename)
    except Exception as e:
        st.error(f"Failed to generate PDF: {e}")

    # In-app JSON views
    if do_auth_audit:
        with st.expander("Auth Auditor JSON"):
            st.json(auth_audit)

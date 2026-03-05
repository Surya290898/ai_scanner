# app.py
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
import streamlit as st
from fpdf import FPDF

from ai_engine import analyze_response
from crawler import crawl
from scanner import (
    headers_analyzer,
    test_sqli,
    test_xss,
    test_form,
    graphql_probe,
    openapi_fetch_and_lint,
    # new
    csper_evaluate_url,
    mozilla_observatory_scan,
    centralcsp_scan,
    securityheaders_scan,
    ssllabs_scan,
    cors_tests,
    redirect_chain,
    analyze_cookies_from_headers,
    find_mixed_content,
    correlate_csp
)

# -------------- Streamlit page setup --------------
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

    # Ensure we start at left margin
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

    st.markdown("---")
    st.subheader("Advanced Integrations")
    do_csp_external = st.checkbox("External CSP checks (Csper, Observatory, CentralCSP*)", value=True)
    do_headers_external = st.checkbox("HTTP header & config checks (Mozilla Observatory, SecurityHeaders*)", value=True)
    do_ssl_labs = st.checkbox("TLS/SSL checks (Qualys SSL Labs)", value=True)
    do_cors = st.checkbox("CORS tests (preflight + simple)", value=True)
    do_redirects = st.checkbox("Redirect tests (full chain)", value=True)
    do_cookies = st.checkbox("Cookie security (Secure/HttpOnly/SameSite)", value=True)
    do_mixed = st.checkbox("Mixed content checks (local + WhyNoPadlock link)", value=True)

    st.caption("* requires an API key that you can paste below if available.")

    st.markdown("**Optional API keys / settings**")
    sec_headers_key = st.text_input("securityheaders.com API key (optional)", type="password")
    centralcsp_key = st.text_input("CentralCSP API key (optional)", type="password")
    test_origin = st.text_input("CORS test Origin", value="https://example.com")

url = st.text_input("Enter your website URL (include https://)")

# ------------------------------------
# Main workflow
# ------------------------------------
if st.button("Scan"):
    if not url or not url.startswith(("http://", "https://")):
        st.error("Please enter a valid URL including http:// or https://")
        st.stop()

    parsed = urlparse(url)
    host = parsed.hostname or url

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
    if discovery.get("graphql_endpoints"):
        if do_graphql:
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
    # External / Advanced checks (single-host scope)
    # ------------------------------------
    csp_vendor = {}
    observatory = {}
    centralcsp = {}
    sec_headers = {}
    ssl_labs = {}
    cors_out = {}
    redirects = []

    if do_csp_external:
        st.info("Running external CSP checks...")
        try:
            csp_vendor = csper_evaluate_url(url)
        except Exception:
            csp_vendor = {}
        try:
            observatory = mozilla_observatory_scan(host, rescan=True)
        except Exception:
            observatory = {}
        try:
            centralcsp = centralcsp_scan(url, centralcsp_key) if centralcsp_key else {}
        except Exception:
            centralcsp = {}
        st.success("External CSP checks complete.")

    if do_headers_external:
        st.info("Running HTTP header & security config checks (Mozilla Observatory / SecurityHeaders)...")
        try:
            if not observatory:
                observatory = mozilla_observatory_scan(host, rescan=True)
        except Exception:
            pass
        try:
            sec_headers = securityheaders_scan(host, sec_headers_key) if sec_headers_key else {}
        except Exception:
            sec_headers = {}
        st.success("Header checks complete.")

    if do_ssl_labs:
        st.info("Running TLS/SSL checks with Qualys SSL Labs...")
        try:
            ssl_labs = ssllabs_scan(host, start_new=True)
        except Exception:
            ssl_labs = {}
        st.success("TLS/SSL checks complete.")

    if do_cors:
        st.info("Running CORS tests (preflight + simple)...")
        try:
            cors_out = cors_tests(url, test_origin=test_origin)
        except Exception:
            cors_out = {}
        st.success("CORS tests complete.")

    if do_redirects:
        st.info("Tracing redirect chain...")
        try:
            redirects = redirect_chain(url)
        except Exception:
            redirects = []
        st.success("Redirect tracing complete.")

    # Correlate CSP with local evaluator on the root page if available
    local_csp_summary = ""
    try:
        head_root = headers_analyzer(url)
        local_csp_summary = head_root.get("csp", "")
    except Exception:
        pass
    csp_summary = correlate_csp(csp_vendor, observatory, local_csp_summary, centralcsp)

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

    # CSP Correlated Summary
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "CSP Checks (Correlated Summary)", ln=True)
    pdf.set_font("Helvetica", "", 11)
    safe_multicell(pdf, 0, 6, f"Overall verdict: {csp_summary.get('overall')}")
    safe_multicell(pdf, 0, 6, f"Local evaluator: {local_csp_summary}")
    if csp_vendor:
        safe_multicell(pdf, 0, 6, "Csper.io Summary:")
        safe_multicell(pdf, 0, 6, json.dumps(csp_vendor, indent=2))
    if observatory:
        safe_multicell(pdf, 0, 6, "Mozilla Observatory (selected fields):")
        safe_multicell(pdf, 0, 6, json.dumps({"scan": observatory.get("scan", {})}, indent=2))
    if centralcsp:
        safe_multicell(pdf, 0, 6, "CentralCSP:")
        safe_multicell(pdf, 0, 6, json.dumps(centralcsp, indent=2))

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

        # Cookies
        if item.get("cookies"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Cookie Security (Set-Cookie analysis):", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(item["cookies"], indent=2))

        # Mixed content
        if item.get("mixed_content_snippets"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Mixed Content Snippets (http:// resources on HTTPS page):", ln=True)
            pdf.set_font("Helvetica", "", 11)
            safe_multicell(pdf, 0, 6, json.dumps(item["mixed_content_snippets"][:10], indent=2))

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
        elif isinstance(af, dict) and af:
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

    # External checks section
    if do_headers_external or do_ssl_labs or do_cors or do_redirects:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "External / Advanced Checks", ln=True)
        pdf.set_font("Helvetica", "", 11)
        if observatory:
            safe_multicell(pdf, 0, 6, "Mozilla Observatory (scan header):")
            safe_multicell(pdf, 0, 6, json.dumps(observatory.get("scan", {}), indent=2))
        if sec_headers:
            safe_multicell(pdf, 0, 6, "SecurityHeaders.com:")
            safe_multicell(pdf, 0, 6, json.dumps(sec_headers, indent=2))
        if ssl_labs:
            safe_multicell(pdf, 0, 6, "Qualys SSL Labs:")
            safe_multicell(pdf, 0, 6, json.dumps(ssl_labs, indent=2))
        if cors_out:
            safe_multicell(pdf, 0, 6, "CORS Tests:")
            safe_multicell(pdf, 0, 6, json.dumps(cors_out, indent=2))
        if redirects:
            safe_multicell(pdf, 0, 6, "Redirect Chain:")
            safe_multicell(pdf, 0, 6, json.dumps(redirects, indent=2))
        if do_mixed:
            safe_multicell(pdf, 0, 6, "Note: WhyNoPadlock is available via web UI; this report includes local mixed-content findings per page.")

    filename = "scan_report.pdf"
    try:
        pdf.output(filename)
        st.success("Scan Complete!")
        with open(filename, "rb") as f:
            st.download_button("Download PDF Report", f, file_name=filename)
    except Exception as e:
        st.error(f"Failed to generate PDF: {e}")

    # Also show quick dashboards in the app
    with st.expander("CSP (Correlated)"):
        st.json(csp_summary)
    if do_headers_external and observatory:
        with st.expander("Mozilla Observatory - Raw"):
            st.json(observatory)
    if do_ssl_labs and ssl_labs:
        with st.expander("SSL Labs - Raw"):
            st.json(ssl_labs)
    if do_cors and cors_out:
        with st.expander("CORS - Details"):
            st.json(cors_out)
    if do_redirects and redirects:
        with st.expander("Redirect Chain"):
            st.json(redirects)

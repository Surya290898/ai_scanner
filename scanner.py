# scanner.py
import json
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 12
UA = {"User-Agent": "AI-Security-Scanner/2.0 (+local)"}

# ------------------------------------
# Core simple tests (kept from your original)
# ------------------------------------
def test_sqli(url: str) -> bool:
    """Benign SQLi error heuristic."""
    payload = "' OR '1'='1"
    try:
        r = requests.get(url, params={"test": payload}, headers=UA, timeout=DEFAULT_TIMEOUT)
        body = (r.text or "").lower()
        return any(err in body for err in [
            "sql syntax", "mysql", "syntax error",
            "unclosed quotation mark", "odbc", "pdoexception"
        ])
    except Exception:
        return False

def test_xss(url: str) -> bool:
    """Simple XSS reflection check using HTML and encoded variants."""
    raw = "<script>alert(1)</script>"
    enc = "&lt;script&gt;alert(1)&lt;/script&gt;"
    try:
        r = requests.get(url, params={"test": raw}, headers=UA, timeout=DEFAULT_TIMEOUT)
        body = r.text or ""
        if raw in body or enc in body:
            return True
        r2 = requests.get(url, params={"test": enc}, headers=UA, timeout=DEFAULT_TIMEOUT)
        body2 = r2.text or ""
        return (raw in body2) or (enc in body2)
    except Exception:
        return False

def test_form(form: Dict) -> Dict:
    """Test a form for XSS on its input fields (safe payloads, GET/POST)."""
    url = form.get("action") or form.get("page")
    method = (form.get("method") or "get").lower()
    data = {}
    results = {}
    payload = "<script>alert(1)</script>"

    for name in form.get("inputs", []):
        try:
            data[name] = payload
            if method == "post":
                resp = requests.post(url, data=data, headers=UA, timeout=DEFAULT_TIMEOUT)
            else:
                resp = requests.get(url, params=data, headers=UA, timeout=DEFAULT_TIMEOUT)
            body = resp.text or ""
            if payload in body or "&lt;script&gt;alert(1)&lt;/script&gt;" in body:
                results[name] = "Possible XSS"
            else:
                results[name] = "No XSS"
        except Exception:
            results[name] = "Test failed"
        finally:
            data[name] = ""
    return results

# ------------------------------------
# Headers / Policy analyzers
# ------------------------------------
def csp_evaluator(csp_header: str) -> str:
    if not csp_header:
        return "No Content-Security-Policy header found"
    warnings = []
    csp = csp_header.lower()
    if "unsafe-inline" in csp:
        warnings.append("Uses unsafe-inline")
    if "unsafe-eval" in csp:
        warnings.append("Uses unsafe-eval")
    if "*" in csp and ("script-src" in csp or "default-src" in csp):
        warnings.append("Wildcard in script/default-src")
    if "script-src" not in csp and "default-src" not in csp:
        warnings.append("Missing script-src/default-src")
    if "frame-ancestors" not in csp:
        warnings.append("Missing frame-ancestors")
    return "Strong CSP configuration" if not warnings else "Weak CSP: " + ", ".join(warnings)

def headers_analyzer(url: str) -> Dict:
    """
    Fetch the URL and return a summarized view of security-relevant headers
    so the report can show CSP/HSTS/CORS/etc. for that page.
    """
    out: Dict = {}
    try:
        r = requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT)
        h = {k.lower(): v for k, v in r.headers.items()}
        out["status"] = r.status_code
        out["csp"] = csp_evaluator(h.get("content-security-policy", ""))
        out["x-frame-options"] = h.get("x-frame-options", "")
        out["hsts"] = h.get("strict-transport-security", "")
        out["referrer-policy"] = h.get("referrer-policy", "")
        out["x-content-type-options"] = h.get("x-content-type-options", "")
        out["permissions-policy"] = h.get("permissions-policy", "")
        out["cors"] = {
            "access-control-allow-origin": h.get("access-control-allow-origin", ""),
            "access-control-allow-credentials": h.get("access-control-allow-credentials", "")
        }
        # capture raw for cookie analysis
        out["set-cookie"] = r.headers.get("set-cookie", "")
    except Exception:
        out["status"] = "request failed"
    return out

# ------------------------------------
# GraphQL (unchanged)
# ------------------------------------
def graphql_probe(endpoint: str) -> Dict:
    """
    Check if GraphQL introspection is enabled (light touch).
    """
    result = {"endpoint": endpoint, "introspection": "Unknown"}
    try:
        r = requests.post(endpoint, json={"query": "query{__typename}"}, headers=UA, timeout=DEFAULT_TIMEOUT)
        if r.status_code not in (200, 400):
            result["introspection"] = "Not reachable"
            return result

        iq = {"query": "{__schema{queryType{name}}}"}
        ri = requests.post(endpoint, json=iq, headers=UA, timeout=DEFAULT_TIMEOUT)
        txt = (ri.text or "").lower()
        if "__schema" in txt and "querytype" in txt:
            result["introspection"] = "Enabled"
        elif "introspection" in txt and "not allowed" in txt:
            result["introspection"] = "Disabled"
        else:
            result["introspection"] = "Probably disabled"
    except Exception:
        result["introspection"] = "Probe failed"
    return result

# ------------------------------------
# OpenAPI (basic lint)
# ------------------------------------
def openapi_fetch_and_lint(url: str) -> Dict:
    """
    Fetch OpenAPI JSON and run a few basic checks (no 3rd-party linter needed).
    """
    res = {"url": url, "fetched": False, "issues": []}
    try:
        r = requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT)
        if not (r and r.ok):
            return res
        data = json.loads(r.text)
        res["fetched"] = True

        servers = data.get("servers", [])
        if servers:
            for s in servers:
                u = s.get("url", "")
                if isinstance(u, str) and u.startswith("http://"):
                    res["issues"].append("Server URL uses http://; prefer https://")
        else:
            res["issues"].append("No 'servers' section declared")

        comps = data.get("components", {})
        sec = comps.get("securitySchemes", {})
        if not sec:
            res["issues"].append("No components.securitySchemes defined")
        if not data.get("security"):
            res["issues"].append("No global 'security' requirement defined")

    except Exception:
        pass
    return res

# =====================================================================
# NEW: External Integrations + Local Enhanced Tests
# =====================================================================

def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url

# ----------------- CSP: Csper.io, Mozilla Observatory, CentralCSP (optional)
def csper_evaluate_url(url: str) -> Dict:
    """
    Uses Csper.io public API endpoint to evaluate CSP for a given URL.
    Returns {} if service not reachable.
    """
    try:
        api = "https://csper.io/api/evaluations"
        r = requests.post(api, json={"URL": url}, headers=UA, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}

def mozilla_observatory_scan(host: str, rescan: bool = True) -> Dict:
    """
    Uses Mozilla Observatory API v2. Kicks off a scan then fetches results.
    """
    base = "https://observatory-api.mdn.mozilla.net/api/v2"
    out = {"host": host, "scan": {}, "tests": {}}
    try:
        # Start scan
        r = requests.post(f"{base}/scan", json={"host": host, "rescan": rescan}, headers=UA, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            return out
        scan_meta = r.json()
        out["scan"] = scan_meta

        # Poll results if we received an id
        scan_id = scan_meta.get("scan", {}).get("id")
        # v2 also supports direct /scan?host=...
        tries = 0
        while tries < 20:
            time.sleep(3)
            rr = requests.get(f"{base}/scan?host={host}", headers=UA, timeout=DEFAULT_TIMEOUT)
            if rr.ok:
                s = rr.json()
                out["scan"] = s
                # If finished, request tests
                if s.get("scan", {}).get("state") in ("FINISHED", "FAILED") or s.get("scan", {}).get("grade"):
                    # results endpoint
                    rres = requests.get(f"{base}/results?host={host}", headers=UA, timeout=DEFAULT_TIMEOUT)
                    if rres.ok:
                        out["tests"] = rres.json()
                    break
            tries += 1
    except Exception:
        pass
    return out

def centralcsp_scan(url: str, api_key: Optional[str]) -> Dict:
    """
    Optional CentralCSP API scan (requires API key). Returns {} if not configured/available.
    """
    if not api_key:
        return {}
    try:
        api = "https://api.centralcsp.com/scanner/scan"
        h = {"Authorization": api_key, **UA}
        r = requests.post(api, json={"url": url}, headers=h, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}

# ----------------- HTTP headers / SecurityHeaders.com
def securityheaders_scan(host: str, api_key: Optional[str]) -> Dict:
    """
    Optional securityheaders.com API. Requires x-api-key.
    """
    if not api_key:
        return {}
    try:
        u = f"https://api.securityheaders.com/?q={host}&hide=on&followRedirects=on"
        r = requests.get(u, headers={"x-api-key": api_key, **UA}, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}

# ----------------- SSL Labs
def ssllabs_scan(host: str, start_new: bool = True) -> Dict:
    """
    Polls Qualys SSL Labs (v3) API for a full assessment.
    """
    base = "https://api.ssllabs.com/api/v3"
    params = {"host": host, "publish": "off", "all": "done"}
    if start_new:
        params["startNew"] = "on"
    try:
        # Start / check
        r = requests.get(f"{base}/analyze", params=params, headers=UA, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            return {}
        data = r.json()
        # Poll until READY or ERROR
        tries = 0
        while data.get("status") not in ("READY", "ERROR") and tries < 40:
            time.sleep(10)
            r = requests.get(f"{base}/analyze", params={"host": host}, headers=UA, timeout=DEFAULT_TIMEOUT)
            if not r.ok:
                break
            data = r.json()
            tries += 1
        return data
    except Exception:
        return {}

# ----------------- CORS tests (local)
def cors_tests(url: str, test_origin: str = "https://example.com") -> Dict:
    """
    Perform a lightweight CORS preflight (OPTIONS) and simple GET with Origin.
    """
    results = {"preflight": {}, "simple": {}}
    try:
        # Preflight
        h = {"Origin": test_origin,
             "Access-Control-Request-Method": "GET",
             **UA}
        o = requests.options(url, headers=h, timeout=DEFAULT_TIMEOUT)
        results["preflight"] = {
            "status": getattr(o, "status_code", "n/a"),
            "acao": o.headers.get("Access-Control-Allow-Origin", ""),
            "acac": o.headers.get("Access-Control-Allow-Credentials", ""),
            "acah": o.headers.get("Access-Control-Allow-Headers", ""),
            "acam": o.headers.get("Access-Control-Allow-Methods", "")
        }
    except Exception:
        results["preflight"] = {"status": "request failed"}

    try:
        # Simple GET with Origin
        g = requests.get(url, headers={"Origin": test_origin, **UA}, timeout=DEFAULT_TIMEOUT)
        results["simple"] = {
            "status": getattr(g, "status_code", "n/a"),
            "acao": g.headers.get("Access-Control-Allow-Origin", ""),
            "acac": g.headers.get("Access-Control-Allow-Credentials", "")
        }
    except Exception:
        results["simple"] = {"status": "request failed"}
    return results

# ----------------- Redirect chain (local) + optional external
def redirect_chain(url: str) -> List[Dict[str, Any]]:
    """
    Follow redirects locally and return the hop chain.
    """
    chain: List[Dict[str, Any]] = []
    try:
        r = requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        for hop in r.history:
            chain.append({
                "url": hop.url,
                "status": hop.status_code,
                "location": hop.headers.get("Location", "")
            })
        chain.append({
            "url": r.url,
            "status": r.status_code,
            "location": ""
        })
    except Exception:
        pass
    return chain

# ----------------- Cookie security analysis (local)
def analyze_cookies_from_headers(set_cookie_header: str) -> List[Dict[str, Any]]:
    """
    Analyzes Set-Cookie header text, flags missing attributes & weak patterns.
    """
    cookies: List[Dict[str, Any]] = []
    if not set_cookie_header:
        return cookies
    # naive split on comma may break if Expires contains commas; split on set-cookie delimiters via '\n' fallback
    parts = [p.strip() for p in set_cookie_header.replace("\r", "\n").split("\n") if p.strip()]
    for raw in parts:
        # each raw may still contain multiple cookies; split conservatively
        segs = [raw]
        for seg in segs:
            attrs = seg.split(";")
            if not attrs:
                continue
            nameval = attrs[0].strip()
            name = nameval.split("=", 1)[0]
            flags = {"Secure": False, "HttpOnly": False, "SameSite": "", "Path": "", "Domain": ""}
            for a in attrs[1:]:
                k = a.strip().lower()
                if k == "secure":
                    flags["Secure"] = True
                elif k == "httponly":
                    flags["HttpOnly"] = True
                elif k.startswith("samesite"):
                    flags["SameSite"] = a.split("=", 1)[-1].strip()
                elif k.startswith("path"):
                    flags["Path"] = a.split("=", 1)[-1].strip()
                elif k.startswith("domain"):
                    flags["Domain"] = a.split("=", 1)[-1].strip()
            risk = []
            if not flags["Secure"]:
                risk.append("Missing Secure")
            if not flags["HttpOnly"]:
                risk.append("Missing HttpOnly")
            if not flags["SameSite"]:
                risk.append("Missing SameSite")
            cookies.append({"cookie": name, "attributes": flags, "issues": risk})
    return cookies

# ----------------- Mixed content (local)
def find_mixed_content(html: str) -> List[str]:
    """
    Searches for http:// resource references inside HTML.
    """
    if not html:
        return []
    out: List[str] = []
    lowers = html.lower()
    markers = ["src=\"http://", "src='http://", "href=\"http://", "href='http://"]
    for m in markers:
        idx = 0
        while True:
            j = lowers.find(m, idx)
            if j == -1:
                break
            out.append(html[j:j+200])  # snippet context
            idx = j + len(m)
    return out

# ----------------- Correlation helpers
def correlate_csp(csper: Dict, observatory: Dict, local_summary: str, central: Dict) -> Dict:
    """
    Merge CSP observations into a unified summary.
    """
    summary: Dict[str, Any] = {
        "csper": csper if csper else {},
        "observatory_grade": (observatory.get("scan", {}) or {}).get("scan", {}).get("grade") or (observatory.get("scan", {}) or {}).get("grade"),
        "observatory_tests": observatory.get("tests", {}),
        "local": local_summary,
        "centralcsp": central if central else {},
        "overall": "See sources"
    }
    # very lightweight "overall" verdict
    flags = []
    if isinstance(local_summary, str) and local_summary.startswith("Weak CSP"):
        flags.append("local-weak")
    try:
        if csper and isinstance(csper.get("Results"), list):
            # If Csper flags exist
            if any(item.get("Severity", "").lower() == "high" for item in csper["Results"]):
                flags.append("csper-high")
    except Exception:
        pass
    grade = summary["observatory_grade"]
    if isinstance(grade, str) and grade.startswith(("D", "E", "F")):
        flags.append("obs-low-grade")
    summary["overall"] = "Needs hardening" if flags else "Looks reasonable (verify details)"
    return summary
``

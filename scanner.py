# scanner.py
import json
from typing import Dict, List, Tuple
import requests

DEFAULT_TIMEOUT = 8
UA = {"User-Agent": "AI-Security-Scanner/1.0 (+local)"}

# ------------------------------------
# Core simple tests
# ------------------------------------
def test_sqli(url: str) -> bool:
    """Benign SQLi error heuristic."""
    payload = "' OR '1'='1"
    try:
        r = requests.get(url, params={"test": payload}, headers=UA, timeout=DEFAULT_TIMEOUT)
        body = (r.text or "").lower()
        return any(err in body for err in ["sql syntax", "mysql", "syntax error", "unclosed quotation mark", "odbc", "pdoexception"])
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
        # Try encoded
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
    out = {}
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
    except Exception:
        out["status"] = "request failed"
    return out

# ------------------------------------
# GraphQL
# ------------------------------------
def graphql_probe(endpoint: str) -> Dict:
    """
    Check if GraphQL introspection is enabled (light touch).
    """
    result = {"endpoint": endpoint, "introspection": "Unknown"}
    try:
        # harmless query
        r = requests.post(endpoint, json={"query": "query{__typename}"}, headers=UA, timeout=DEFAULT_TIMEOUT)
        if r.status_code not in (200, 400):
            result["introspection"] = "Not reachable"
            return result

        # try introspection
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
                if u.startswith("http://"):
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

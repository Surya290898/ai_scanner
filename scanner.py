# scanner.py
import json
import time
import random
import string
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 12
UA = {"User-Agent": "AI-Security-Scanner/2.1 (+local)"}

# ----------------------------
# Core simple tests (existing)
# ----------------------------
def test_sqli(url: str) -> bool:
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

# ----------------------------
# Header analyzers (existing)
# ----------------------------
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
        out["set-cookie"] = r.headers.get("set-cookie", "")
    except Exception:
        out["status"] = "request failed"
    return out

# ----------------------------
# GraphQL / OpenAPI (existing)
# ----------------------------
def graphql_probe(endpoint: str) -> Dict:
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

def openapi_fetch_and_lint(url: str) -> Dict:
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
# NEW: Safe Authentication Surface Checks (non-intrusive)
# =====================================================================

CSRF_CANDIDATE_NAMES = [
    "csrf", "csrf-token", "csrf_token", "authenticity_token",
    "__requestverificationtoken", "__csrf", "_csrf", "xsrf-token", "x-csrf-token"
]

def _fetch(session: requests.Session, url: str) -> Optional[requests.Response]:
    try:
        return session.get(url, headers=UA, timeout=DEFAULT_TIMEOUT)
    except Exception:
        return None

def _post(session: requests.Session, url: str, data: Dict[str, str], referer: Optional[str] = None) -> Optional[requests.Response]:
    try:
        h = {**UA}
        if referer:
            h["Referer"] = referer
        return session.post(url, data=data, headers=h, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception:
        return None

def _find_password_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    out = []
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs = []
        has_pwd = False
        csrf_present = False
        for inp in form.find_all("input"):
            name = inp.get("name")
            itype = (inp.get("type") or "").lower()
            if name:
                inputs.append({"name": name, "type": itype, "value": inp.get("value") or ""})
            if itype == "password":
                has_pwd = True
            if itype == "hidden":
                nm = (name or "").lower()
                if any(c in nm for c in CSRF_CANDIDATE_NAMES):
                    csrf_present = True
        # meta csrf?
        for meta in soup.find_all("meta"):
            nm = (meta.get("name") or "").lower()
            if any(c == nm for c in CSRF_CANDIDATE_NAMES):
                csrf_present = True
        if has_pwd:
            out.append({
                "method": method,
                "action": action,
                "inputs": inputs,
                "csrf_token_present": csrf_present
            })
    return out

def _has_loginish_url(u: str) -> bool:
    u = (u or "").lower()
    return any(x in u for x in ("/login", "/signin", "/account/login", "/users/sign_in", "/auth/login"))

def _random_email(domain_hint: str = "example.com") -> str:
    left = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{left}@{domain_hint}"

def _username_enum_hint(res_a: requests.Response, res_b: requests.Response) -> Optional[str]:
    """
    Heuristic: if content length differs significantly for two invalid users,
    this may hint username enumeration via error messages. Non-binding.
    """
    try:
        a = res_a.text or ""
        b = res_b.text or ""
        if abs(len(a) - len(b)) > 100:
            return "Different error sizes for distinct fake usernames (possible username enumeration hint)."
    except Exception:
        pass
    return None

def auth_surface_checks(root: str, pages: List[str], max_attempts_per_login: int = 3) -> Dict[str, Any]:
    """
    Non-intrusive authentication posture assessment:
      - Map login forms
      - Check HTTPS & POST usage
      - Detect CSRF token presence
      - Evaluate session cookie flags via response headers
      - Small, capped failed attempts (<=3) to observe lockout/rate-limit/captcha signals
      - Optional username-enumeration hint via message size delta
    Never performs brute-force or large-scale guessing.
    """
    session = requests.Session()
    session.headers.update(UA)

    candidates = []
    for p in pages:
        if _has_loginish_url(p):
            candidates.append(p)
    # Also test root for links to login
    if root not in candidates:
        candidates = [root] + candidates
    candidates = list(dict.fromkeys(candidates))[:20]  # cap

    findings: List[Dict[str, Any]] = []
    for page in candidates:
        r = _fetch(session, page)
        if not (r and r.ok):
            continue
        pwd_forms = _find_password_forms(r.text, page)
        # record cookie attributes (high level)
        set_cookie = r.headers.get("Set-Cookie", "")
        cookie_issues = []
        if set_cookie:
            lower = set_cookie.lower()
            if "secure" not in lower:
                cookie_issues.append("Missing Secure on Set-Cookie")
            if "httponly" not in lower:
                cookie_issues.append("Missing HttpOnly on Set-Cookie")
            if "samesite" not in lower:
                cookie_issues.append("Missing SameSite on Set-Cookie")

        for f in pwd_forms:
            issues = []
            # HTTPS & method
            if not f["action"].startswith("https://") or not page.startswith("https://"):
                issues.append("Login form/page not fully over HTTPS")
            if f["method"] != "post":
                issues.append("Login form uses GET instead of POST")
            if not f["csrf_token_present"]:
                issues.append("No obvious anti-CSRF token in form or meta")

            # small, capped failed attempts for signals (not brute-force)
            lockout_signal = None
            enum_hint = None
            try:
                action = f["action"]
                # pick username and password field names (best-effort)
                uname_field = None
                pass_field = None
                for i in f["inputs"]:
                    t = (i.get("type") or "").lower()
                    n = (i.get("name") or "").lower()
                    if t == "password" and not pass_field:
                        pass_field = i["name"]
                    if n in ("username", "email", "user", "login", "user[email]", "user[login]") and not uname_field:
                        uname_field = i["name"]
                # if we couldn't detect required fields, skip active checks
                if uname_field and pass_field:
                    # prepare 2 distinct fake usernames for enum hint
                    domain_hint = urlparse(root).hostname or "example.com"
                    u1 = _random_email(domain_hint)
                    u2 = _random_email(domain_hint)
                    payload_base = {}
                    for i in f["inputs"]:
                        # keep other hidden/default inputs (e.g., CSRF) as-is
                        if i["name"] not in (uname_field, pass_field):
                            payload_base[i["name"]] = i.get("value") or ""

                    # attempt #1
                    data1 = dict(payload_base)
                    data1[uname_field] = u1
                    data1[pass_field]  = "Wrong#12345"
                    res1 = _post(session, action, data1, referer=page)

                    time.sleep(0.8)

                    # attempt #2
                    data2 = dict(payload_base)
                    data2[uname_field] = u2
                    data2[pass_field]  = "Wrong#12345"
                    res2 = _post(session, action, data2, referer=page)

                    # cap attempts: third only if we saw explicit signals missing
                    res3 = None
                    if max_attempts_per_login >= 3:
                        time.sleep(0.8)
                        data3 = dict(payload_base)
                        data3[uname_field] = u2
                        data3[pass_field]  = "Wrong#12345"
                        res3 = _post(session, action, data3, referer=page)

                    # look for basic lockout/rate-limit cues
                    for rr in [res1, res2, res3]:
                        if not rr:
                            continue
                        txt = (rr.text or "").lower()
                        if any(s in txt for s in ["too many attempts", "locked", "try again later", "captcha"]):
                            lockout_signal = "Lockout/CAPTCHA message visible after few failed attempts"
                            break
                        if rr.headers.get("Retry-After") or rr.headers.get("X-RateLimit-Remaining"):
                            lockout_signal = "Rate-limiting headers present after failed attempts"
                            break

                    # username-enumeration hint
                    if res1 and res2:
                        enum_hint = _username_enum_hint(res1, res2)
            except Exception:
                pass

            details = {
                "login_page": page,
                "action": f["action"],
                "method": f["method"],
                "csrf_token_present": f["csrf_token_present"],
                "cookie_issues": cookie_issues,
                "issues": issues,
                "signals": {
                    "lockout_or_rate_limit": lockout_signal,
                    "username_enumeration_hint": enum_hint
                }
            }
            findings.append(details)

    return {
        "root": root,
        "logins_assessed": len(findings),
        "findings": findings
    }

# ----------------------------
# Other utilities (existing)
# ----------------------------
def cors_tests(url: str, test_origin: str = "https://example.com") -> Dict:
    results = {"preflight": {}, "simple": {}}
    try:
        h = {"Origin": test_origin, "Access-Control-Request-Method": "GET", **UA}
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
        g = requests.get(url, headers={"Origin": test_origin, **UA}, timeout=DEFAULT_TIMEOUT)
        results["simple"] = {
            "status": getattr(g, "status_code", "n/a"),
            "acao": g.headers.get("Access-Control-Allow-Origin", ""),
            "acac": g.headers.get("Access-Control-Allow-Credentials", "")
        }
    except Exception:
        results["simple"] = {"status": "request failed"}
    return results

def redirect_chain(url: str) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    try:
        r = requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        for hop in r.history:
            chain.append({"url": hop.url, "status": hop.status_code, "location": hop.headers.get("Location", "")})
        chain.append({"url": r.url, "status": r.status_code, "location": ""})
    except Exception:
        pass
    return chain

def analyze_cookies_from_headers(set_cookie_header: str) -> List[Dict[str, Any]]:
    cookies: List[Dict[str, Any]] = []
    if not set_cookie_header:
        return cookies
    parts = [p.strip() for p in set_cookie_header.replace("\r", "\n").split("\n") if p.strip()]
    for raw in parts:
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

def find_mixed_content(html: str) -> List[str]:
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
            out.append(html[j:j+200])
            idx = j + len(m)
    return out

def correlate_csp(csper: Dict, observatory: Dict, local_summary: str, central: Dict) -> Dict:
    obs_grade = None
    try:
        obs_grade = (observatory.get("scan") or {}).get("grade") \
            or ((observatory.get("scan") or {}).get("scan") or {}).get("grade")
    except Exception:
        obs_grade = None

    summary: Dict[str, Any] = {
        "csper": csper if csper else {},
        "observatory_grade": obs_grade,
        "observatory_tests": observatory.get("tests", {}),
        "local": local_summary,
        "centralcsp": central if central else {},
        "overall": "See sources"
    }
    flags = []
    if isinstance(local_summary, str) and local_summary.startswith("Weak CSP"):
        flags.append("local-weak")
    try:
        if csper and isinstance(csper.get("Results"), list):
            if any(item.get("Severity", "").lower() == "high" for item in csper["Results"]):
                flags.append("csper-high")
    except Exception:
        pass
    if isinstance(obs_grade, str) and obs_grade[:1] in ("D", "E", "F"):
        flags.append("obs-low-grade")
    summary["overall"] = "Needs hardening" if flags else "Looks reasonable (verify details)"
    return summary

__all__ = [
    "test_sqli", "test_xss", "test_form",
    "headers_analyzer", "csp_evaluator",
    "graphql_probe", "openapi_fetch_and_lint",
    "auth_surface_checks",  # NEW
    "cors_tests", "redirect_chain", "analyze_cookies_from_headers",
    "find_mixed_content", "correlate_csp",
]

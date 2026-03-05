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
UA = {"User-Agent": "AI-Security-Scanner/2.2 (+local)"}

# ----------------------------
# Classic simple tests
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
# Header analyzers
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
# GraphQL / OpenAPI
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

# ----------------------------
# CORS / Redirect / Cookie / Mixed
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

# =====================================================================
# NEW: Authentication Security Auditor (safe mode)
# =====================================================================

CSRF_CANDIDATE_NAMES = [
    "csrf", "csrf-token", "csrf_token", "authenticity_token",
    "__requestverificationtoken", "__csrf", "_csrf", "xsrf-token", "x-csrf-token"
]

LOGIN_HINT_WORDS = [
    "/login", "/signin", "/account/login", "/users/sign_in", "/auth/login"
]

SENSITIVE_ENDPOINTS = [
    "/admin", "/admin/login", "/manage", "/manager", "/console",
    "/actuator", "/debug", "/phpmyadmin", "/_profiler", "/wp-admin", "/umbraco"
]

API_CANDIDATES = [
    "/api", "/api/v1", "/api/v2", "/v1", "/v2"
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

def _random_email(domain_hint: str = "example.com") -> str:
    left = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{left}@{domain_hint}"

def _username_enum_hint(res_a: requests.Response, res_b: requests.Response) -> Optional[str]:
    try:
        a = res_a.text or ""
        b = res_b.text or ""
        if abs(len(a) - len(b)) > 100:
            return "Different error sizes for distinct fake usernames (possible username enumeration hint)."
    except Exception:
        pass
    return None

def _has_loginish_url(u: str) -> bool:
    u = (u or "").lower()
    return any(x in u for x in LOGIN_HINT_WORDS)

def _detect_login_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    out = []
    soup = BeautifulSoup(html or "", "html.parser")
    meta_csrf = False
    for meta in soup.find_all("meta"):
        nm = (meta.get("name") or "").lower()
        if any(c == nm for c in CSRF_CANDIDATE_NAMES):
            meta_csrf = True
            break

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs, has_pwd, csrf_present = [], False, meta_csrf
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
        if has_pwd:
            out.append({
                "method": method,
                "action": action,
                "inputs": inputs,
                "csrf_token_present": csrf_present
            })
    return out

def _mfa_hints(html: str) -> Optional[str]:
    t = (html or "").lower()
    if any(k in t for k in ["2fa", "two factor", "two-factor", "one-time", "otp", "authenticator app", "totp"]):
        return "MFA references detected (2FA/OTP)."
    return None

def _password_policy_hints(html: str) -> List[str]:
    hints = []
    soup = BeautifulSoup(html or "", "html.parser")
    for inp in soup.find_all("input"):
        itype = (inp.get("type") or "").lower()
        if itype == "password":
            if inp.get("minlength"):
                hints.append(f"Password minlength client-side: {inp.get('minlength')}")
            if inp.get("pattern"):
                hints.append("Password pattern enforced client-side.")
    text = (html or "").lower()
    if any(k in text for k in ["minimum", "uppercase", "lowercase", "special character", "length"]):
        hints.append("Password policy hints present in page text.")
    return hints

def _logout_csrf_hints(html: str, base_url: str) -> Optional[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    # look for logout links/forms
    for a in soup.find_all("a", href=True):
        if "logout" in (a.get("href") or "").lower():
            href = urljoin(base_url, a["href"])
            if href.startswith("http") and (href.startswith("http://") or href.startswith("https://")):
                # anchor logout via GET -> likely CSRF-prone unless SameSite strict everywhere
                return "Logout appears to use GET (consider POST + CSRF)."
    for form in soup.find_all("form"):
        act = (form.get("action") or "").lower()
        if "logout" in act and (form.get("method") or "get").lower() != "post":
            return "Logout form not using POST."
    return None

def _session_cookie_signals(headers: Dict[str, str]) -> List[str]:
    issues = []
    set_cookie = (headers or {}).get("Set-Cookie", "")
    if not set_cookie:
        return issues
    low = set_cookie.lower()
    if "secure" not in low:    issues.append("Set-Cookie missing Secure")
    if "httponly" not in low:  issues.append("Set-Cookie missing HttpOnly")
    if "samesite" not in low:  issues.append("Set-Cookie missing SameSite")
    return issues

def _rate_limit_lockout_signals(responses: List[Optional[requests.Response]]) -> Optional[str]:
    for rr in responses:
        if not rr:
            continue
        txt = (rr.text or "").lower()
        if any(s in txt for s in ["too many attempts", "locked", "try again later", "captcha"]):
            return "Lockout/CAPTCHA message visible after few failed attempts"
        if rr.headers.get("Retry-After") or rr.headers.get("X-RateLimit-Remaining"):
            return "Rate-limiting headers present after failed attempts"
    return None

def _extract_un_pw_fields(inputs: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    uname_field = None
    pass_field = None
    for i in inputs:
        t = (i.get("type") or "").lower()
        n = (i.get("name") or "").lower()
        if t == "password" and not pass_field:
            pass_field = i["name"]
        if n in ("username", "email", "user", "login", "user[email]", "user[login]") and not uname_field:
            uname_field = i["name"]
    return uname_field, pass_field

def _visible_text_hints(html: str) -> List[str]:
    out = []
    low = (html or "").lower()
    if "remember me" in low:
        out.append("Remember-me option visible")
    if "show password" in low or "toggle password" in low:
        out.append("Show password toggle present")
    return out

def _guess_api_endpoints(root: str, pages: List[str]) -> List[str]:
    # known pages with /api in path + a few candidates relative to root
    candidates = set()
    for p in pages:
        if "/api" in p:
            candidates.add(p)
    for suffix in API_CANDIDATES:
        candidates.add(urljoin(root, suffix))
    return list(candidates)[:15]

def _evaluate_api_auth(root: str, pages: List[str]) -> List[Dict[str, Any]]:
    """
    Very light probes: GET and OPTIONS with Origin to look for permissive CORS or unauthenticated 200 JSON.
    """
    session = requests.Session()
    session.headers.update(UA)
    out = []
    for ep in _guess_api_endpoints(root, pages):
        try:
            g = session.get(ep, timeout=DEFAULT_TIMEOUT, headers=UA)
            api_item = {"endpoint": ep, "status": getattr(g, "status_code", "n/a"), "notes": []}
            ct = (g.headers.get("Content-Type") or "").lower()
            if g.status_code == 200 and ("application/json" in ct or g.text.strip().startswith(("{", "["))):
                api_item["notes"].append("Endpoint returns JSON with no auth (verify intended public access)")
            # CORS preflight
            try:
                h = {"Origin": "https://example.com", "Access-Control-Request-Method": "GET", **UA}
                o = session.options(ep, headers=h, timeout=DEFAULT_TIMEOUT)
                acao = o.headers.get("Access-Control-Allow-Origin", "")
                acac = (o.headers.get("Access-Control-Allow-Credentials", "") or "").lower()
                if acao == "*" and acac == "true":
                    api_item["notes"].append("CORS allows '*' with credentials (misconfiguration)")
            except Exception:
                pass
            out.append(api_item)
        except Exception:
            pass
    return out

def _scan_sensitive_endpoints(root: str) -> List[Dict[str, Any]]:
    session = requests.Session()
    session.headers.update(UA)
    out = []
    for path in SENSITIVE_ENDPOINTS[:15]:
        url = urljoin(root, path)
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            note = None
            if r.status_code == 200:
                note = "Accessible (200). If admin-only, ensure protection."
            elif r.status_code in (401, 403):
                note = f"Protected ({r.status_code})."
            elif r.status_code in (301, 302):
                note = f"Redirects ({r.status_code}) to {r.headers.get('Location', '')}"
            else:
                note = f"Status {r.status_code}"
            out.append({"url": url, "status": r.status_code, "note": note})
        except Exception:
            pass
    return out

def _score_auth(findings: Dict[str, Any]) -> int:
    """
    Produce a 0-100 score from multiple categories.
    Simple weighting to keep it explainable.
    """
    score = 100
    penalties = []

    # Missing CSRF/HTTPS/POST use on any login
    for f in findings.get("logins", []):
        if not f.get("https_ok", True): penalties.append(8)
        if not f.get("post_ok",  True): penalties.append(6)
        if not f.get("csrf_ok",  True): penalties.append(8)
        for c in (f.get("cookie_issues") or []):
            penalties.append(4)

        # if username enumeration hint present
        if f.get("signals", {}).get("username_enumeration_hint"): penalties.append(4)
        if not f.get("signals", {}).get("lockout_or_rate_limit"): penalties.append(4)  # no visible signal

    # Logout CSRF
    if findings.get("logout_csrf_hint"): penalties.append(4)

    # Weak password policy
    if findings.get("password_policy") and not findings["password_policy"]:
        penalties.append(0)
    elif findings.get("password_policy"):
        # If only minlength < 8 detected
        for h in findings["password_policy"]:
            if "minlength" in h:
                try:
                    v = int("".join([d for d in h if d.isdigit()]))
                    if v < 8:
                        penalties.append(4)
                except Exception:
                    pass

    # Sensitive endpoints: accessible admin-like endpoints
    for s in findings.get("sensitive_endpoints", []):
        if s.get("status") == 200 and "admin" in s.get("url", "").lower():
            penalties.append(10)

    # API auth notes
    for a in findings.get("api_auth", []):
        for n in a.get("notes", []):
            if "no auth" in n.lower():
                penalties.append(6)
            if "misconfiguration" in n.lower():
                penalties.append(6)

    # MFA absent (no hints) is not a penalty; presence earns small bonus
    if findings.get("mfa_hint"):
        score += 2  # small bonus

    # clamp
    total_pen = sum(penalties)
    score = max(0, min(100, score - total_pen))
    return score

def auth_security_audit(root: str, pages: List[str]) -> Dict[str, Any]:
    """
    Authentication Security Auditor (safe mode)
    - Login mapping, HTTPS/POST/CSRF check
    - Cookie flags on login responses
    - ≤3 benign failed attempts for lockout/rate-limit signals + username-enum hint (size delta)
    - MFA hints, password policy hints, logout CSRF hints
    - Sensitive endpoints quick scan
    - API auth misconfig quick scan
    Returns a dict with detailed findings and a 0..100 score
    """
    session = requests.Session()
    session.headers.update(UA)

    candidates = []
    for p in pages:
        if _has_loginish_url(p):
            candidates.append(p)
    # Always include root for nav-based login
    if root not in candidates:
        candidates = [root] + candidates
    candidates = list(dict.fromkeys(candidates))[:20]

    login_findings: List[Dict[str, Any]] = []
    any_logout_hint = None
    mfa_hint = None
    pwd_policy_hints: List[str] = []
    cookie_issues_aggregate: List[str] = []

    for page in candidates:
        r = _fetch(session, page)
        if not (r and r.ok):
            continue
        html = r.text or ""
        mfa_hint = mfa_hint or _mfa_hints(html)
        li_forms = _detect_login_forms(html, page)
        logout_hint = _logout_csrf_hints(html, page)
        if logout_hint:
            any_logout_hint = logout_hint
        pwd_policy_hints.extend(_password_policy_hints(html))

        # cookie flags for the page view
        cookie_issues_aggregate.extend(_session_cookie_signals(r.headers))

        for f in li_forms:
            # HTTPS + POST + CSRF flags
            https_ok = page.startswith("https://") and f["action"].startswith("https://")
            post_ok  = f["method"] == "post"
            csrf_ok  = f["csrf_token_present"]

            # benign failed attempts (≤3)
            lockout_signal = None
            enum_hint = None
            try:
                uname_field, pass_field = _extract_un_pw_fields(f["inputs"])
                if uname_field and pass_field:
                    domain_hint = urlparse(root).hostname or "example.com"
                    u1 = _random_email(domain_hint)
                    u2 = _random_email(domain_hint)
                    payload_base = {}
                    for i in f["inputs"]:
                        if i["name"] not in (uname_field, pass_field):
                            payload_base[i["name"]] = i.get("value") or ""

                    # attempt #1
                    d1 = dict(payload_base); d1[uname_field] = u1; d1[pass_field] = "Wrong#12345"
                    res1 = _post(session, f["action"], d1, referer=page); time.sleep(0.6)

                    # attempt #2
                    d2 = dict(payload_base); d2[uname_field] = u2; d2[pass_field] = "Wrong#12345"
                    res2 = _post(session, f["action"], d2, referer=page); time.sleep(0.6)

                    # attempt #3 (optional)
                    d3 = dict(payload_base); d3[uname_field] = u2; d3[pass_field] = "Wrong#12345"
                    res3 = _post(session, f["action"], d3, referer=page)

                    lockout_signal = _rate_limit_lockout_signals([res1, res2, res3])
                    if res1 and res2:
                        enum_hint = _username_enum_hint(res1, res2)
            except Exception:
                pass

            # cookie flags from response to login page already collected above
            login_findings.append({
                "login_page": page,
                "action": f["action"],
                "https_ok": https_ok,
                "post_ok": post_ok,
                "csrf_ok": csrf_ok,
                "cookie_issues": list(set(cookie_issues_aggregate)),
                "signals": {
                    "lockout_or_rate_limit": lockout_signal,
                    "username_enumeration_hint": enum_hint
                },
                "ui_hints": _visible_text_hints(html),
            })

    sensitive = _scan_sensitive_endpoints(root)
    api_auth  = _evaluate_api_auth(root, pages)

    findings = {
        "root": root,
        "logins": login_findings,
        "logout_csrf_hint": any_logout_hint,
        "mfa_hint": mfa_hint,
        "password_policy": list(set(pwd_policy_hints)),
        "sensitive_endpoints": sensitive,
        "api_auth": api_auth
    }
    score = _score_auth(findings)
    findings["score"] = score
    return findings

__all__ = [
    "test_sqli", "test_xss", "test_form",
    "headers_analyzer", "csp_evaluator",
    "graphql_probe", "openapi_fetch_and_lint",
    "cors_tests", "redirect_chain",
    "analyze_cookies_from_headers", "find_mixed_content",
    "auth_security_audit",
]

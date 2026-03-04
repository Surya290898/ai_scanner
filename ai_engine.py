# ai_engine.py
# Fully Local AI-Style Analysis Engine (No External API)

from typing import Dict, List, Union

def _add(findings: List[Dict], ftype: str, severity: str, description: str, impact: str, remediation: str):
    findings.append({
        "type": ftype,
        "severity": severity,
        "description": description,
        "impact": impact,
        "remediation": remediation
    })

def analyze_response(response_text: str,
                     response_headers: Dict[str, str] = None,
                     url: str = "") -> Union[List[Dict], Dict]:
    """
    Lightweight content+headers heuristic analyzer to augment raw checks.
    Fully local; no external API.
    """
    text = (response_text or "").lower()
    headers = {k.lower(): v for k, v in (response_headers or {}).items()}
    findings: List[Dict] = []

    # ----------------------------
    # SQL Error Detection
    # ----------------------------
    sql_errors = [
        "sql syntax", "mysql_fetch", "syntax error",
        "unclosed quotation mark", "odbc", "pdoexception",
        "psql:", "sqlite error", "you have an error in your sql syntax"
    ]
    if any(err in text for err in sql_errors):
        _add(findings, "SQL Injection", "High",
             "The application appears to expose SQL error messages.",
             "Attackers may manipulate database queries to extract, modify, or delete sensitive data.",
             "Use parameterized queries (prepared statements), validate inputs, and turn off verbose DB errors in production.")

    # ----------------------------
    # XSS Detection (basic reflection hints)
    # ----------------------------
    if "<script>" in text or "&lt;script&gt;" in text or "alert(" in text:
        _add(findings, "Cross-Site Scripting (XSS)", "High",
             "User-controlled input may be reflected without proper output encoding.",
             "Attackers could run arbitrary JS to steal sessions or perform actions as the user.",
             "Encode output per context, sanitize inputs, and enforce a strict Content Security Policy (CSP) with nonces/hashes.")

    # ----------------------------
    # Debug / Stack Trace Exposure
    # ----------------------------
    if "traceback" in text or "stack trace" in text or "exception" in text:
        _add(findings, "Information Disclosure", "Medium",
             "Stack traces or exceptions appear in responses.",
             "Internal details help attackers pivot or craft exploits.",
             "Disable debug in production and render generic error pages; log detailed errors server-side only.")

    # ----------------------------
    # Security Headers (from response headers)
    # ----------------------------
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    hsts = headers.get("strict-transport-security", "")
    refpol = headers.get("referrer-policy", "")
    xcto = headers.get("x-content-type-options", "")
    perm = headers.get("permissions-policy", "")
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    # Clickjacking baseline (prefer CSP frame-ancestors, else XFO)
    if not csp or ("frame-ancestors" not in csp.lower()):
        if not xfo:
            _add(findings, "Missing Security Header", "Low",
                 "No clickjacking protection header detected (CSP frame-ancestors or X-Frame-Options).",
                 "Pages could be embedded in iframes to trick users into unwanted clicks.",
                 "Set 'Content-Security-Policy: frame-ancestors 'none';' (recommended) or 'X-Frame-Options: DENY'.")

    # CSP quality hints
    if csp:
        lc = csp.lower()
        weak_bits = []
        if "unsafe-inline" in lc:
            weak_bits.append("unsafe-inline")
        if "unsafe-eval" in lc:
            weak_bits.append("unsafe-eval")
        if "*" in lc and ("script-src" in lc or "default-src" in lc):
            weak_bits.append("wildcards in script/default-src")
        if weak_bits:
            _add(findings, "CSP Weakness", "Medium",
                 f"CSP allows {', '.join(weak_bits)}.",
                 "Weak CSP increases XSS and injection exploitability.",
                 "Use nonces/hashes for scripts, drop 'unsafe-*', avoid '*' for script/default-src; add 'frame-ancestors'.")
    else:
        _add(findings, "Missing Security Header", "Low",
             "No Content-Security-Policy header detected.",
             "Lack of CSP removes a key browser-enforced mitigation for XSS and clickjacking.",
             "Add a strict CSP with nonces/hashes and frame-ancestors.")

    # HSTS
    if url.startswith("https://") and not hsts:
        _add(findings, "Missing Security Header", "Low",
             "No HTTP Strict-Transport-Security (HSTS) header detected on HTTPS response.",
             "Users may be downgraded to HTTP by network attackers.",
             "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' after ensuring full HTTPS readiness.")

    # Referrer-Policy
    if not refpol:
        _add(findings, "Missing Security Header", "Low",
             "No Referrer-Policy header detected.",
             "Cross-origin navigations may leak full URLs and query strings.",
             "Set 'Referrer-Policy: strict-origin-when-cross-origin'.")

    # X-Content-Type-Options
    if xcto.lower() != "nosniff":
        _add(findings, "Missing Security Header", "Low",
             "Missing or incorrect X-Content-Type-Options.",
             "MIME sniffing can make browsers execute content in unexpected contexts.",
             "Set 'X-Content-Type-Options: nosniff'.")

    # Permissions-Policy (optional but good)
    if not perm:
        _add(findings, "Missing Security Header", "Low",
             "No Permissions-Policy header detected.",
             "Unneeded browser features may be accessible to injected scripts or third-party iframes.",
             "Disable unused features, e.g., 'Permissions-Policy: camera=(), microphone=(), geolocation=(self)'.")

    # ----------------------------
    # CORS basic smell
    # ----------------------------
    if acao:
        if acao.strip() == "*" and acac.lower() == "true":
            _add(findings, "CORS Misconfiguration", "Medium",
                 "Access-Control-Allow-Origin is '*' while credentials are allowed.",
                 "This can expose authenticated endpoints cross-origin.",
                 "Never combine wildcard ACAO with 'Access-Control-Allow-Credentials: true'; use an explicit allowlist per endpoint.")

    # ----------------------------
    # Mixed content hint (if https and body links to http)
    # ----------------------------
    if url.startswith("https://") and ('src="http://' in text or 'href="http://' in text):
        _add(findings, "Mixed Content", "Medium",
             "HTTPS page links or loads HTTP resources.",
             "Breaks transport security and can lead to code/data injection.",
             "Upgrade resources to HTTPS or use relative/HTTPS URIs.")

    if not findings:
        return {
            "status": "No major AI-detected issues found.",
            "details": "No obvious injection errors, debug traces, or header gaps were detected in this response."
        }

    return findings

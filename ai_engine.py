# ai_engine.py
# Fully Local AI-Style Analysis Engine (No External API)

def analyze_response(response_text):

    text = response_text.lower()

    findings = []

    # ----------------------------
    # SQL Error Detection
    # ----------------------------
    sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "syntax error",
        "unclosed quotation mark",
        "odbc",
        "pdoexception"
    ]

    if any(error in text for error in sql_errors):
        findings.append({
            "type": "SQL Injection",
            "severity": "High",
            "description": "The application appears to expose SQL error messages, which may indicate improper input validation and possible SQL injection vulnerability.",
            "impact": "Attackers may manipulate database queries to extract, modify, or delete sensitive data.",
            "remediation": "Use parameterized queries (prepared statements), implement input validation, and disable verbose database error messages in production."
        })

    # ----------------------------
    # XSS Detection
    # ----------------------------
    if "<script>" in text or "alert(" in text:
        findings.append({
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "description": "User-controlled input appears to be reflected in the response without proper sanitization.",
            "impact": "Attackers can inject malicious JavaScript to steal session cookies or perform actions on behalf of users.",
            "remediation": "Implement proper output encoding, use Content Security Policy (CSP), and sanitize user inputs."
        })

    # ----------------------------
    # Debug / Stack Trace Exposure
    # ----------------------------
    if "traceback" in text or "exception" in text:
        findings.append({
            "type": "Information Disclosure",
            "severity": "Medium",
            "description": "Application appears to expose stack traces or internal exception messages.",
            "impact": "Sensitive system information may be disclosed to attackers.",
            "remediation": "Disable debug mode in production and configure generic error pages."
        })

    # ----------------------------
    # Missing Security Headers
    # ----------------------------
    if "x-frame-options" not in text:
        findings.append({
            "type": "Missing Security Header",
            "severity": "Low",
            "description": "X-Frame-Options header not detected.",
            "impact": "Application may be vulnerable to clickjacking attacks.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
        })

    # ----------------------------
    # Default Case
    # ----------------------------
    if not findings:
        return {
            "status": "No major AI-detected application-layer issues found.",
            "details": "Response content does not indicate obvious injection, debug exposure, or script reflection patterns."
        }

    return findings

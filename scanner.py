# scanner.py
import requests

def test_sqli(url):
    """Simple SQL Injection Test"""
    payload = "' OR '1'='1"
    try:
        response = requests.get(url, params={"test": payload}, timeout=5)
        if any(err in response.text.lower() for err in ["sql", "mysql", "syntax error"]):
            return True
    except:
        pass
    return False

def test_xss(url):
    """Simple XSS Test on URL parameter"""
    payload = "<script>alert(1)</script>"
    try:
        response = requests.get(url, params={"test": payload}, timeout=5)
        if payload in response.text:
            return True
    except:
        pass
    return False

def test_form(form):
    """Test a form for XSS or SQLi in its input fields (safe payloads)"""
    url = form["page"]
    method = form["method"]
    data = {}
    results = {}

    for input_name in form["inputs"]:
        # Test payloads
        data[input_name] = "<script>alert(1)</script>"
        try:
            if method == "post":
                response = requests.post(url, data=data, timeout=5)
            else:
                response = requests.get(url, params=data, timeout=5)

            # Check for XSS reflection
            if "<script>alert(1)</script>" in response.text:
                results[input_name] = "Possible XSS detected"
            else:
                results[input_name] = "No XSS detected"

        except:
            results[input_name] = "Failed to test"
        data[input_name] = ""  # Reset for next field

    return results
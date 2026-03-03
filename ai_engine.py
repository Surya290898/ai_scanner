# ai_engine.py
import requests

# HuggingFace free API (replace with your token)
API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.1"
HEADERS = {"Authorization": "Bearer YOUR_API_KEY"}

def analyze_response(response_text):
    """
    AI analyzes HTTP response for vulnerabilities.
    """
    prompt = f"""
    Analyze this HTTP response for vulnerabilities and business logic issues.
    Look for workflow flaws like skipping steps, duplicate actions, or unexpected behavior.
    If safe, reply 'No vulnerabilities found.'
    Response snippet:
    {response_text[:1000]}
    """
    try:
        response = requests.post(API_URL, headers=HEADERS, json={"inputs": prompt})
        result = response.json()
        if isinstance(result, list) and "generated_text" in result[0]:
            return result[0]["generated_text"]
        return str(result)
    except Exception as e:
        return f"AI analysis failed: {e}"
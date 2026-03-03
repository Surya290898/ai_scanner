import requests
import os

HF_TOKEN = os.getenv("HF_TOKEN")  # Store token securely in Streamlit secrets

API_URL = "https://router.huggingface.co/hf-inference/models/facebook/bart-large-mnli"

headers = {
    "Authorization": f"Bearer {HF_TOKEN}"
}

def analyze_response(text):

    payload = {
        "inputs": text[:1000]  # limit text size
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=10)

        if response.status_code != 200:
            return f"AI API Error: {response.json()}"

        return str(response.json())[:500]

    except Exception as e:
        return f"AI analysis failed: {str(e)}"

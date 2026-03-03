# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl(url):
    """
    Crawl website starting from the given URL.
    Returns:
        visited_urls: list of all page URLs
        forms: list of forms with method and input names
    """
    visited = []
    to_visit = [url]
    all_forms = []

    while to_visit:
        current = to_visit.pop()
        if current in visited:
            continue

        try:
            response = requests.get(current, timeout=5)
            visited.append(current)

            soup = BeautifulSoup(response.text, "html.parser")

            # Find links
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])
                if full_url not in visited and full_url.startswith(url):
                    to_visit.append(full_url)

            # Find forms
            for form in soup.find_all("form"):
                form_info = {
                    "page": current,
                    "method": form.get("method", "get").lower(),
                    "action": form.get("action"),
                    "inputs": [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                }
                all_forms.append(form_info)

        except:
            pass

    return visited, all_forms
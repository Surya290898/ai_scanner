import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time

class SecurityCrawler:

    def __init__(self, base_url, max_pages=200):
        self.base_url = base_url
        self.visited = set()
        self.to_visit = [base_url]
        self.session = requests.Session()
        self.max_pages = max_pages

        self.login_pages = []
        self.forms = []
        self.potential_vulns = []

    # -------------------------
    # Basic Request
    # -------------------------
    def fetch(self, url):
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            return response
        except Exception:
            return None

    # -------------------------
    # Detect Login Pages
    # -------------------------
    def detect_login(self, soup, url):
        forms = soup.find_all("form")

        for form in forms:
            inputs = form.find_all("input")

            password_fields = [
                i for i in inputs if i.get("type") == "password"
            ]

            if password_fields:
                self.login_pages.append(url)
                print(f"[+] Login page detected: {url}")
                return True

        return False

    # -------------------------
    # Extract Forms
    # -------------------------
    def extract_forms(self, soup, url):

        forms = soup.find_all("form")

        for form in forms:
            form_data = {
                "url": url,
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all("input"):
                form_data["inputs"].append({
                    "name": input_tag.get("name"),
                    "type": input_tag.get("type"),
                })

            self.forms.append(form_data)

    # -------------------------
    # Check CSRF Protection
    # -------------------------
    def check_csrf(self, form):

        token_patterns = [
            "csrf",
            "token",
            "authenticity_token"
        ]

        for input_field in form["inputs"]:
            name = input_field["name"]

            if name:
                for token in token_patterns:
                    if token in name.lower():
                        return True

        return False

    # -------------------------
    # Test Access Control
    # -------------------------
    def check_direct_access(self, url):

        r = self.session.get(url)

        if r.status_code == 200:
            if "login" not in r.url.lower():
                self.potential_vulns.append({
                    "type": "Access Control Bypass",
                    "url": url
                })
                print(f"[!] Possible access control bypass: {url}")

    # -------------------------
    # Identify Brute Force Risk
    # -------------------------
    def check_bruteforce_risk(self, form):

        password_fields = [
            f for f in form["inputs"] if f["type"] == "password"
        ]

        if password_fields:

            if not self.check_csrf(form):

                self.potential_vulns.append({
                    "type": "Possible Brute Force Risk",
                    "url": form["url"]
                })

                print(f"[!] Possible brute force risk: {form['url']}")

    # -------------------------
    # Extract Links
    # -------------------------
    def extract_links(self, soup, url):

        links = set()

        for a in soup.find_all("a", href=True):

            link = urljoin(url, a["href"])

            if urlparse(link).netloc == urlparse(self.base_url).netloc:
                links.add(link)

        return links

    # -------------------------
    # Crawl
    # -------------------------
    def crawl(self):

        while self.to_visit and len(self.visited) < self.max_pages:

            url = self.to_visit.pop(0)

            if url in self.visited:
                continue

            print(f"[+] Crawling: {url}")

            response = self.fetch(url)

            if not response or "text/html" not in response.headers.get("Content-Type",""):
                continue

            self.visited.add(url)

            soup = BeautifulSoup(response.text, "html.parser")

            self.detect_login(soup, url)

            self.extract_forms(soup, url)

            self.check_direct_access(url)

            links = self.extract_links(soup, url)

            for link in links:
                if link not in self.visited:
                    self.to_visit.append(link)

            time.sleep(0.5)

        self.analyze_forms()

    # -------------------------
    # Analyze Forms
    # -------------------------
    def analyze_forms(self):

        print("\n[+] Analyzing Forms")

        for form in self.forms:

            if not self.check_csrf(form):

                self.potential_vulns.append({
                    "type": "Missing CSRF Token",
                    "url": form["url"]
                })

                print(f"[!] Missing CSRF protection: {form['url']}")

            self.check_bruteforce_risk(form)

    # -------------------------
    # Report
    # -------------------------
    def report(self):

        print("\n========== Scan Report ==========")

        print(f"Pages Crawled: {len(self.visited)}")
        print(f"Login Pages Found: {len(self.login_pages)}")

        for login in self.login_pages:
            print(f"  - {login}")

        print("\nPotential Vulnerabilities:")

        for v in self.potential_vulns:
            print(f"[{v['type']}] -> {v['url']}")

        print("=================================")


if __name__ == "__main__":

    target = input("Enter target URL: ")

    crawler = SecurityCrawler(target)

    crawler.crawl()

    crawler.report()

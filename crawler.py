# crawler.py
import json
import os
import re
from collections import deque
from typing import Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 8
UA = {"User-Agent": "AI-Security-Scanner/2.0 (+local)"}

def same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(a), urlparse(b)
        def _port(p): return p.port or (443 if p.scheme == "https" else 80)
        return (pa.scheme, pa.hostname, _port(pa)) == (pb.scheme, pb.hostname, _port(pb))
    except Exception:
        return False

def _get(url: str, allow_redirects: bool = True):
    try:
        return requests.get(url, headers=UA, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
    except Exception:
        return None

def _safe_add(url: str, base: str, queue: deque, seen: Set[str]):
    if not url:
        return
    full = urljoin(base, url)
    if full not in seen and full.startswith(base):
        queue.append(full)

def parse_forms(soup: BeautifulSoup, page_url: str) -> List[Dict]:
    forms = []
    try:
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page_url
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            forms.append({"page": page_url, "method": method, "action": urljoin(page_url, action), "inputs": inputs})
    except Exception:
        pass
    return forms

def robots_and_sitemap_seeds(root: str) -> Tuple[List[str], List[str]]:
    seeds, site_urls = [], []
    r = _get(urljoin(root, "/robots.txt"))
    if r and r.ok:
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    seeds.append(urljoin(root, path))
            if line.lower().startswith("sitemap:"):
                site_urls.append(line.split(":", 1)[1].strip())
    if not site_urls:
        site_urls = [urljoin(root, "/sitemap.xml")]
    for sm in site_urls:
        resp = _get(sm)
        if resp and resp.ok:
            try:
                soup = BeautifulSoup(resp.text, "xml")
                for loc in soup.find_all("loc"):
                    loc_url = (loc.text or "").strip()
                    if loc_url:
                        seeds.append(loc_url)
            except Exception:
                pass
    return list(set(seeds)), site_urls

def historical_urls_via_wayback(root: str, limit: int = 50) -> List[str]:
    try:
        host = urlparse(root).netloc
        api = f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit={limit}"
        resp = _get(api)
        results = []
        if resp and resp.ok:
            data = json.loads(resp.text)
            for row in data[1:]:
                orig = row[2]
                if orig.startswith(("http://", "https://")):
                    scheme = urlparse(root).scheme or "https"
                    results.append(orig.replace("http://", scheme + "://", 1))
        return list(set(results))
    except Exception:
        return []

def subdomains_via_crtsh(root: str, limit: int = 50) -> List[str]:
    try:
        parsed = urlparse(root)
        apex = parsed.hostname
        if not apex:
            return []
        q = f"https://crt.sh/?q=%25.{apex}&output=json"
        resp = _get(q)
        subs = set()
        if resp and resp.ok:
            try:
                data = json.loads(resp.text)
            except Exception:
                text = "[" + resp.text.replace("}{", "},{") + "]"
                data = json.loads(text)
            for item in data[:limit]:
                name = item.get("name_value", "")
                for host in name.split("\n"):
                    host = host.strip()
                    if host and host.endswith(apex):
                        scheme = parsed.scheme or "https"
                        subs.add(f"{scheme}://{host}")
        return list(subs)
    except Exception:
        return []

def guess_openapi_paths(root: str) -> List[str]:
    candidates = [
        "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
        "/v3/api-docs", "/api-docs", "/api/openapi.json"
    ]
    found = []
    for p in candidates:
        resp = _get(urljoin(root, p))
        if resp and resp.ok and (resp.headers.get("content-type", "").lower().startswith("application/json") or resp.text.strip().startswith("{")):
            found.append(urljoin(root, p))
    return found

def guess_graphql_endpoints(root: str) -> List[str]:
    candidates = ["/graphql", "/api", "/api/graphql", "/graphql/api"]
    found = []
    for p in candidates:
        url = urljoin(root, p)
        try:
            jr = requests.post(url, json={"query": "query{__typename}"}, headers=UA, timeout=DEFAULT_TIMEOUT)
            if jr.status_code in (200, 400) and ("__typename" in (jr.text or "")):
                found.append(url)
        except Exception:
            pass
    return list(set(found))

def extract_js_libs_and_links(soup: BeautifulSoup) -> Dict:
    libs = []
    links = []
    try:
        for s in soup.find_all("script", src=True):
            src = s.get("src") or ""
            links.append(src)
            m = re.search(r"/?([a-z0-9\.\-_]+?)-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", src, flags=re.I)
            if m:
                libs.append({"name": m.group(1).lower(), "version": m.group(2), "src": src})
    except Exception:
        pass
    return {"libs": libs, "links": links}

def crawl(root: str) -> Tuple[List[str], List[Dict], Dict]:
    root = root.rstrip("/")
    visited: List[str] = []
    forms: List[Dict] = []
    js_libs_unique: Dict[str, Dict] = {}

    robot_seeds, sitemaps = robots_and_sitemap_seeds(root)
    wayback = historical_urls_via_wayback(root, limit=50)
    crt = subdomains_via_crtsh(root, limit=50)
    openapi_docs = guess_openapi_paths(root)
    graphql_eps = guess_graphql_endpoints(root)

    queue: deque = deque()
    seen: Set[str] = set()

    for s in set(robot_seeds + wayback + [root]):
        if s.startswith(root):
            queue.append(s)

    while queue and len(visited) < 250:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)

        resp = _get(current)
        if not (resp and resp.ok):
            continue

        visited.append(current)
        soup = BeautifulSoup(resp.text, "html.parser")

        try:
            for a in soup.find_all("a", href=True):
                full = urljoin(current, a.get("href"))
                if same_origin(full, root) and full not in seen:
                    queue.append(full)
        except Exception:
            pass

        forms.extend(parse_forms(soup, current))

        js = extract_js_libs_and_links(soup)
        for lib in js["libs"]:
            key = f"{lib['name']}@{lib['version']}"
            if key not in js_libs_unique:
                js_libs_unique[key] = lib

    discovery = {
        "robots_seeds": robot_seeds,
        "sitemaps": sitemaps,
        "historical_urls": wayback,
        "subdomains": crt,
        "openapi_docs": openapi_docs,
        "graphql_endpoints": graphql_eps,
        "js_libs": list(js_libs_unique.values())
    }
    return visited, forms, discovery

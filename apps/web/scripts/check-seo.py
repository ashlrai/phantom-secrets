"""Validate rendered SEO contracts: python3 scripts/check-seo.py http://localhost:PORT."""
import sys
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from datetime import datetime


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.canonicals, self.links, self.ids, self.claims = [], [], set(), []
        self.sections, self.headings, self.noindex = [], 0, False
        self.feed(html)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "h1":
            self.headings += 1
        if tag == "meta" and attrs.get("name") == "robots":
            self.noindex = "noindex" in attrs.get("content", "")
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonicals.append(attrs.get("href"))
        if tag == "section":
            claim = {"id": attrs["data-claim"], "sources": []} if "data-claim" in attrs else None
            self.sections.append(claim)
            if claim is not None:
                self.claims.append(claim)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
            if "data-source" in attrs:
                for claim in self.sections:
                    if claim is not None:
                        claim["sources"].append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "section" and self.sections:
            self.sections.pop()


def check(base):
    origin = urllib.parse.urlsplit(base)
    assert origin.scheme == "http" and origin.hostname in {"localhost", "127.0.0.1"}, "Use a local production server"
    base = base.rstrip("/")
    cache = {}

    def fetch(path):
        if path not in cache:
            with urllib.request.urlopen(base + path, timeout=30) as response:
                assert response.status == 200, path
                assert "noindex" not in response.headers.get("X-Robots-Tag", ""), path
                cache[path] = response.read().decode()
        return cache[path]

    root = ET.fromstring(fetch("/sitemap.xml"))
    ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    assert root.tag == ns + "urlset", "Invalid sitemap namespace"
    urls = []
    for entry in root:
        assert entry.tag == ns + "url", "Invalid sitemap entry"
        assert len(entry.findall(ns + "loc")) == 1, "Each entry needs one URL"
        loc = entry.findtext(ns + "loc")
        parsed = urllib.parse.urlsplit(loc)
        assert parsed.scheme == "https" and parsed.netloc == "phm.dev", loc
        assert not parsed.query and not parsed.fragment, loc
        assert not parsed.path.endswith((".txt", ".json", ".xml")), loc
        assert not parsed.path.startswith(("/api/", "/dashboard", "/device", "/integrations/")), loc
        assert len(entry.findall(ns + "lastmod")) <= 1, loc
        modified = entry.findtext(ns + "lastmod")
        if modified:
            assert datetime.fromisoformat(modified.replace("Z", "+00:00")).tzinfo, modified
        urls.append(loc)
    assert len(urls) == len(set(urls)) and len(urls) > 7, "Duplicate or missing URLs"
    guides, claims, source_links = 0, 0, set()
    for url in urls:
        path = urllib.parse.urlsplit(url).path or "/"
        page = Page(fetch(path))
        assert page.canonicals == [url], f"Canonical mismatch: {path}: {page.canonicals}"
        assert not page.noindex, path
        assert page.headings == 1, f"Expected one H1: {path}"
        if path.startswith("/secrets/use-cases/"):
            guides += 1
            assert len(page.claims) >= 3, f"Missing claim blocks: {path}"
            for claim in page.claims:
                assert claim["sources"], f"Uncited claim: {path}#{claim['id']}"
                claims += 1
                source_links.update(claim["sources"])
            assert "/secrets#install" in page.links and "/docs" in page.links, path
            peers = [urllib.parse.urlsplit(url).path for url in urls if "/secrets/use-cases/" in url]
            assert all(peer in page.links for peer in peers if peer != path), path
            for link in page.links:
                if link.startswith("/") or link.startswith("#"):
                    target = urllib.parse.urlsplit(urllib.parse.urljoin(path, link))
                    target_page = Page(fetch(target.path))
                    if target.fragment:
                        assert target.fragment in target_page.ids, f"Broken fragment: {link}"
    assert 2 <= guides <= 4, f"Expected 2-4 guides, got {guides}"
    for path in ("/secrets", "/docs"):
        links = Page(fetch(path)).links
        assert all(urllib.parse.urlsplit(url).path in links for url in urls if "/secrets/use-cases/" in url), path
    print(f"PASS: sitemap XML, {len(urls)} canonical pages, {guides} linked guides, {claims} cited claim blocks, {len(source_links)} distinct sources; local links and fragments resolve.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    check(sys.argv[1])

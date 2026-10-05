#!/usr/bin/env python3
"""Validate local copy, static links and PNG format; never publishes anything."""
import argparse
import json
import struct
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "landingpage"
STORE = ROOT / "release/store"


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = set()

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            if attrs.get(key):
                self.links.append(attrs[key])


def check_store_copy():
    metadata = json.loads((STORE / "metadata.en.json").read_text())
    limits = [("app_store", "name", 30), ("app_store", "subtitle", 30),
              ("app_store", "promotional_text", 170), ("google_play", "name", 30),
              ("google_play", "short_description", 80)]
    for platform, field, limit in limits:
        count = len(metadata[platform][field])
        assert count <= limit, (platform, field, count, limit)
        print(f"{platform}.{field}: {count}/{limit}")
    assert len(metadata["description"]) <= 4000
    assert len(metadata["app_store"]["keywords"].encode()) <= 100
    print(f"Description: {len(metadata['description'])}/4000; keywords: {len(metadata['app_store']['keywords'].encode())}/100 bytes")


def check_landing():
    pages = {}
    for file in SITE.rglob("*.html"):
        parser = Links()
        parser.feed(file.read_text())
        pages[file.resolve()] = parser
    for file, parser in pages.items():
        for link in parser.links:
            parts = urlsplit(link)
            if parts.scheme or parts.netloc:
                continue
            target = (file.parent / unquote(parts.path)).resolve() if parts.path else file
            if target.is_dir():
                target /= "index.html"
            assert target.exists(), (file, link)
            if parts.fragment and target in pages:
                assert parts.fragment in pages[target].ids, (file, link)
    # Canonical variants, discovery files and social metadata must agree.
    canonical_paths = ["/", "/privacy/", "/terms/", "/support/", "/delete-account/", "/community/"]
    expected_urls = {"https://elo.now" + route for route in canonical_paths}
    sitemap = ET.parse(SITE / "sitemap.xml")
    actual_urls = {node.text for node in sitemap.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")}
    assert actual_urls == expected_urls, actual_urls
    assert "Sitemap: https://elo.now/sitemap.xml" in (SITE / "robots.txt").read_text()
    import re
    for file in pages:
        html = file.read_text()
        relative = file.relative_to(SITE)
        route = "/" if relative.parts[0] in {"index.html", "light", "dark"} else "/" + relative.parts[0] + "/"
        canonical = re.findall(r'<link rel="canonical" href="([^"]+)"', html)
        assert canonical == ["https://elo.now" + route], (file, canonical)
        assert 'property="og:image" content="https://elo.now/assets/social-preview.png"' in html, file
        assert 'name="twitter:card" content="summary_large_image"' in html, file
        schema = re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
        assert schema, file
        graph = json.loads(schema.group(1))["@graph"]
        assert any(node.get("@type") == "WebPage" and node.get("url") == canonical[0] for node in graph), file
        assert not any("aggregateRating" in node or "review" in node for node in graph), file
    preview = (SITE / "assets/social-preview.png").read_bytes()
    assert preview[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", preview[16:24]) == (1200, 630)
    print("Passed canonical, structured-data, sitemap, robots and social-image checks.")
    return len(pages)


def check_store_screenshots():
    manifest = json.loads((STORE / "assets.json").read_text())
    assert len(manifest["screenshots"]) == 12
    for entry in manifest["screenshots"]:
        data = (STORE / entry["platform"] / entry["file"]).read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", data[16:24])
        assert (width, height) == (entry["width"], entry["height"])
        assert data[25] == 2, "Expected opaque RGB PNG"
        assert len(entry["alt"]) <= 140


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--landing-only", action="store_true",
        help="Check the generated website without store materials or publisher configuration.",
    )
    args = parser.parse_args()
    if not args.landing_only:
        check_store_copy()
    page_count = check_landing()
    if args.landing_only:
        print(f"Passed {page_count} static pages; no store materials or publisher configuration needed.")
        return
    check_store_screenshots()
    print(f"Passed {page_count} static pages and 12 screenshot checks.")
    publisher = json.loads((SITE / "publisher.json").read_text())
    pending = [key for key in ("legal_name", "address", "support_email", "privacy_email") if not publisher.get(key)]
    if pending or not publisher.get("legal_review_complete"):
        print("PUBLICATION PENDING: publisher/service review; these checks validate local materials only.")


if __name__ == "__main__":
    main()

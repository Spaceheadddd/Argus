from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from scanner.core.requester import Requester


@dataclass
class CrawlerData:
    base_url: str
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    query_params: List[Dict] = field(default_factory=list)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Dict] = []
        self.links: List[str] = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
                "fields": [],
            }
        elif self._current_form and tag in ("input", "textarea", "select"):
            self._current_form["fields"].append({
                "name": attrs.get("name", ""),
                "type": attrs.get("type", "text"),
                "value": attrs.get("value", ""),
            })
        elif tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class Crawler:
    def __init__(self, requester: Requester):
        self.requester = requester

    def collect(self, url: str) -> CrawlerData:
        data = CrawlerData(base_url=url)
        resp = self.requester.get(url)
        if resp is None:
            return data

        try:
            html = resp.text
        except Exception:
            return data

        parser = _FormParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        data.forms = self._resolve_form_actions(parser.forms, url)
        data.links = self._resolve_links(parser.links, url)
        data.query_params = self._extract_query_params(data.links)

        # Also include the base URL itself if it has query params
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            flat = {k: v[0] for k, v in qs.items()}
            clean_url = url.split("?")[0]
            data.query_params.append({"url": clean_url, "params": flat})

        return data

    def _resolve_form_actions(self, forms: List[Dict], base_url: str) -> List[Dict]:
        resolved = []
        for form in forms:
            action = form["action"].strip()
            if not action:
                action = base_url
            else:
                action = urljoin(base_url, action)
            resolved.append({**form, "action": action})
        return resolved

    def _resolve_links(self, links: List[str], base_url: str) -> List[str]:
        resolved = []
        base_parsed = urlparse(base_url)
        for link in links:
            try:
                full = urljoin(base_url, link)
                parsed = urlparse(full)
                # Only keep same-host links
                if parsed.netloc == base_parsed.netloc:
                    resolved.append(full)
            except Exception:
                pass
        return list(set(resolved))

    def _extract_query_params(self, links: List[str]) -> List[Dict]:
        entries = []
        seen = set()
        for link in links:
            try:
                parsed = urlparse(link)
                if not parsed.query:
                    continue
                qs = parse_qs(parsed.query, keep_blank_values=True)
                flat = {k: v[0] for k, v in qs.items()}
                key = (parsed.scheme + "://" + parsed.netloc + parsed.path, tuple(sorted(flat.keys())))
                if key in seen:
                    continue
                seen.add(key)
                clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                entries.append({"url": clean_url, "params": flat})
            except Exception:
                pass
        return entries

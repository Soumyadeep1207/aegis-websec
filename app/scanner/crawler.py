from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from urllib.parse import urldefrag

import requests
from bs4 import BeautifulSoup

from .utils import same_origin, safe_join


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int
    title: str
    depth: int


class SameOriginCrawler:
    def __init__(self, timeout: float, max_pages: int = 10, max_depth: int = 1) -> None:
        self.timeout = timeout
        self.max_pages = max(1, min(max_pages, 50))
        self.max_depth = max(0, min(max_depth, 3))

    def crawl(self, start_url: str, session: requests.Session) -> list[CrawledPage]:
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        seen: set[str] = set()
        pages: list[CrawledPage] = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            clean_url = urldefrag(url)[0].rstrip("/")
            if clean_url in seen:
                continue
            seen.add(clean_url)

            try:
                response = session.get(clean_url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            content_type = response.headers.get("Content-Type", "")
            title = ""
            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, "html.parser")
                title_node = soup.find("title")
                title = title_node.get_text(" ", strip=True) if title_node else ""
                if depth < self.max_depth:
                    for anchor in soup.find_all("a", href=True):
                        candidate = safe_join(response.url, anchor["href"])
                        candidate = urldefrag(candidate)[0].rstrip("/")
                        if same_origin(start_url, candidate) and candidate not in seen:
                            queue.append((candidate, depth + 1))

            pages.append(CrawledPage(url=response.url.rstrip("/"), status_code=response.status_code, title=title, depth=depth))

        return pages

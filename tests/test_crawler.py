from app.scanner.crawler import SameOriginCrawler


class FakeResponse:
    def __init__(self, url, body, status_code=200):
        self.url = url
        self.text = body
        self.status_code = status_code
        self.headers = {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self):
        self.pages = {
            "https://example.test": FakeResponse(
                "https://example.test",
                "<title>Home</title><a href='/one?x=1'>One</a><a href='https://other.test/out'>Out</a>",
            ),
            "https://example.test/one?x=1": FakeResponse("https://example.test/one?x=1", "<title>One</title>"),
        }

    def get(self, url, timeout, allow_redirects=True):
        return self.pages[url]


def test_crawler_keeps_same_origin_links():
    crawler = SameOriginCrawler(timeout=1, max_pages=5, max_depth=1)
    pages = crawler.crawl("https://example.test", FakeSession())

    assert [page.url for page in pages] == ["https://example.test", "https://example.test/one?x=1"]

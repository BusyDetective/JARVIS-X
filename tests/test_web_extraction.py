from __future__ import annotations

import pytest

from app.web.errors import ExtractionError
from app.web.extraction import HtmlExtractor, normalize_whitespace, truncate_text

X = HtmlExtractor()


def ex(html, limit=10_000, base="https://example.com/dir/page", ctype="text/html"):
    return X.extract(html, ctype, limit, base)


PAGE = """<!doctype html><html><head><title>  My   Page </title>
<meta name="description" content="A description"><meta property="og:site_name" content="Site">
<meta name="author" content="Ann"><meta property="article:published_time" content="2025-02-03T04:05:06Z">
<link rel="canonical" href="https://example.com/canon">
<style>body{color:red}</style><script>var secret = 1;</script></head>
<body><nav>Home | About</nav><h1>Main Heading</h1><p>First <b>para</b> here.</p>
<h2>Sub</h2><ul><li>one</li><li>two</li></ul><script>alert('x')</script>
<a href="/rel">Rel link</a><a href="https://other.org/x">Abs</a><a href="javascript:x()">bad</a>
<a href="mailto:a@b.c">mail</a><footer>copyright junk</footer></body></html>"""


def test_title_text_headings_metadata_links():
    r = ex(PAGE)
    assert r.title == "My Page"
    assert "# Main Heading" in r.text and "## Sub" in r.text and "First para here." in r.text
    assert "- one" in r.text and "- two" in r.text
    assert r.headings == ["Main Heading", "Sub"]
    assert r.metadata["description"] == "A description" and r.metadata["author"] == "Ann"
    assert r.metadata["site_name"] == "Site" and r.metadata["published"] == "2025-02-03T04:05:06Z"
    assert r.metadata["canonical_url"] == "https://example.com/canon"
    assert [l.url for l in r.links] == ["https://example.com/rel", "https://other.org/x"]
    assert r.links[0].text == "Rel link"


def test_script_style_and_nonContent_removed():
    r = ex(PAGE)
    for junk in ("secret", "alert", "color:red", "Home | About", "copyright junk"):
        assert junk not in r.text


def test_malformed_html_is_tolerated():
    r = ex("<html><body><p>Unclosed <b>bold <div>nested<p>second<h1>Head</body>")
    assert "Unclosed" in r.text and "second" in r.text and "Head" in r.text
    r2 = ex("<<<>>> <p attr='unterminated>text</p> & stray </div></span>")
    assert isinstance(r2.text, str)


def test_unclosed_head_does_not_swallow_body():
    r = ex("<html><head><title>T</title><body><p>visible</p></body></html>")
    assert r.title == "T" and "visible" in r.text


def test_empty_and_whitespace_html():
    for html in ("", "   \n ", "<html></html>", "<html><body></body></html>"):
        r = ex(html)
        assert r.text == "" and r.title is None and r.truncated is False


def test_missing_title_falls_back():
    assert ex("<body><h1>Only Heading</h1><p>x</p></body>").title == "Only Heading"
    assert ex('<head><meta property="og:title" content="OG"></head><body>x</body>').title == "OG"
    assert ex("<body><p>nothing</p></body>").title is None


def test_non_html_text_types():
    r = X.extract("  line one \n\n\n\n line   two  ", "text/plain; charset=utf-8", 1000)
    assert r.text == "line one\n\nline two" and r.title is None
    assert X.extract('{"a": 1}', "application/json", 1000).text == '{"a": 1}'
    assert X.extract("plain text here", None, 1000).text == "plain text here"
    assert "<b>" not in X.extract("<html><body><b>x</b></body></html>", None, 1000).text  # sniffed as HTML


@pytest.mark.parametrize("ctype", ["image/png", "application/pdf", "application/octet-stream", "video/mp4"])
def test_unsupported_content_types_raise(ctype):
    with pytest.raises(ExtractionError):
        X.extract("data", ctype, 1000)


def test_truncation():
    html = "<html><body>" + "".join(f"<p>paragraph number {i} text</p>" for i in range(500)) + "</body></html>"
    r = ex(html, limit=300)
    assert r.truncated is True and len(r.text) <= 300 and not r.text.endswith(" ")
    assert ex("<p>short</p>", limit=300).truncated is False


def test_truncate_text_helper():
    assert truncate_text("abc", 10) == ("abc", False)
    t, cut = truncate_text("hello wonderful world", 15)
    assert cut is True and t == "hello"[:0] + t and len(t) <= 15


def test_very_large_page_is_bounded():
    html = "<html><body>" + "<p>" + "lorem ipsum " * 200_000 + "</p></body></html>"
    r = ex(html, limit=1_000)
    assert len(r.text) <= 1_000 and r.truncated


def test_link_cap_and_dedupe():
    html = "<body>" + "".join(f'<a href="/p{i}">l{i}</a><a href="/p{i}">dup</a>' for i in range(200)) + "</body>"
    r = ex(html)
    assert len(r.links) == 50 and len({l.url for l in r.links}) == 50


def test_normalize_whitespace():
    assert normalize_whitespace("a \u00a0 b\r\n\r\n\r\n c\t d") == "a b\n\nc d"
    assert normalize_whitespace("\n\n  x  \n\n") == "x"

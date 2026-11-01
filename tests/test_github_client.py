from __future__ import annotations

import logging

import httpx
import pytest

from app.github.api import RepositoryRef
from app.github.client import GitHubClient, GitHubLimits, HttpxGitHubClient
from app.github.errors import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubInvalidReferenceError,
    GitHubNotFoundError,
    GitHubPermissionError,
    GitHubRateLimitError,
)
from tests.github_helpers import (
    TOKEN, branch_json, commit_json, file_json, issue_json, json_handler, make_client, pr_json, repo_json,
)

R = RepositoryRef("octo", "demo")


async def test_get_repository_and_request_shape():
    seen = {}

    def handler(request: httpx.Request):
        seen.update(url=str(request.url), headers=dict(request.headers), method=request.method)
        return httpx.Response(200, json=repo_json(), headers={
            "x-ratelimit-limit": "60", "x-ratelimit-remaining": "58", "x-ratelimit-reset": "1700000000"})

    client = make_client(handler)
    repo = await client.get_repository(R)
    assert repo.full_name == "octo/demo" and seen["method"] == "GET"
    assert seen["url"] == "https://api.github.com/repos/octo/demo"
    assert "authorization" not in seen["headers"]  # unauthenticated works
    assert seen["headers"]["accept"] == "application/vnd.github+json"
    assert client.authenticated is False and client.rate_limit.remaining == 58 and client.rate_limit.limit == 60


async def test_token_sent_only_as_authorization_header():
    seen = {}

    def handler(request):
        seen["auth"], seen["url"] = request.headers.get("authorization"), str(request.url)
        return httpx.Response(200, json=repo_json())

    client = make_client(handler, token=TOKEN)
    await client.get_repository(R)
    assert seen["auth"] == f"Bearer {TOKEN}" and TOKEN not in seen["url"]
    assert client.authenticated and client.known_secrets() == (TOKEN,)
    assert TOKEN not in repr(client) and TOKEN not in str(client.limits)


async def test_blank_token_is_unauthenticated():
    assert HttpxGitHubClient("   ").authenticated is False and HttpxGitHubClient(None).known_secrets() == ()


async def test_search_repositories():
    seen = {}

    def handler(request):
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json={"total_count": 2, "incomplete_results": False,
                                         "items": [repo_json(name="a"), repo_json(name="b")]})

    res = await make_client(handler).search_repositories("  asyncio   lib ", limit=5)
    assert res.total_count == 2 and [r.name for r in res.repositories] == ["a", "b"] and res.query == "asyncio lib"
    assert seen["params"] == {"q": "asyncio lib", "per_page": "5"}


async def test_search_limit_is_clamped_and_results_bounded():
    items = [repo_json(name=f"r{i}") for i in range(50)]
    seen = {}

    def handler(request):
        seen["per_page"] = request.url.params["per_page"]
        return httpx.Response(200, json={"total_count": 50, "items": items})

    res = await make_client(handler, max_results=7).search_repositories("x", limit=100000)
    assert seen["per_page"] == "7" and len(res.repositories) == 7


async def test_search_malformed_and_invalid_query():
    with pytest.raises(GitHubAPIError, match="malformed"):
        await make_client(json_handler({"items": "nope"})).search_repositories("q")
    with pytest.raises(GitHubInvalidReferenceError):
        await make_client(json_handler({})).search_repositories("   ")


async def test_get_file_builds_safe_path_and_ref():
    seen = {}

    def handler(request):
        seen["url"], seen["params"] = str(request.url), dict(request.url.params)
        return httpx.Response(200, json=file_json("docs/my file.md", "# hi"))

    f = await make_client(handler).get_file(R, "docs/my file.md", "feature/x")
    assert f.content == "# hi" and seen["params"] == {"ref": "feature/x"}
    assert seen["url"].startswith("https://api.github.com/repos/octo/demo/contents/docs/my%20file.md")


async def test_get_file_rejects_bad_inputs_without_any_request():
    called = []
    client = make_client(lambda r: called.append(r) or httpx.Response(200, json={}))
    for path in ("", "../etc/passwd", "a/%2e%2e/b", "a\\b"):
        with pytest.raises(GitHubInvalidReferenceError):
            await client.get_file(R, path)
    with pytest.raises(GitHubInvalidReferenceError):
        await client.get_file(R, "a.py", "bad ref")
    assert called == []


async def test_get_file_on_directory_and_large_file():
    with pytest.raises(GitHubAPIError, match="directory"):
        await make_client(json_handler({"type": "dir"})).get_file(R, "src")
    big = await make_client(json_handler(file_json(text="x" * 5000)), max_file_size=1000).get_file(R, "a.py")
    assert big.content is None and big.truncated and big.encoding == "omitted"


async def test_list_directory_sorted_and_bounded():
    raw = [{"name": n, "path": n, "type": t, "size": 1, "sha": "s"} for n, t in
           [("z.py", "file"), ("src", "dir"), ("a.py", "file"), ("Docs", "dir")]]
    client = make_client(json_handler(raw), max_directory_entries=3)
    listing = await client.list_directory(R, "")
    assert [e.name for e in listing.entries] == ["Docs", "src", "a.py"]
    assert listing.total_entries == 4 and listing.truncated is True
    with pytest.raises(GitHubAPIError, match="file"):
        await make_client(json_handler(file_json())).list_directory(R, "a.py")


async def test_issue_and_pr_operations():
    client = make_client(json_handler(issue_json(9)))
    assert (await client.get_issue(R, 9)).number == 9
    assert (await make_client(json_handler(pr_json(5))).get_pull_request(R, 5)).head_branch == "feature"
    for bad in (0, -1, True, "7", 10**10):
        with pytest.raises(GitHubInvalidReferenceError):
            await client.get_issue(R, bad)


async def test_list_issues_excludes_pull_requests():
    payload = [issue_json(1), issue_json(2, pull_request={"url": "x"}), issue_json(3)]
    issues = await make_client(json_handler(payload)).list_issues(R, "open", 10)
    assert [i.number for i in issues] == [1, 3]
    with pytest.raises(GitHubInvalidReferenceError):
        await make_client(json_handler(payload)).list_issues(R, "weird", 10)


async def test_commit_branch_operations():
    c = await make_client(json_handler(commit_json())).get_commit(R, "main")
    assert c.message == "Fix the thing"
    commits = await make_client(json_handler([commit_json("a" * 40), commit_json("c" * 40)])).list_commits(R, "main", "src/x.py", 5)
    assert [x.sha[0] for x in commits] == ["a", "c"]
    branches = await make_client(json_handler([branch_json("main"), branch_json("dev")])).list_branches(R)
    assert [b.name for b in branches] == ["main", "dev"] and branches[0].protected
    with pytest.raises(GitHubInvalidReferenceError):
        await make_client(json_handler({})).get_commit(R, "  ")


# --- pagination and limits ---------------------------------------------------


async def test_single_page_when_limit_fits_one_page():
    pages = []

    def handler(request):
        pages.append((int(request.url.params["page"]), request.url.params["per_page"]))
        return httpx.Response(200, json=[branch_json(f"b{i}") for i in range(int(request.url.params["per_page"]))])

    out = await make_client(handler, max_results=100, max_pages=3).list_branches(R, limit=250)  # clamped to 100
    assert len(out) == 100 and pages == [(1, "100")]


async def test_pagination_continues_across_pages_but_stops_at_max_pages():
    """A filter (PRs are dropped from issue lists) can leave a page short of the
    requested count; paging then continues, but never beyond max_pages."""
    calls = []

    def handler(request):
        page = int(request.url.params["page"])
        calls.append(page)
        items = [issue_json(page * 100 + i, pull_request={"url": "x"}) for i in range(29)]
        return httpx.Response(200, json=items + [issue_json(page)])

    out = await make_client(handler, max_results=30, max_pages=3).list_issues(R, "all", 30)
    assert calls == [1, 2, 3] and [i.number for i in out] == [1, 2, 3]


async def test_pagination_stops_early_on_short_page():
    calls = []

    def handler(request):
        calls.append(int(request.url.params["page"]))
        return httpx.Response(200, json=[branch_json("only")])

    out = await make_client(handler, max_pages=5).list_branches(R, limit=30)
    assert calls == [1] and len(out) == 1


async def test_limit_one_and_defaults():
    out = await make_client(json_handler([branch_json("a"), branch_json("b")])).list_branches(R, limit=1)
    assert len(out) == 1
    assert GitHubLimits().clamp(None) == 30 and GitHubLimits().clamp(0) == 1 and GitHubLimits().clamp(-5) == 1


def test_limits_absurd_values_rejected():
    for kw in (dict(max_results=0), dict(max_results=101), dict(max_pages=11), dict(max_retries=6), dict(request_timeout_seconds=0)):
        with pytest.raises(ValueError):
            GitHubLimits(**kw)


# --- errors ----------------------------------------------------------------------


@pytest.mark.parametrize("status,exc,fragment", [
    (401, GitHubAuthenticationError, "credentials"),
    (403, GitHubPermissionError, "forbidden"),
    (404, GitHubNotFoundError, "not found"),
    (409, GitHubAPIError, "conflict"),
    (422, GitHubAPIError, "invalid"),
    (418, GitHubAPIError, "HTTP 418"),
])
async def test_http_errors_are_typed_safe_and_not_retried(status, exc, fragment):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(status, json={"message": f"secret detail {TOKEN}", "documentation_url": "x"})

    sleeps = []
    with pytest.raises(exc, match=fragment) as ei:
        await make_client(handler, token=TOKEN, sleeps=sleeps).get_repository(R)
    assert len(calls) == 1 and sleeps == []
    assert TOKEN not in str(ei.value) and "secret detail" not in str(ei.value)


async def test_429_is_rate_limit_error_and_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, headers={"retry-after": "30", "x-ratelimit-reset": "1700000000"}, text="slow down")

    with pytest.raises(GitHubRateLimitError) as ei:
        await make_client(handler).get_repository(R)
    assert len(calls) == 1 and ei.value.retry_after == 30.0 and ei.value.reset_at.year == 2023


@pytest.mark.parametrize("headers,body", [
    ({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}, "forbidden"),
    ({"retry-after": "60"}, "forbidden"),
    ({}, '{"message": "API rate limit exceeded for 1.2.3.4"}'),
])
async def test_403_rate_limit_variants(headers, body):
    with pytest.raises(GitHubRateLimitError) as ei:
        await make_client(lambda r: httpx.Response(403, headers=headers, text=body)).get_repository(R)
    assert "1.2.3.4" not in str(ei.value)


async def test_5xx_retried_with_bounded_attempts_then_fails():
    calls, sleeps = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(503, text=f"oops {TOKEN}")

    with pytest.raises(GitHubAPIError, match="unavailable") as ei:
        await make_client(handler, token=TOKEN, sleeps=sleeps, max_retries=2).get_repository(R)
    assert len(calls) == 3 and sleeps == [0.5, 1.0] and TOKEN not in str(ei.value)


async def test_5xx_then_success_and_retry_after_respected():
    calls, sleeps = [], []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(502, headers={"retry-after": "3"})
        return httpx.Response(200, json=repo_json())

    repo = await make_client(handler, sleeps=sleeps).get_repository(R)
    assert repo.name == "demo" and len(calls) == 2 and sleeps == [3.0]


async def test_huge_retry_after_fails_fast_without_sleeping():
    calls, sleeps = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(503, headers={"retry-after": "3600"})

    with pytest.raises(GitHubAPIError):
        await make_client(handler, sleeps=sleeps).get_repository(R)
    assert len(calls) == 1 and sleeps == []


async def test_zero_retries_configured():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(500)

    with pytest.raises(GitHubAPIError):
        await make_client(handler, max_retries=0).get_repository(R)
    assert len(calls) == 1


async def test_timeout_and_connection_errors_retried_then_typed_and_safe():
    calls = []

    def timeout(request):
        calls.append(1)
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(GitHubAPIError, match="timed out"):
        await make_client(timeout, max_retries=1).get_repository(R)
    assert len(calls) == 2

    def boom(request):
        raise httpx.ConnectError(f"cannot connect {TOKEN}", request=request)

    with pytest.raises(GitHubAPIError, match="could not reach") as ei:
        await make_client(boom, token=TOKEN, max_retries=0).get_repository(R)
    assert TOKEN not in str(ei.value)


async def test_malformed_json_and_shape():
    with pytest.raises(GitHubAPIError, match="malformed JSON"):
        await make_client(lambda r: httpx.Response(200, content=b"<html>not json")).get_repository(R)
    with pytest.raises(GitHubAPIError, match="malformed"):
        await make_client(json_handler(["a list"])).get_repository(R)
    with pytest.raises(GitHubAPIError, match="malformed"):
        await make_client(json_handler({"unexpected": 1})).list_branches(R)


async def test_oversized_response_rejected():
    big = httpx.Response(200, content=b'{"a": "' + b"x" * 50_000 + b'"}')
    with pytest.raises(GitHubAPIError, match="size limit"):
        await make_client(lambda r: big, max_response_bytes=10_000).get_repository(R)


async def test_redirects_only_to_same_https_host():
    def good(request):
        if request.url.path == "/repos/old/name":
            return httpx.Response(301, headers={"location": "https://api.github.com/repositories/42"})
        return httpx.Response(200, json=repo_json())

    assert (await make_client(good).get_repository(RepositoryRef("old", "name"))).id == 42
    for location in ("https://evil.example.com/steal", "http://api.github.com/x", "https://api.github.com.evil.com/x"):
        calls = []

        def bad(request, location=location):
            calls.append(str(request.url))
            return httpx.Response(302, headers={"location": location})

        with pytest.raises(GitHubAPIError, match="unexpected location"):
            await make_client(bad, token=TOKEN).get_repository(R)
        assert len(calls) == 1  # the token was never sent anywhere else


async def test_logs_never_contain_token_or_body(caplog):
    caplog.set_level(logging.DEBUG)
    await make_client(json_handler(repo_json(description="BODYMARKER")), token=TOKEN).get_repository(R)
    with pytest.raises(GitHubError_) as _:
        await make_client(lambda r: httpx.Response(401, text="BODYMARKER"), token=TOKEN).get_repository(R)
    assert TOKEN not in caplog.text and "BODYMARKER" not in caplog.text and "Bearer" not in caplog.text


GitHubError_ = GitHubAuthenticationError


def test_abstract_client_cannot_be_instantiated():
    with pytest.raises(TypeError):
        GitHubClient()

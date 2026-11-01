from __future__ import annotations

import pytest

from app.github.api import (
    RepositoryRef,
    parse_branch,
    parse_commit,
    parse_directory_entry,
    parse_file,
    parse_issue,
    parse_pull_request,
    parse_rate_limit,
    parse_repository,
    validate_path,
    validate_query,
    validate_ref,
)
from app.github.errors import GitHubAPIError, GitHubInvalidReferenceError
from tests.github_helpers import branch_json, commit_json, file_json, issue_json, pr_json, repo_json


@pytest.mark.parametrize("value,full", [
    ("octo/demo", "octo/demo"), ("  octo/demo  ", "octo/demo"), ("octo/demo.git", "octo/demo"),
    ("https://github.com/octo/demo", "octo/demo"), ("https://github.com/octo/demo.git", "octo/demo"),
    ("https://www.github.com/octo/demo/tree/main/src", "octo/demo"), ("github.com/octo/demo", "octo/demo"),
    ("o/my.repo-name_2", "o/my.repo-name_2"),
])
def test_valid_repository_references(value, full):
    assert RepositoryRef.parse(value).full_name == full


@pytest.mark.parametrize("value", [
    "", "   ", "octo", "octo/", "/demo", "a/b/c", "octo/..", "octo/.", "../etc", "-bad/demo", "octo/de mo",
    "octo/demo?x=1", "octo/demo#frag", "octo/de%6Fmo", "octo/de\nmo", "a" * 40 + "/x",
    "http://github.com/octo/demo", "https://evil.com/octo/demo", "https://github.com.evil.com/octo/demo",
    "https://user:pw@github.com/octo/demo", "https://github.com:8443/octo/demo", "ftp://github.com/octo/demo",
    "file:///etc/passwd", "https://api.github.com/repos/octo/demo", "https://github.com/octo",
    "javascript:alert(1)", "https://github.com@evil.com/octo/demo", "x" * 400,
])
def test_invalid_repository_references(value):
    with pytest.raises(GitHubInvalidReferenceError):
        RepositoryRef.parse(value)


@pytest.mark.parametrize("path,expected", [
    (None, ""), ("", ""), ("/", ""), ("src/app.py", "src/app.py"), ("/src/app.py/", "src/app.py"),
    ("docs/a b.md", "docs/a b.md"),
])
def test_valid_paths(path, expected):
    assert validate_path(path) == expected


@pytest.mark.parametrize("path", [
    "../x", "a/../b", "a/./b", "a//b", "..", "a\\b", "a/%2e%2e/b", "%2E%2e/x", "a%2fb", "a%5Cb", "a/%00",
    "a\x00b", "a\nb", "x" * 1100,
])
def test_invalid_paths(path):
    with pytest.raises(GitHubInvalidReferenceError):
        validate_path(path)


@pytest.mark.parametrize("ref", ["main", "feature/x-1", "v1.2.3", "a" * 40, "release_2025.1"])
def test_valid_refs(ref):
    assert validate_ref(ref) == ref
    assert validate_ref(None) is None and validate_ref("  ") is None


@pytest.mark.parametrize("ref", ["a..b", "-x", "/x", "x/", "a//b", "a b", "a;b", "a?b", "a@{1}", "x.lock", "a\nb", "a" * 300])
def test_invalid_refs(ref):
    with pytest.raises(GitHubInvalidReferenceError):
        validate_ref(ref)


def test_query_validation():
    assert validate_query("  asyncio   http  ") == "asyncio http"
    for bad in ("", "   ", "x" * 300):
        with pytest.raises(GitHubInvalidReferenceError):
            validate_query(bad)


def test_parse_repository():
    r = parse_repository(repo_json())
    assert (r.id, r.full_name, r.owner, r.default_branch, r.stars, r.open_issues) == (42, "octo/demo", "octo", "main", 7, 2)
    assert r.topics == ["a", "b"] and r.private is False and r.html_url.endswith("octo/demo")
    assert not hasattr(r, "node_id") and "node_id" not in r.model_dump()


def test_parse_issue_and_pr_flag():
    i = parse_issue(issue_json(3))
    assert (i.number, i.author, i.labels, i.comments, i.is_pull_request) == (3, "alice", ["bug", "help"], 3, False)
    assert i.created_at.tzinfo is not None
    assert parse_issue(issue_json(4, pull_request={"url": "x"})).is_pull_request is True


def test_parse_pull_request():
    p = parse_pull_request(pr_json(merged_at="2025-01-01T00:00:00Z", merged=False))
    assert (p.number, p.author, p.head_branch, p.base_branch, p.merged, p.draft) == (5, "bob", "feature", "main", True, False)


def test_parse_commit_branch_dir_entry():
    c = parse_commit(commit_json())
    assert c.sha == "a" * 40 and c.message == "Fix the thing" and c.author_name == "Carol" and c.author_login == "carol"
    assert c.date.tzinfo is not None and c.files[0].filename == "a.py" and c.files[0].additions == 3
    many = commit_json(files=[{"filename": f"f{i}", "status": "added"} for i in range(150)])
    cm = parse_commit(many, max_files=100)
    assert len(cm.files) == 100 and cm.files_truncated is True
    b = parse_branch(branch_json())
    assert (b.name, b.sha, b.protected) == ("main", "b" * 40, True)
    e = parse_directory_entry({"name": "x", "path": "d/x", "type": "file", "size": 5, "sha": "s", "html_url": "u"})
    assert (e.name, e.path, e.type, e.size) == ("x", "d/x", "file", 5)


def test_parse_file_text_binary_large_and_directory():
    f = parse_file(file_json(text="héllo\n"), 1000)
    assert f.content == "héllo\n" and f.encoding == "utf-8" and f.truncated is False and f.sha == "abc123"
    b = parse_file(file_json("img.bin", b"\x00\x01\x02binary"), 1000)
    assert b.content is None and b.encoding == "binary" and "binary" in b.note
    big = parse_file(file_json(text="x" * 50), 10)
    assert big.content is None and big.encoding == "omitted" and big.truncated and "limit" in big.note
    with pytest.raises(GitHubAPIError, match="directory"):
        parse_file({"type": "dir"}, 100)
    with pytest.raises(GitHubAPIError, match="unsupported"):
        parse_file({"type": "symlink"}, 100)
    no_inline = parse_file({**file_json(), "encoding": "none", "content": ""}, 1000)
    assert no_inline.content is None and no_inline.encoding == "omitted"


@pytest.mark.parametrize("fn,raw", [
    (parse_repository, {"id": 1}), (parse_repository, []), (parse_repository, "x"),
    (parse_issue, {"number": 1}), (parse_pull_request, {}), (parse_commit, {"sha": "x", "commit": 5}),
    (parse_branch, {"name": "a"}), (parse_directory_entry, {"name": "a"}),
])
def test_malformed_payloads_raise_api_error(fn, raw):
    with pytest.raises(GitHubAPIError, match="malformed"):
        fn(raw)


def test_parse_rate_limit():
    rl = parse_rate_limit({"x-ratelimit-limit": "60", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"})
    assert (rl.limit, rl.remaining) == (60, 0) and rl.reset_at.tzinfo is not None and rl.reset_at.year == 2023
    assert parse_rate_limit({}) is None
    assert parse_rate_limit({"x-ratelimit-remaining": "abc"}) is None

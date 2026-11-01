"""Shared fakes for the Phase 7 tests. No network."""
from __future__ import annotations

import base64

import httpx

from app.github.client import GitHubLimits, HttpxGitHubClient

TOKEN = "ghp_TESTTOKENabcdefghijklmnopqrstuvwxyz0123"


def repo_json(owner="octo", name="demo", **kw):
    return {"id": 42, "full_name": f"{owner}/{name}", "name": name, "owner": {"login": owner},
            "description": "A demo", "default_branch": "main", "private": False, "archived": False,
            "fork": False, "language": "Python", "stargazers_count": 7, "open_issues_count": 2,
            "topics": ["a", "b"], "html_url": f"https://github.com/{owner}/{name}", **kw}


def file_json(path="src/app.py", text="print('hi')\n", **kw):
    raw = text.encode() if isinstance(text, str) else text
    return {"type": "file", "name": path.split("/")[-1], "path": path, "sha": "abc123", "size": len(raw),
            "encoding": "base64", "content": base64.b64encode(raw).decode(),
            "html_url": f"https://github.com/octo/demo/blob/main/{path}", **kw}


def issue_json(number=1, **kw):
    return {"number": number, "title": f"Issue {number}", "state": "open", "user": {"login": "alice"},
            "body": "body text", "labels": [{"name": "bug"}, {"name": "help"}], "comments": 3,
            "created_at": "2025-01-02T03:04:05Z", "updated_at": "2025-01-03T03:04:05Z",
            "html_url": f"https://github.com/octo/demo/issues/{number}", **kw}


def pr_json(number=5, **kw):
    return {"number": number, "title": f"PR {number}", "state": "open", "user": {"login": "bob"},
            "body": "pr body", "head": {"ref": "feature"}, "base": {"ref": "main"}, "merged": False,
            "draft": False, "created_at": "2025-02-02T00:00:00Z", "updated_at": "2025-02-03T00:00:00Z",
            "html_url": f"https://github.com/octo/demo/pull/{number}", **kw}


def commit_json(sha="a" * 40, **kw):
    return {"sha": sha, "html_url": f"https://github.com/octo/demo/commit/{sha}", "author": {"login": "carol"},
            "commit": {"message": "Fix the thing", "author": {"name": "Carol", "date": "2025-03-04T05:06:07Z"}},
            "files": [{"filename": "a.py", "status": "modified", "additions": 3, "deletions": 1}], **kw}


def branch_json(name="main"):
    return {"name": name, "commit": {"sha": "b" * 40}, "protected": name == "main"}


def make_client(handler, token=None, sleeps=None, **limits) -> HttpxGitHubClient:
    async def fake_sleep(seconds):
        if sleeps is not None:
            sleeps.append(seconds)

    return HttpxGitHubClient(token, GitHubLimits(**limits), httpx.MockTransport(handler), sleep=fake_sleep)


def json_handler(payload, headers=None, status=200):
    def handler(request):
        return httpx.Response(status, json=payload, headers=headers or {})

    return handler

from __future__ import annotations

import os

import pytest

from app.workspace.errors import (
    WorkspaceAccessDeniedError, WorkspaceError, WorkspaceFileTooLargeError, WorkspacePathError,
    WorkspaceUnsupportedFileError,
)
from app.workspace.manager import WorkspaceLimits, WorkspaceManager, is_protected_path


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "project"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "src" / "main.py").write_text("import os\n\ndef main():\n    return 'Hello World'\n")
    (root / "src" / "pkg" / "util.py").write_text("def helper():\n    return 1  # hello again\n")
    (root / "docs" / "guide.md").write_text("# Guide\nhello docs\n")
    (root / "README.md").write_text("# Project\n")
    (root / ".env").write_text("API_KEY=supersecretvalue123\n")
    (root / ".env.example").write_text("API_KEY=changeme\n")
    (root / "server.pem").write_text("pem")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[remote] url=https://token@github.com/x/y")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("hello from dep")
    (root / "image.bin").write_bytes(b"\x89PNG\x00\x01\x02binary")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside hello")
    return WorkspaceManager(root)


def test_root_must_exist(tmp_path):
    with pytest.raises(WorkspaceError):
        WorkspaceManager(tmp_path / "missing")
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(WorkspaceError):
        WorkspaceManager(f)


def test_get_project_root_is_resolved(ws, tmp_path):
    assert ws.get_project_root() == (tmp_path / "project").resolve()


@pytest.mark.parametrize("bad", [
    "../outside/secret.txt", "src/../../outside/secret.txt", "..", "/etc/passwd", "~/x", "C:/Windows/win.ini",
    "src\\main.py", "src/%2e%2e/%2e%2e/outside", "%2e%2e/x", "src/a%2fb", "a\x00b", "x" * 1100,
])
def test_path_traversal_and_absolute_paths_rejected(ws, bad):
    for op in (ws.read_file, ws.list_files, ws.exists):
        with pytest.raises(WorkspacePathError):
            op(bad)
    with pytest.raises(WorkspacePathError):
        ws.search_files("hello", bad)


def test_absolute_path_inside_root_still_rejected(ws):
    with pytest.raises(WorkspacePathError, match="absolute"):
        ws.read_file(str(ws.get_project_root() / "README.md"))


def test_symlink_escape_blocked(ws, tmp_path):
    root = ws.get_project_root()
    (root / "link_dir").symlink_to(tmp_path / "outside", target_is_directory=True)
    (root / "link_file").symlink_to(tmp_path / "outside" / "secret.txt")
    for bad in ("link_dir/secret.txt", "link_file"):
        with pytest.raises(WorkspacePathError, match="outside"):
            ws.read_file(bad)
    with pytest.raises(WorkspacePathError):
        ws.list_files("link_dir")
    listed = {e.path for e in ws.list_files(recursive=True).entries}
    assert "link_dir" not in listed and "link_file" not in listed
    assert all("outside hello" not in m.line for m in ws.search_files("outside").matches)
    assert ws.search_files("outside hello").matches == []


def test_internal_symlink_to_protected_file_is_still_protected(ws):
    (ws.get_project_root() / "innocent.txt").symlink_to(ws.get_project_root() / ".env")
    with pytest.raises(WorkspaceAccessDeniedError):
        ws.read_file("innocent.txt")


def test_internal_symlink_to_normal_file_is_readable(ws):
    (ws.get_project_root() / "alias.md").symlink_to(ws.get_project_root() / "README.md")
    assert ws.read_file("alias.md").content.startswith("# Project")


def test_list_files_is_deterministic_and_never_leaks_absolute_paths(ws):
    first = ws.list_files(recursive=True)
    second = ws.list_files(recursive=True)
    assert first == second
    paths = [e.path for e in first.entries]
    assert paths == sorted(paths)
    assert "src/pkg/util.py" in paths and "docs" in paths
    assert not any(p.startswith("/") or str(ws.get_project_root()) in p for p in paths)
    assert ".git" not in paths and not any(p.startswith(".git/") or p.startswith("node_modules") for p in paths)
    assert first.path == "."


def test_non_recursive_listing_and_subdirectory(ws):
    top = {e.path: e for e in ws.list_files().entries}
    assert "src" in top and top["src"].type == "dir" and "src/main.py" not in top
    sub = [e.path for e in ws.list_files("src").entries]
    assert sub == ["src/main.py", "src/pkg"]
    with pytest.raises(WorkspacePathError, match="not a directory"):
        ws.list_files("README.md")


def test_protected_files_listed_as_metadata_only(ws):
    entries = {e.path: e for e in ws.list_files().entries}
    for name in (".env", "server.pem"):
        assert entries[name].protected is True and entries[name].size is None
    assert entries[".env.example"].protected is False and entries["README.md"].size == 10


@pytest.mark.parametrize("path", [".env", ".env.local", ".env.production", "server.pem", "my.key", "id_rsa", "id_ed25519.pub",
                                  "credentials.json", "secrets.yaml", ".netrc", ".npmrc", "a/b/.env", ".git/config",
                                  ".ssh/id_rsa", ".aws/credentials", "x.token", "token.json", "keystore.jks"])
def test_protected_path_patterns(path):
    assert is_protected_path(path)


@pytest.mark.parametrize("path", ["README.md", "src/main.py", ".env.example", ".env.sample", "tokenizer.py", "keyboard.py",
                                  "docs/credentials_guide.md", "environment.py", "monkey.py"])
def test_non_protected_paths(path):
    assert not is_protected_path(path)


def test_protected_files_never_readable(ws):
    for p in (".env", "server.pem", ".git/config"):
        with pytest.raises(WorkspaceAccessDeniedError, match="protected"):
            ws.read_file(p)
        with pytest.raises(WorkspaceAccessDeniedError):
            ws.read_text(p)
    assert ws.read_file(".env.example").content.startswith("API_KEY")


def test_protected_content_never_appears_in_search_or_errors(ws):
    assert ws.search_files("supersecretvalue123").matches == []
    with pytest.raises(WorkspaceAccessDeniedError) as ei:
        ws.read_file(".env")
    assert "supersecretvalue123" not in str(ei.value)


def test_private_key_content_in_ordinary_file_is_refused(ws):
    (ws.get_project_root() / "notes.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n")
    with pytest.raises(WorkspaceAccessDeniedError, match="private key"):
        ws.read_file("notes.txt")
    assert ws.search_files("MIIabc").matches == []


def test_secret_looking_text_redacted_in_read_and_search(ws):
    (ws.get_project_root() / "cfg.py").write_text("DB = 'x'\npassword = 'hunter2hunter2'\ntoken = ghp_abcdefghijklmnopqrstuvwxyz0123\n")
    c = ws.read_file("cfg.py")
    assert "hunter2hunter2" not in c.content and "ghp_abcdef" not in c.content and c.redactions == 2
    hits = ws.search_files("password").matches
    assert hits and all("hunter2hunter2" not in m.line for m in hits)


def test_read_file_metadata_and_hash(ws):
    import hashlib
    c = ws.read_file("src/main.py")
    raw = (ws.get_project_root() / "src/main.py").read_bytes()
    assert c.path == "src/main.py" and c.size == len(raw) and c.sha256 == hashlib.sha256(raw).hexdigest()
    assert c.line_count == 4 and "def main" in c.content and c.truncated is False and c.redactions == 0
    assert ws.read_text("src/main.py") == (raw.decode(), c.sha256)


def test_binary_and_missing_and_directory(ws):
    with pytest.raises(WorkspaceUnsupportedFileError, match="binary"):
        ws.read_file("image.bin")
    with pytest.raises(WorkspacePathError, match="not found"):
        ws.read_file("nope.txt")
    with pytest.raises(WorkspacePathError, match="regular file"):
        ws.read_file("src")


def test_file_size_limit(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "big.txt").write_text("x" * 5000)
    (root / "ok.txt").write_text("fine")
    w = WorkspaceManager(root, WorkspaceLimits(max_file_size=1000))
    with pytest.raises(WorkspaceFileTooLargeError, match="5000 bytes"):
        w.read_file("big.txt")
    assert w.read_file("ok.txt").content == "fine"
    res = w.search_files("x")
    assert res.matches == [] and res.files_scanned == 2  # the oversized file is skipped, never read


def test_output_char_limit(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.txt").write_text("line\n" * 1000)
    c = WorkspaceManager(root, WorkspaceLimits(max_output_chars=500)).read_file("a.txt")
    assert c.truncated is True and len(c.content) <= 500 and c.size == 5000


def test_file_count_limit_on_listing(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    for i in range(20):
        (root / f"f{i:02d}.txt").write_text("x")
    listing = WorkspaceManager(root, WorkspaceLimits(max_files=5)).list_files(recursive=True)
    assert len(listing.entries) == 5 and listing.truncated is True
    assert [e.path for e in listing.entries] == [f"f{i:02d}.txt" for i in range(5)]


def test_search_basic_filters_and_ordering(ws):
    res = ws.search_files("hello")
    assert [(m.path, m.line_number) for m in res.matches] == [("docs/guide.md", 2), ("src/main.py", 4), ("src/pkg/util.py", 2)]
    assert res.files_scanned >= 4 and res.truncated is False
    assert ws.search_files("hello") == res  # deterministic
    assert [m.path for m in ws.search_files("hello", extensions=["py"]).matches] == ["src/main.py", "src/pkg/util.py"]
    assert [m.path for m in ws.search_files("hello", extensions=[".MD"]).matches] == ["docs/guide.md"]
    assert [m.path for m in ws.search_files("hello", path="src/pkg").matches] == ["src/pkg/util.py"]
    assert [m.path for m in ws.search_files("hello", glob="docs/*.md").matches] == ["docs/guide.md"]
    assert ws.search_files("HELLO", case_sensitive=True).matches == []
    assert len(ws.search_files("HELLO").matches) == 3
    assert ws.search_files("zzzzzz").matches == []


def test_search_excludes_ignored_protected_and_binary(ws):
    paths = {m.path for m in ws.search_files("hello").matches}
    assert not any(p.startswith("node_modules") for p in paths)
    assert ws.search_files("remote").matches == []  # .git/config
    assert ws.search_files("PNG").matches == []


def test_search_result_bound_and_regex_is_not_interpreted(ws):
    root = ws.get_project_root()
    (root / "many.txt").write_text("\n".join(f"needle {i}" for i in range(100)))
    limited = WorkspaceManager(root, WorkspaceLimits(max_search_results=5))
    res = limited.search_files("needle", max_results=100000)
    assert len(res.matches) == 5 and res.truncated is True
    assert len(limited.search_files("needle", max_results=2).matches) == 2
    (root / "re.txt").write_text("a.*b literal")
    assert [m.path for m in ws.search_files("a.*b").matches] == ["re.txt"]


def test_search_scan_limit_and_query_validation(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    for i in range(10):
        (root / f"f{i}.txt").write_text("nothing")
    res = WorkspaceManager(root, WorkspaceLimits(max_files=3)).search_files("zzz")
    assert res.files_scanned == 3 and res.truncated is True
    w = WorkspaceManager(root)
    for bad in ("", "   ", "x" * 300, "a\x00b"):
        with pytest.raises(WorkspacePathError):
            w.search_files(bad)
    with pytest.raises(WorkspacePathError):
        w.search_files("x", glob="../*")
    with pytest.raises(WorkspacePathError):
        w.search_files("x", glob="/etc/*")


def test_long_lines_are_cut(ws):
    (ws.get_project_root() / "long.txt").write_text("needle " + "x" * 2000)
    assert len(ws.search_files("needle").matches[0].line) <= 300


def test_validate_writable_target_checks_but_never_creates(ws):
    assert ws.validate_writable_target("src/new_module.py") == "src/new_module.py"
    assert not (ws.get_project_root() / "src" / "new_module.py").exists()
    for bad, exc in [("../x.py", WorkspacePathError), ("", WorkspacePathError), ("src", WorkspacePathError),
                     (".env", WorkspaceAccessDeniedError), (".git/hooks/pre-commit", WorkspaceAccessDeniedError)]:
        with pytest.raises(exc):
            ws.validate_writable_target(bad)


def test_workspace_makes_no_modifications(ws):
    root = ws.get_project_root()
    before = sorted((str(p.relative_to(root)), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file())
    ws.list_files(recursive=True); ws.read_file("README.md"); ws.search_files("hello")
    for bad in (".env", "../x"):
        with pytest.raises(WorkspaceError):
            ws.read_file(bad)
    after = sorted((str(p.relative_to(root)), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file())
    assert before == after and sorted(os.listdir(root.parent)) == ["outside", "project"]


def test_limits_validation():
    for kw in (dict(max_file_size=1), dict(max_files=0), dict(max_search_results=0), dict(max_output_chars=1)):
        with pytest.raises(ValueError):
            WorkspaceLimits(**kw)

from __future__ import annotations

import json

import pytest

from app.versioning.manager import ReleaseExistsError, ReleaseNotFoundError, ReleaseStore, VersioningError
from app.versioning.manifest import (
    build_manifest, compare_manifests, hash_tree, is_snapshot_path, parse_version, read_dependencies, read_git_commit,
)
from app.versioning.models import TestBaseline, UpdateManifest
from tests.improvement_helpers import make_project, tree_hashes


@pytest.fixture
def project(tmp_path):
    return make_project(tmp_path / "project", {".env": "SECRET=1", ".git/HEAD": "ref: refs/heads/main\n",
                                               ".git/refs/heads/main": "a" * 40 + "\n", "data/x.db": "db", "id_rsa": "k"})


@pytest.fixture
def store(tmp_path):
    return ReleaseStore(tmp_path / "store")


def test_manifest_is_deterministic_and_has_no_secrets(project):
    a, b = build_manifest(project), build_manifest(project)
    assert a.content_hash == b.content_hash and [f.path for f in a.files] == sorted(f.path for f in a.files)
    paths = {f.path for f in a.files}
    assert {"app/util.py", "README.md", "requirements.txt"} <= paths
    assert not paths & {".env", "id_rsa", "data/x.db", ".git/HEAD"}
    blob = a.model_dump_json()
    assert "SECRET=1" not in blob and "def add" not in blob  # hashes only, never contents
    assert a.git_commit == "a" * 40 and a.dependencies["runtime"] == ["httpx>=0.27"]
    assert a.dependencies["dev"] == ["pytest>=8"]


def test_manifest_changes_with_content_and_compares(project, tmp_path):
    before = build_manifest(project)
    (project / "app" / "util.py").write_text("def add(a, b):\n    return b + a\n")
    (project / "app" / "extra.py").write_text("x = 1\n")
    (project / "README.md").unlink()
    (project / "requirements.txt").write_text("httpx>=0.28\n")
    after = build_manifest(project, TestBaseline(passed=5))
    assert before.content_hash != after.content_hash
    diff = compare_manifests(before.model_copy(update={"test_baseline": TestBaseline(passed=2)}), after)
    assert diff.added == ["app/extra.py"] and diff.removed == ["README.md"] and diff.modified == ["app/util.py", "requirements.txt"]
    assert diff.dependencies_changed is True and diff.config_changed is False and diff.test_count_delta == 3


def test_snapshot_path_rules():
    for ok in ("app/a.py", "README.md", "tests/test_a.py", ".env.example"):
        assert is_snapshot_path(ok)
    for bad in (".env", "a/.env", "id_rsa", "x.pem", ".git/config", "data/a.db", "logs/a.log", "workspace/a", "a/__pycache__/b.py",
                "node_modules/x.js", "venv/lib/x.py", "a.pyc", "app.db", ""):
        assert not is_snapshot_path(bad), bad


def test_dependencies_and_git_commit(tmp_path):
    (tmp_path / "requirements.txt").write_text("# comment\n\nhttpx>=1\n-r other.txt\npydantic<3\n")
    assert read_dependencies(tmp_path) == {"runtime": ["httpx>=1", "pydantic<3"]}
    assert read_git_commit(tmp_path) is None
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("b" * 40)
    assert read_git_commit(tmp_path) == "b" * 40


def test_create_release_and_verify(store, project):
    v = store.create_release(project, UpdateManifest(version="x", risk_level="low"))
    assert parse_version(v) == 1 and v.startswith("v0001-") and store.has_release(v)
    assert store.verify_release(v).valid is True
    assert not (store.release_source(v) / ".env").exists() and not (store.release_source(v) / "data").exists()
    assert store.read_update(v).version == v and store.read_manifest(v).content_hash == build_manifest(project).content_hash
    assert list(store.releases_dir.glob(".tmp-*")) == []


def test_version_ids_are_deterministic_by_content(tmp_path, project):
    a, b = ReleaseStore(tmp_path / "a"), ReleaseStore(tmp_path / "b")
    assert a.create_release(project) == b.create_release(project)
    (project / "app" / "util.py").write_text("changed\n")
    second = a.create_release(project)
    assert second.startswith("v0002-") and a.list_releases()[-1] == second


def test_verify_detects_modified_missing_and_unexpected_files(store, project):
    v = store.create_release(project)
    src = store.release_source(v)
    (src / "app" / "util.py").write_text("tampered")
    (src / "README.md").unlink()
    (src / "extra.py").write_text("x")
    report = store.verify_release(v)
    assert report.valid is False and report.modified == ["app/util.py"] and report.missing == ["README.md"] and report.unexpected == ["extra.py"]


def test_verify_of_unreadable_or_missing_release(store, project):
    v = store.create_release(project)
    (store.releases_dir / v / "manifest.json").write_text("{not json")
    assert store.verify_release(v).valid is False
    assert store.verify_release("v0042-0123456789").valid is False


@pytest.mark.parametrize("bad", ["../x", "v1", "latest", "v0001-XYZ", "", "v0001-0123456789/../..", "/etc"])
def test_invalid_version_identifiers(store, bad):
    with pytest.raises(ReleaseNotFoundError):
        store.release_source(bad)
    assert store.has_release(bad) is False


def test_pointer_is_atomic_and_validated(store, project):
    v1 = store.create_release(project)
    assert store.current() is None
    store.write_pointer(v1, [])
    assert store.current_version() == v1 and json.loads(store.pointer_path.read_text())["version"] == v1
    assert [p.name for p in store.root.iterdir() if p.name.startswith(".")] == []  # no stray temp files
    with pytest.raises(ReleaseNotFoundError):
        store.write_pointer("v0099-0123456789", [])
    store.pointer_path.write_text("garbage")
    with pytest.raises(VersioningError, match="unreadable"):
        store.current()


def test_bootstrap_is_idempotent_and_reads_only(store, project):
    before = tree_hashes(project)
    v = store.bootstrap(project)
    assert store.bootstrap(project) == v and store.list_releases() == [v] and store.current_version() == v
    assert tree_hashes(project) == before


def test_baseline_is_write_once(store, project):
    v = store.create_release(project)
    assert store.get_baseline(v) is None
    store.record_baseline(v, TestBaseline(passed=7))
    assert store.get_baseline(v).passed == 7 and store.read_manifest(v).test_baseline.passed == 7
    with pytest.raises(ReleaseExistsError):
        store.record_baseline(v, TestBaseline(passed=99))
    with pytest.raises(ReleaseNotFoundError):
        store.record_baseline("v0099-0123456789", TestBaseline(passed=1))
    assert store.verify_release(v).valid is True  # baseline.json is metadata, not release content


def test_remove_unreferenced_release_protects_current_and_history(store, project):
    v1 = store.create_release(project)
    (project / "app" / "util.py").write_text("v2\n")
    v2 = store.create_release(project)
    (project / "app" / "util.py").write_text("v3\n")
    v3 = store.create_release(project)
    store.write_pointer(v3, [v1, v2])
    for protected in (v1, v2, v3):
        with pytest.raises(VersioningError, match="refusing"):
            store.remove_unreferenced_release(protected)
    store.write_pointer(v1, [])
    assert store.remove_unreferenced_release(v3) is True and not store.has_release(v3) and store.has_release(v2)


def test_cleanup_temp_dirs(store):
    (store.releases_dir / ".tmp-abc").mkdir()
    (store.releases_dir / ".tmp-def").mkdir()
    assert store.cleanup_temp_dirs() == 2 and store.list_releases() == []


def test_hash_tree_strict_mode_includes_everything(tmp_path):
    (tmp_path / ".env").write_text("x")
    (tmp_path / "a.txt").write_text("y")
    assert set(hash_tree(tmp_path)) == {"a.txt"} and set(hash_tree(tmp_path, only_snapshot=False)) == {".env", "a.txt"}


def test_source_modules_with_sensitive_sounding_names_are_included_but_data_files_are_not(tmp_path):
    """Regression: a snapshot once dropped app/memory/secrets.py (a source module) because of a
    filename rule meant for data files, which silently produced an incomplete release."""
    for rel in ("app/memory/secrets.py", "app/security/credentials.py", "app/auth/token.py"):
        assert is_snapshot_path(rel), rel
    for rel in ("config/secrets.json", "credentials.yaml", "secrets.yml", "keys/token.txt", ".env", ".ssh/anything.py", ".git/hooks/x.py", "a/.aws/creds.py"):
        assert not is_snapshot_path(rel), rel
    project = make_project(tmp_path / "p", {"app/memory/__init__.py": "", "app/memory/secrets.py": "def find():\n    return 1\n", "secrets.json": "{}"})
    paths = {f.path for f in build_manifest(project).files}
    assert "app/memory/secrets.py" in paths and "secrets.json" not in paths

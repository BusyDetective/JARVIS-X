from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterator

from app.versioning.models import FileEntry, ManifestDiff, SystemManifest, TestBaseline
from app.workspace.manager import is_protected_path

PROJECT_VERSION = "0.8.0"
CONFIG_SCHEMA_VERSION = 1

# Never part of a source snapshot: VCS data, environments, caches, runtime
# data (databases, logs, workspaces) and anything that may hold secrets.
SNAPSHOT_EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
                          ".ruff_cache", ".tox", ".idea", "node_modules", ".eggs"}
SNAPSHOT_EXCLUDED_TOP_LEVEL = {"data", "logs", "workspace"}
SNAPSHOT_EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".log", ".db-wal", ".db-shm")
_VERSION_RE = re.compile(r"^v(\d{4})-[0-9a-f]{10}$")


def is_snapshot_path(rel_posix: str) -> bool:
    """True if a relative path belongs in a source snapshot / may be changed."""
    parts = [p for p in rel_posix.split("/") if p]
    if not parts:
        return False
    if parts[0] in SNAPSHOT_EXCLUDED_TOP_LEVEL:
        return False
    if any(p in SNAPSHOT_EXCLUDED_DIRS for p in parts[:-1]) or parts[-1] in SNAPSHOT_EXCLUDED_DIRS:
        return False
    if parts[-1].endswith(SNAPSHOT_EXCLUDED_SUFFIXES) or is_secret_bearing(rel_posix):
        return False
    return True


_SECRET_DIRS = {".git", ".ssh", ".aws", ".gnupg", ".kube", ".docker"}


def is_secret_bearing(rel_posix: str) -> bool:
    """Likely to hold secrets: protected folders, or data-like files whose NAME suggests it
    (.env, *.pem, *.key, credentials.json, secrets.yaml, ...). Python SOURCE files are code
    even when named like app/memory/secrets.py, so they are not secret-bearing here (they are
    still classified CRITICAL by the change classifier)."""
    parts = [p for p in rel_posix.split("/") if p]
    if any(p in _SECRET_DIRS for p in parts):
        return True
    if parts and parts[-1].endswith(".py"):
        return False
    return is_protected_path(rel_posix)


def iter_snapshot_files(root: Path) -> Iterator[tuple[str, Path]]:
    """(relative POSIX path, absolute path) for every snapshot-eligible regular
    file, deterministic order. Symlinks are never followed or included."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = sorted(
            d for d in dirnames
            if not (Path(dirpath, d).is_symlink()) and is_snapshot_dir(f"{rel_dir}/{d}" if rel_dir != "." else d)
        )
        for name in sorted(filenames):
            full = Path(dirpath, name)
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if full.is_symlink() or not full.is_file() or not is_snapshot_path(rel):
                continue
            yield rel, full


def is_snapshot_dir(rel_posix: str) -> bool:
    parts = [p for p in rel_posix.split("/") if p]
    if not parts:
        return True
    if parts[0] in SNAPSHOT_EXCLUDED_TOP_LEVEL and len(parts) >= 1:
        return False
    return not any(p in SNAPSHOT_EXCLUDED_DIRS or p in (".ssh", ".aws", ".gnupg", ".kube", ".docker") for p in parts)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: Path, only_snapshot: bool = True) -> dict[str, str]:
    """{relative path: sha256}. With only_snapshot=False EVERY regular file under
    root is included (used for strict release verification)."""
    if only_snapshot:
        return {rel: sha256_file(full) for rel, full in iter_snapshot_files(root)}
    root = root.resolve()
    out: dict[str, str] = {}
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for name in sorted(filenames):
            full = Path(dirpath, name)
            if full.is_file():
                out[full.relative_to(root).as_posix()] = sha256_file(full)
    return dict(sorted(out.items()))


def read_dependencies(root: Path) -> dict[str, list[str]]:
    deps: dict[str, list[str]] = {}
    for name, key in (("requirements.txt", "runtime"), ("requirements-dev.txt", "dev")):
        path = root / name
        if path.is_file():
            lines = [ln.strip() for ln in path.read_text(errors="replace").splitlines()]
            deps[key] = [ln for ln in lines if ln and not ln.startswith(("#", "-"))]
    return deps


def read_git_commit(root: Path) -> str | None:
    """Reads .git/HEAD directly (never runs git); None if unavailable."""
    try:
        head = (root / ".git" / "HEAD").read_text().strip()
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            ref_file = root / ".git" / ref
            if ref_file.is_file():
                return ref_file.read_text().strip()[:40]
            packed = root / ".git" / "packed-refs"
            if packed.is_file():
                for line in packed.read_text().splitlines():
                    if line.endswith(" " + ref):
                        return line.split()[0][:40]
            return None
        return head[:40]
    except OSError:
        return None


def build_manifest(root: Path, test_baseline: TestBaseline | None = None, project_version: str = PROJECT_VERSION) -> SystemManifest:
    root = root.resolve()
    entries = [FileEntry(path=rel, sha256=sha256_file(full), size=full.stat().st_size) for rel, full in iter_snapshot_files(root)]
    return _finish_manifest(root, entries, test_baseline, project_version)


def build_manifest_from_hashes(root: Path, hashes_and_sizes: dict[str, tuple[str, int]], test_baseline: TestBaseline | None = None) -> SystemManifest:
    entries = [FileEntry(path=p, sha256=h, size=s) for p, (h, s) in sorted(hashes_and_sizes.items())]
    return _finish_manifest(root.resolve(), entries, test_baseline, PROJECT_VERSION)


def _finish_manifest(root: Path, entries: list[FileEntry], baseline: TestBaseline | None, project_version: str) -> SystemManifest:
    entries = sorted(entries, key=lambda e: e.path)
    deps = read_dependencies(root)
    settings_file = root / "app" / "config" / "settings.py"
    config_hash = sha256_file(settings_file) if settings_file.is_file() else None
    digest = hashlib.sha256(json.dumps(
        {"files": [(e.path, e.sha256) for e in entries], "deps": deps, "config": config_hash}, sort_keys=True,
    ).encode()).hexdigest()
    return SystemManifest(
        project_version=project_version, git_commit=read_git_commit(root),
        config_schema_version=CONFIG_SCHEMA_VERSION, config_schema_hash=config_hash, dependencies=deps,
        files=entries, test_baseline=baseline, content_hash=digest,
    )


def compare_manifests(current: SystemManifest, candidate: SystemManifest) -> ManifestDiff:
    cur = {f.path: f.sha256 for f in current.files}
    cand = {f.path: f.sha256 for f in candidate.files}
    delta = None
    if current.test_baseline and candidate.test_baseline:
        delta = candidate.test_baseline.passed - current.test_baseline.passed
    return ManifestDiff(
        added=sorted(set(cand) - set(cur)), removed=sorted(set(cur) - set(cand)),
        modified=sorted(p for p in cur.keys() & cand.keys() if cur[p] != cand[p]),
        dependencies_changed=current.dependencies != candidate.dependencies,
        config_changed=current.config_schema_hash != candidate.config_schema_hash,
        test_count_delta=delta,
    )


def parse_version(version: str) -> int | None:
    m = _VERSION_RE.match(version)
    return int(m.group(1)) if m else None


def tree_digest(root: Path) -> str:
    """Deterministic digest of EVERY entry under root: regular files by content hash, symlinks by
    their target (never followed). Used to bind validation and approval to the exact candidate tree."""
    root = root.resolve()
    entries: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = Path(dirpath, name)
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                entries.append((rel, "link:" + os.readlink(full)))
            elif full.is_file():
                entries.append((rel, sha256_file(full)))
    return hashlib.sha256(json.dumps(sorted(entries)).encode()).hexdigest()

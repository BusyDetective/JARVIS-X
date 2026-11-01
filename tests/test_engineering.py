from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from app.engineering.analysis import ProjectInspector, language_for
from app.engineering.diff import MAX_FILES_PER_DIFF, DiffGenerator
from app.engineering.errors import EngineeringError, InvalidPatchError
from app.engineering.models import EngineeringPlan, FileChange, PlanStage
from app.engineering.planning import EngineeringPlanner, select_relevant_files
from app.engineering.tools import engineering_tools
from app.workspace.manager import WorkspaceLimits, WorkspaceManager


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "proj"
    for d in ("src/auth", "src/utils", "tests", "docs", "node_modules/x"):
        (r / d).mkdir(parents=True)
    files = {
        "pyproject.toml": "[project]\nname='x'\n", "requirements.txt": "httpx\n", "requirements-dev.txt": "pytest\n",
        "README.md": "# X\n", "Dockerfile": "FROM python\n", "package.json": "{}", "main.py": "print('hi')\n",
        "src/app.py": "def run():\n    return 1\n", "src/auth/login.py": "def login():\n    pass\n",
        "src/utils/strings.py": "def up(s):\n    return s.upper()\n", "src/index.ts": "export {}\n",
        "tests/test_app.py": "def test_x():\n    assert True\n", "docs/guide.md": "guide\n",
        ".env": "SECRET=1", "node_modules/x/lib.js": "module.exports = 1",
    }
    for rel, content in files.items():
        (r / rel).write_text(content)
    return r


@pytest.fixture
def ws(root):
    return WorkspaceManager(root)


# --- project inspection ---------------------------------------------------------


def test_project_inspection(ws):
    s = ProjectInspector(ws).inspect()
    assert s.path == "." and s.total_files == 13 and s.total_dirs == 5
    assert s.languages == {"JSON": 1, "Markdown": 2, "Python": 5, "TOML": 1, "Text": 2, "TypeScript": 1}
    assert s.config_files == ["Dockerfile", "README.md", "package.json", "pyproject.toml", "requirements-dev.txt", "requirements.txt"]
    assert s.entry_points == ["main.py", "src/app.py", "src/index.ts"]
    assert ".env" not in s.files and not any("node_modules" in f for f in s.files)
    assert s.truncated is False and s.files == sorted(s.files)


def test_inspection_is_deterministic_and_scoped(ws):
    a, b = ProjectInspector(ws).inspect(), ProjectInspector(ws).inspect()
    assert a == b
    sub = ProjectInspector(ws).inspect("src")
    assert sub.path == "src" and all(f.startswith("src/") for f in sub.files) and sub.languages == {"Python": 3, "TypeScript": 1}


def test_inspection_bounds(tmp_path):
    r = tmp_path / "big"
    r.mkdir()
    for i in range(30):
        (r / f"f{i:02d}.py").write_text("x")
    s = ProjectInspector(WorkspaceManager(r, WorkspaceLimits(max_files=10))).inspect()
    assert s.total_files == 10 and s.truncated is True


def test_inspection_rejects_escape(ws):
    from app.workspace.errors import WorkspacePathError
    with pytest.raises(WorkspacePathError):
        ProjectInspector(ws).inspect("../")


def test_language_detection():
    assert language_for("a/b.PY") == "Python" and language_for("x.tsx") == "TypeScript"
    assert language_for("Makefile") is None and language_for("a.unknownext") is None


def test_read_source_and_search_code(ws):
    insp = ProjectInspector(ws)
    src = insp.read_source("src/app.py")
    assert src.language == "Python" and src.line_count == 2 and src.sha256 == sha("def run():\n    return 1\n")
    res = insp.search_code("def ", extensions=["py"], max_results=2)
    assert len(res.matches) == 2 and res.truncated is True and res.query == "def "
    assert [m.path for m in insp.search_code("login", path="src").matches] == ["src/auth/login.py"]
    assert insp.search_code("nothing-here").matches == []


# --- diffs ------------------------------------------------------------------------


def test_modify_existing_file_diff(ws, root):
    old = (root / "src/app.py").read_text()
    new = "def run():\n    return 2\n\n\ndef extra():\n    pass\n"
    d = DiffGenerator(ws).generate([FileChange(path="src/app.py", original_hash=sha(old), new_content=new, reason="update")])
    assert d.files[0].status == "modified" and (d.files[0].additions, d.files[0].deletions) == (5, 1)
    assert d.unified_diff.startswith("--- a/src/app.py\n+++ b/src/app.py\n@@")
    assert "-    return 1\n" in d.unified_diff and "+    return 2\n" in d.unified_diff
    assert d.applied is False and "Proposal only" in d.summary and "1 modified" in d.summary and d.truncated is False


def test_new_file_and_unchanged(ws, root):
    old = (root / "main.py").read_text()
    d = DiffGenerator(ws).generate([
        FileChange(path="src/new.py", new_content="x = 1\n", reason="add"),
        FileChange(path="main.py", original_hash=sha(old), new_content=old, reason="noop"),
    ])
    assert [(f.path, f.status) for f in d.files] == [("src/new.py", "added"), ("main.py", "unchanged")]
    assert d.unified_diff.startswith("--- /dev/null\n+++ b/src/new.py\n") and "1 added" in d.summary and "1 unchanged" in d.summary


def test_multiple_files_and_missing_trailing_newline(ws, root):
    old = (root / "docs/guide.md").read_text()
    d = DiffGenerator(ws).generate([
        FileChange(path="docs/guide.md", original_hash=sha(old), new_content="guide v2", reason="r"),
        FileChange(path="docs/extra.md", new_content="extra\n", reason="r"),
    ])
    assert "\\ No newline at end of file" in d.unified_diff and len(d.files) == 2
    assert d.unified_diff.count("--- ") == 2


def test_nothing_is_ever_written(ws, root):
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    old = (root / "src/app.py").read_text()
    DiffGenerator(ws).generate([FileChange(path="src/app.py", original_hash=sha(old), new_content="changed\n", reason="r"),
                                FileChange(path="brand/new.py", new_content="x\n", reason="r")])
    after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before == after and not (root / "brand").exists()


@pytest.mark.parametrize("path", ["../outside.py", "/etc/passwd", "src", "", ".env", ".git/config", "a/%2e%2e/b", "sub\\x.py"])
def test_invalid_or_protected_paths_rejected(ws, path):
    with pytest.raises((InvalidPatchError, ValidationError)):
        DiffGenerator(ws).generate([FileChange(path=path, new_content="x", reason="r")])


def test_hash_rules(ws, root):
    gen = DiffGenerator(ws)
    with pytest.raises(InvalidPatchError, match="original_hash is required"):
        gen.generate([FileChange(path="src/app.py", new_content="x\n", reason="r")])
    with pytest.raises(InvalidPatchError, match="hash mismatch"):
        gen.generate([FileChange(path="src/app.py", original_hash=sha("stale"), new_content="x\n", reason="r")])
    with pytest.raises(InvalidPatchError, match="does not exist"):
        gen.generate([FileChange(path="src/ghost.py", original_hash=sha("x"), new_content="x\n", reason="r")])
    with pytest.raises(ValidationError):
        FileChange(path="a.py", original_hash="not-a-hash", new_content="x", reason="r")


def test_content_and_batch_validation(ws):
    gen = DiffGenerator(ws)
    with pytest.raises(InvalidPatchError, match="no changes"):
        gen.generate([])
    with pytest.raises(InvalidPatchError, match="more than once"):
        gen.generate([FileChange(path="n.py", new_content="a", reason="r"), FileChange(path="./n.py", new_content="b", reason="r")])
    with pytest.raises(InvalidPatchError, match="binary"):
        gen.generate([FileChange(path="n.py", new_content="a\x00b", reason="r")])
    with pytest.raises(InvalidPatchError, match="too many"):
        gen.generate([FileChange(path=f"n{i}.py", new_content="a", reason="r") for i in range(MAX_FILES_PER_DIFF + 1)])
    small = DiffGenerator(WorkspaceManager(ws.get_project_root(), WorkspaceLimits(max_file_size=100)))
    with pytest.raises(InvalidPatchError, match="exceeds"):
        small.generate([FileChange(path="n.py", new_content="a" * 500, reason="r")])


def test_cannot_base_change_on_binary_or_protected_existing_file(ws, root):
    (root / "blob.bin").write_bytes(b"\x00\x01\x02")
    with pytest.raises(InvalidPatchError, match="cannot base"):
        DiffGenerator(ws).generate([FileChange(path="blob.bin", original_hash=sha("x"), new_content="a", reason="r")])


def test_diff_truncation(ws):
    d = DiffGenerator(ws, max_diff_chars=300).generate([FileChange(path="big.txt", new_content="line\n" * 1000, reason="r")])
    assert d.truncated is True and len(d.unified_diff) <= 340 and d.unified_diff.rstrip().endswith("(diff truncated)")
    assert d.files[0].additions == 1000  # counts reflect the full change


# --- planning -------------------------------------------------------------------------


def test_plan_structure_and_serialization(ws):
    structure = ProjectInspector(ws).inspect()
    plan = EngineeringPlanner().create_plan("Fix the login bug in auth", structure)
    assert [t.stage for t in plan.tasks] == list(PlanStage)
    assert [t.id for t in plan.tasks] == [f"step-{i}" for i in range(1, 8)]
    assert plan.tasks[0].depends_on == [] and all(t.depends_on == [f"step-{i}"] for i, t in enumerate(plan.tasks[1:], 1))
    assert plan.requires_approval is True and plan.status == "proposed" and all(t.status == "pending" for t in plan.tasks)
    assert plan.tasks[1].files[0] == "src/auth/login.py" and plan.tasks[0].files == structure.config_files
    assert plan.tasks[-1].files == [] and plan.created_at.tzinfo is not None
    again = EngineeringPlan.model_validate(json.loads(plan.model_dump_json()))
    assert again == plan


def test_plan_is_deterministic_apart_from_timestamp(ws):
    s = ProjectInspector(ws).inspect()
    a = EngineeringPlanner().create_plan("improve string utils", s).model_dump(exclude={"created_at"})
    b = EngineeringPlanner().create_plan("improve string utils", s).model_dump(exclude={"created_at"})
    assert a == b


def test_plan_with_explicit_files_and_no_matches(ws):
    p = EngineeringPlanner().create_plan("do things", None, ["a.py", " a.py ", "b.py", ""])
    assert p.tasks[2].files == ["a.py", "b.py"]
    q = EngineeringPlanner().create_plan("zzqqxx quux", ProjectInspector(ws).inspect())
    assert q.tasks[1].files == [] and any("No files matched" in n for n in q.notes)


def test_select_relevant_files_ranking(ws):
    s = ProjectInspector(ws).inspect()
    assert select_relevant_files("login auth", s)[0] == "src/auth/login.py"
    assert select_relevant_files("the and for", s) == []


def test_plan_goal_validation():
    for bad in ("", "   ", "x" * 1001):
        with pytest.raises(EngineeringError):
            EngineeringPlanner().create_plan(bad)


def test_plan_model_rejects_unapproved_variants():
    with pytest.raises(ValidationError):
        EngineeringPlan(goal="g", tasks=[], requires_approval=False)
    with pytest.raises(ValidationError):
        EngineeringPlan(goal="g", tasks=[], status="approved")


# --- tools ----------------------------------------------------------------------------


async def call(tool, **kw):
    return await tool.execute(tool.args_model(**kw))


async def test_engineering_tools_end_to_end(ws, root):
    t = {x.name: x for x in engineering_tools(ws)}
    assert list(t) == ["engineering_inspect_project", "engineering_propose_diff", "engineering_create_plan"]
    insp = await call(t["engineering_inspect_project"])
    assert insp["data"]["languages"]["Python"] == 5 and "UNTRUSTED" in insp["notice"]
    old = (root / "src/app.py").read_text()
    out = await call(t["engineering_propose_diff"], changes=[
        {"path": "src/app.py", "original_hash": sha(old), "new_content": "def run():\n    return 9\n", "reason": "tweak"}])
    assert out["data"]["applied"] is False and "+    return 9" in out["data"]["unified_diff"]
    assert (root / "src/app.py").read_text() == old
    plan = await call(t["engineering_create_plan"], goal="refactor login")
    assert plan["data"]["tasks"][1]["files"][0] == "src/auth/login.py" and plan["data"]["requires_approval"] is True
    plan2 = await call(t["engineering_create_plan"], goal="g", relevant_files=["x.py"])
    assert plan2["data"]["tasks"][3]["files"] == ["x.py"]


async def test_propose_diff_tool_errors_are_safe(ws, root):
    t = {x.name: x for x in engineering_tools(ws)}["engineering_propose_diff"]
    with pytest.raises(InvalidPatchError):
        await call(t, changes=[{"path": ".env", "new_content": "x", "reason": "r"}])
    with pytest.raises(InvalidPatchError) as ei:
        await call(t, changes=[{"path": "a.py", "original_hash": "nothex", "new_content": "x", "reason": "r"}])
    assert str(root) not in str(ei.value)
    with pytest.raises(ValidationError):
        t.args_model(changes=[])


async def test_engineering_tool_unexpected_error_is_generic(ws):
    class Weird(type(engineering_tools(ws)[0])):
        def _run(self, args):
            raise RuntimeError("leak /home/user SECRET=1")

    with pytest.raises(EngineeringError, match="failed unexpectedly") as ei:
        await call(Weird(ws))
    assert "SECRET" not in str(ei.value)

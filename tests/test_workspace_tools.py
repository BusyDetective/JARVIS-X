from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.security.permissions import PermissionLevel
from app.security.untrusted import UNTRUSTED_REPO_NOTICE
from app.workspace.errors import WorkspaceAccessDeniedError, WorkspaceError, WorkspacePathError
from app.workspace.manager import WorkspaceLimits, WorkspaceManager
from app.workspace.tools import workspace_tools


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "p"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print('hello')\npassword = 'hunter2hunter2'\n")
    (root / ".env").write_text("SECRET=zzz")
    return WorkspaceManager(root, WorkspaceLimits(max_output_chars=2_000))


@pytest.fixture
def tools(ws):
    return {t.name: t for t in workspace_tools(ws)}


async def call(tool, **kw):
    return await tool.execute(tool.args_model(**kw))


def test_tools_are_read_only_safe_with_clean_schemas(tools):
    assert list(tools) == ["workspace_list_files", "workspace_read_file", "workspace_search"]
    blob = ""
    for t in tools.values():
        assert t.permission_level is PermissionLevel.SAFE
        blob += json.dumps(t.to_tool_schema().__dict__)
    for leak in ("WorkspaceManager", "_ReadArgs", "/home", "tmp"):
        assert leak not in blob


async def test_list_read_search_through_manager(tools):
    listing = await call(tools["workspace_list_files"], recursive=True)
    assert listing["notice"] == UNTRUSTED_REPO_NOTICE
    paths = {e["path"]: e for e in listing["data"]["entries"]}
    assert paths["src/a.py"]["size"] > 0 and paths[".env"]["protected"] is True and paths[".env"]["size"] is None
    read = await call(tools["workspace_read_file"], path="src/a.py")
    assert "print('hello')" in read["data"]["content"] and "hunter2hunter2" not in json.dumps(read)
    assert read["redactions"] == 1
    found = await call(tools["workspace_search"], query="hello", extensions=["py"])
    assert found["data"]["matches"][0] == {"path": "src/a.py", "line_number": 1, "line": "print('hello')"}


async def test_errors_are_workspace_errors_with_relative_paths_only(tools, ws):
    with pytest.raises(WorkspaceAccessDeniedError) as e1:
        await call(tools["workspace_read_file"], path=".env")
    with pytest.raises(WorkspacePathError) as e2:
        await call(tools["workspace_read_file"], path="../../etc/passwd")
    for e in (e1, e2):
        assert str(ws.get_project_root()) not in str(e.value) and "zzz" not in str(e.value)


async def test_unexpected_exceptions_are_genericized(ws):
    class Weird(type(workspace_tools(ws)[1])):
        def _run(self, args):
            raise RuntimeError(f"leak {ws.get_project_root()} SECRET=zzz")

    tool = Weird(ws)
    with pytest.raises(WorkspaceError) as ei:
        await call(tool, path="x")
    assert str(ei.value) == "workspace operation failed unexpectedly"


def test_argument_validation(tools):
    with pytest.raises(ValidationError):
        tools["workspace_read_file"].args_model(path="")
    with pytest.raises(ValidationError):
        tools["workspace_search"].args_model(query="")
    with pytest.raises(ValidationError):
        tools["workspace_search"].args_model(query="x", max_results=0)
    assert tools["workspace_search"].args_model(query="x", max_results=10**6).max_results == 10**6  # clamped server-side


async def test_output_size_is_bounded(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "big.txt").write_text("word " * 20_000)
    w = WorkspaceManager(root, WorkspaceLimits(max_output_chars=1_500, max_file_size=1_000_000))
    out = await call(workspace_tools(w)[1], path="big.txt")
    assert len(json.dumps(out)) <= 1_500 + 100 and out["truncated_output"] is True

import pytest

from app.security.workspace import WorkspaceViolationError, resolve_in_workspace


def test_resolve_in_workspace_allows_nested_path():
    path = resolve_in_workspace("notes/todo.txt")
    assert path.name == "todo.txt"
    assert "workspace" in str(path)


def test_resolve_in_workspace_blocks_parent_traversal():
    with pytest.raises(WorkspaceViolationError):
        resolve_in_workspace("../../etc/passwd")


def test_resolve_in_workspace_blocks_absolute_escape():
    with pytest.raises(WorkspaceViolationError):
        resolve_in_workspace("/etc/passwd")

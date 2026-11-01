from __future__ import annotations


class WorkspaceError(Exception):
    """Base for workspace errors. Messages are safe by construction: relative
    paths and fixed text only — never absolute filesystem paths or file
    contents."""


class WorkspacePathError(WorkspaceError):
    pass


class WorkspaceFileTooLargeError(WorkspaceError):
    pass


class WorkspaceAccessDeniedError(WorkspaceError):
    pass


class WorkspaceUnsupportedFileError(WorkspaceError):
    pass

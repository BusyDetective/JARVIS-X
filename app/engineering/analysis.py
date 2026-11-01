from __future__ import annotations

import fnmatch
import posixpath

from app.engineering.models import CodeSearchResult, ProjectStructure, SourceFile
from app.workspace.manager import WorkspaceManager

_LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin", ".c": "C", ".h": "C", ".cpp": "C++",
    ".cc": "C++", ".hpp": "C++", ".cs": "C#", ".rb": "Ruby", ".php": "PHP", ".swift": "Swift",
    ".sh": "Shell", ".sql": "SQL", ".html": "HTML", ".css": "CSS", ".md": "Markdown", ".json": "JSON",
    ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML", ".ini": "INI", ".txt": "Text",
}
_CONFIG_NAMES = {
    "pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "pytest.ini", "package.json", "tsconfig.json",
    "cargo.toml", "go.mod", "pom.xml", "build.gradle", "gemfile", "composer.json", "dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "makefile", "readme.md", "readme.rst", ".gitignore",
    ".env.example", ".editorconfig",
}
_CONFIG_GLOBS = ("requirements*.txt",)
_ENTRY_NAMES = {
    "main.py", "__main__.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "cli.py", "run.py", "index.js",
    "index.ts", "main.js", "main.ts", "server.js", "main.go", "main.rs", "main.java", "program.cs",
}
MAX_LISTED_FILES = 500
MAX_LISTED_DIRS = 200


def language_for(path: str) -> str | None:
    return _LANGUAGES.get(posixpath.splitext(path)[1].lower())


class ProjectInspector:
    """Deterministic, read-only project analysis over a WorkspaceManager.
    Never executes project code, installs anything or runs commands; detection
    is by file names and extensions only."""

    def __init__(self, workspace: WorkspaceManager) -> None:
        self._ws = workspace

    def inspect(self, path: str = "") -> ProjectStructure:
        listing = self._ws.list_files(path, recursive=True)
        files = [e for e in listing.entries if e.type == "file" and not e.protected]
        dirs = [e.path for e in listing.entries if e.type == "dir"]
        languages: dict[str, int] = {}
        for f in files:
            lang = language_for(f.path)
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
        names = [(f.path, posixpath.basename(f.path).lower()) for f in files]
        config = [p for p, n in names if n in _CONFIG_NAMES or any(fnmatch.fnmatchcase(n, g) for g in _CONFIG_GLOBS)]
        entries = [p for p, n in names if n in _ENTRY_NAMES]
        return ProjectStructure(
            path=listing.path, total_files=len(files), total_dirs=len(dirs),
            files=[f.path for f in files][:MAX_LISTED_FILES], directories=dirs[:MAX_LISTED_DIRS],
            languages=dict(sorted(languages.items())), config_files=config, entry_points=entries,
            truncated=listing.truncated or len(files) > MAX_LISTED_FILES or len(dirs) > MAX_LISTED_DIRS,
        )

    def read_source(self, path: str) -> SourceFile:
        content = self._ws.read_file(path)
        return SourceFile(
            path=content.path, language=language_for(content.path), size=content.size,
            line_count=content.line_count, sha256=content.sha256, content=content.content,
            truncated=content.truncated,
        )

    def search_code(
        self, query: str, path: str = "", extensions: list[str] | None = None,
        glob: str | None = None, max_results: int | None = None, case_sensitive: bool = False,
    ) -> CodeSearchResult:
        result = self._ws.search_files(query, path, extensions, glob, max_results, case_sensitive)
        return CodeSearchResult(query=result.query, matches=result.matches,
                                files_scanned=result.files_scanned, truncated=result.truncated)

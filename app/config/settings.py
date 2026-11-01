from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central, provider-agnostic configuration.

    All values are overridable via environment variables or a `.env` file.
    Nothing here hard-codes a provider as "the" provider — PROVIDER_ORDER
    decides preference, and every provider is independently optional.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Gemini ---
    gemini_api_key: str | None = None
    # PLACEHOLDER DEFAULT — not guaranteed to remain available. Provider
    # model lineups change on their own schedule, independent of JARVIS-X.
    # Always override via GEMINI_MODEL in .env; verify current model names
    # against Gemini's own model-listing endpoint/docs before relying on
    # this default in production.
    gemini_model: str = "gemini-2.0-flash"

    # --- OpenRouter ---
    openrouter_api_key: str | None = None
    # PLACEHOLDER DEFAULT — free-tier model slugs on OpenRouter are added,
    # renamed, and retired frequently. Always override via
    # OPENROUTER_MODEL in .env; verify against https://openrouter.ai/models
    # before relying on this default.
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct:free"

    # --- Ollama (local, optional) ---
    ollama_base_url: str = "http://localhost:11434"
    # PLACEHOLDER DEFAULT — depends entirely on what you've pulled locally
    # (`ollama pull <model>`). Always override via OLLAMA_MODEL in .env to
    # match a model you actually have installed.
    ollama_model: str = "llama3.1"

    # --- Routing ---
    # Comma-separated preference order. Configurable without code changes.
    provider_order: str = "gemini,openrouter,ollama"

    # --- Networking ---
    request_timeout_seconds: float = 30.0

    # --- Agent loop safety ---
    # Hard caps the orchestrator enforces on every run, to guarantee no
    # agent loop can run forever. Configurable without code changes; the
    # orchestrator also accepts per-instance overrides for tests/tuning.
    max_iterations: int = 10
    max_tool_calls: int = 20

    # --- Context management ---
    # Deterministic item-count limits ContextManager enforces when
    # assembling a ContextBundle. No token counting yet (see
    # app/context/manager.py) — these are simple counts, not budgets.
    max_conversation_context_items: int = 20
    max_memory_context_items: int = 5
    max_task_context_items: int = 10
    max_total_context_items: int = 30

    # --- Sessions / conversations ---
    # Default window for ConversationManager.get_recent_messages() when the
    # caller passes no explicit limit. Item-count based (no token counting).
    max_recent_messages: int = 20
    # Max length of an auto-derived session title (see
    # app.sessions.manager.derive_session_title).
    session_title_max_length: int = 60

    # --- Capabilities ---
    # Master switch for the capability framework. When false,
    # CapabilityManager.register_builtin_capabilities() registers nothing
    # and install() is refused. Tools registered directly in a ToolRegistry
    # are unaffected.
    capabilities_enabled: bool = True

    # --- Web research ---
    # Master switch: when false, register_web_research_capability() installs
    # nothing. Limits are enforced by the server side regardless of what a
    # model asks for.
    web_research_enabled: bool = True
    web_search_provider: str = "brave"
    brave_search_api_key: str | None = None
    web_request_timeout: float = 15.0
    web_max_results: int = 10
    web_max_pages: int = 5
    web_max_response_bytes: int = 2_000_000
    web_max_document_chars: int = 8_000
    web_max_redirects: int = 5
    web_max_concurrent_fetches: int = 3
    web_max_tool_output_chars: int = 24_000

    # --- Software engineering (Phase 7): GitHub (read-only), workspace, engineering ---
    # Master switch for the whole `software_engineering` capability.
    software_engineering_enabled: bool = True
    github_enabled: bool = True
    # Optional. Never logged, never shown to the model. Unauthenticated
    # read-only access works where GitHub allows it (lower rate limits).
    github_token: str | None = None
    github_request_timeout: float = 15.0
    github_max_retries: int = 2
    github_max_results: int = 30
    github_max_pages: int = 3
    github_max_file_size: int = 200_000
    github_max_directory_entries: int = 200
    github_max_response_chars: int = 24_000
    github_max_response_bytes: int = 2_000_000
    # Workspace reads are confined to WORKSPACE_ROOT (defined below).
    workspace_enabled: bool = True
    workspace_max_file_size: int = 200_000
    workspace_max_files: int = 2_000
    workspace_max_search_results: int = 50
    workspace_max_output_chars: int = 24_000
    engineering_enabled: bool = True
    engineering_max_diff_chars: int = 50_000

    # --- Self-improvement (Phase 8) ---
    # OFF by default. Even when on, risk classification, validation, human
    # approval and rollback policies still apply; nothing here lets the model
    # modify the running installation.
    self_improvement_enabled: bool = False
    # Where releases/ candidates/ and the current-release pointer live.
    self_improvement_root: Path = Path("data/improvement")
    # Allow the policy (not the model) to auto-approve genuinely low-risk,
    # documentation-only candidates. Off by default.
    self_improvement_safe_automatic: bool = False
    improvement_validation_timeout: float = 900.0
    improvement_validation_max_output_bytes: int = 200_000
    improvement_validation_memory_mb: int = 2048
    improvement_validation_cpus: float = 2.0
    improvement_validation_pids: int = 256
    # Isolated validation backend: a disposable container (docker or podman CLI). There is no
    # host-execution fallback: without a working container runtime and image, validation fails closed.
    improvement_isolation_backend: str = "auto"  # auto | docker | podman
    improvement_container_image: str = "jarvisx-validation:1"
    improvement_container_oci_runtime: str | None = None  # e.g. "runc", "crun", "runsc" (gVisor)

    # --- Cybersecurity specialist (Phase 10) ---
    # OFF by default. Bounded, authorization-scoped reconnaissance against
    # explicitly authorized targets only — see app/cybersecurity/. Every
    # tool still requires approval via the existing DANGEROUS/CONFIRM
    # permission levels regardless of this flag; this flag only controls
    # whether the capability is installed at all.
    cybersecurity_enabled: bool = False
    # Path to a JSON file listing AuthorizedScope entries (see
    # app/cybersecurity/models.py:AuthorizedScope). Relative paths resolve
    # against the working directory JARVIS-X is launched from. Unset (the
    # default) means no scope is configured — every operation is denied
    # (fail closed), never a permissive default.
    cybersecurity_scope_file: Path | None = None
    # Directory reports are written into. Relative paths resolve against
    # the working directory. Created on first use if missing.
    cybersecurity_report_dir: Path = Path("data/cybersecurity/reports")
    cybersecurity_max_subdomains: int = 50
    cybersecurity_max_hosts: int = 15
    cybersecurity_max_endpoints: int = 100
    cybersecurity_max_findings: int = 200
    cybersecurity_request_timeout: float = 20.0
    cybersecurity_operation_timeout: float = 180.0
    cybersecurity_max_concurrency: int = 10
    cybersecurity_max_tool_output_chars: int = 24_000
    cybersecurity_cache_ttl_seconds: float = 3600.0
    cybersecurity_cache_max_domains: int = 50

    # --- Dashboard / UI (Phase 9) ---
    # `python -m app.ui` starts the dashboard; nothing starts it automatically.
    ui_enabled: bool = True
    ui_host: str = "127.0.0.1"
    ui_port: int = 8765
    # Local auth token. If unset, an ephemeral random token is generated at each start and
    # printed once to the terminal. Never logged when configured. Required (>=24 chars) to
    # bind a non-loopback host.
    ui_auth_token: str | None = None
    ui_allow_remote: bool = False
    ui_cookie_secure: bool = False  # set true when a TLS-terminating proxy serves the dashboard over HTTPS
    # Extra allowed Host/Origin values (comma-separated "host:port"), e.g. behind a reverse proxy.
    ui_extra_allowed_hosts: str = ""
    ui_max_message_chars: int = 8_000
    ui_approval_timeout_seconds: float = 300.0
    ui_max_concurrent_runs: int = 4
    ui_session_ttl_seconds: int = 8 * 3600

    # --- Browser (Phase 9) --- OFF by default; needs `pip install -r requirements-browser.txt`
    # and a browser binary you install yourself (nothing is downloaded at startup).
    browser_enabled: bool = False
    browser_executable_path: Path | None = None
    browser_no_sandbox: bool = False  # Chromium cannot sandbox as root/in some containers
    browser_javascript_enabled: bool = False  # page scripts OFF by default
    browser_navigation_timeout: float = 20.0
    browser_action_timeout: float = 10.0
    browser_max_actions: int = 30
    browser_max_redirects: int = 5
    browser_max_requests_per_page: int = 150
    browser_max_resource_bytes: int = 5_000_000
    browser_max_total_bytes: int = 25_000_000
    browser_max_text_chars: int = 8_000
    browser_max_links: int = 50
    browser_max_form_fields: int = 30
    browser_screenshot_max_bytes: int = 400_000
    browser_viewport_width: int = 1280
    browser_viewport_height: int = 800
    browser_idle_seconds: float = 300.0
    browser_allowed_ports: str = "80,443"
    # Optional allow-list of domains (comma-separated; subdomains included). Empty = any public host.
    browser_allowed_domains: str = ""

    # --- Voice (Phase 9) --- both directions OFF by default; text always works.
    voice_input_enabled: bool = False
    voice_stt_provider: str = "none"  # none | browser | faster_whisper
    voice_stt_model: str = "base"
    voice_stt_model_path: Path | None = None
    voice_stt_language: str | None = None
    voice_stt_allow_download: bool = False
    voice_stt_timeout: float = 60.0
    voice_max_audio_bytes: int = 5_000_000
    speech_output_enabled: bool = False
    speech_synthesis_provider: str = "none"  # none | browser
    speech_max_chars: int = 2_000
    speech_chunk_chars: int = 300

    # --- Persistence ---
    # Directory for all locally persisted data (currently just the SQLite
    # task database). Created automatically if missing. Field/env-var
    # naming kept unprefixed (DATA_DIR, DB_PATH) to match every other
    # setting in this file, rather than JARVIS_DATA_DIR/JARVIS_DB_PATH.
    data_dir: Path = Path("data")
    # SQLite database file. None (the default) means "use <data_dir>/jarvis.db";
    # set DB_PATH explicitly to relocate it. Relative paths resolve against
    # the working directory JARVIS-X is launched from — same convention as
    # WORKSPACE_ROOT below. Never hard-code a machine-specific absolute path.
    db_path: Path | None = None

    @property
    def resolved_db_path(self) -> Path:
        """The actual SQLite file path to use: DB_PATH if explicitly set,
        otherwise <data_dir>/jarvis.db."""
        return self.db_path if self.db_path is not None else self.data_dir / "jarvis.db"

    # --- Workspace ---
    # Filesystem/coding tools (future) must restrict all reads/writes to this
    # directory. Relative paths are resolved against the current working
    # directory; set an absolute path in .env to pin it explicitly.
    workspace_root: Path = Path("workspace")

    @property
    def provider_order_list(self) -> list[str]:
        return [p.strip().lower() for p in self.provider_order.split(",") if p.strip()]


# Single shared settings instance, imported everywhere.
settings = Settings()

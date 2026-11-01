# JARVIS-X — Phases 1–9 (core agent … controlled self-improvement, dashboard, browser, voice)

> Phase 9 (dashboard + browser + voice) is documented in ["Dashboard, browser and voice (Phase 9)"](#dashboard-browser-and-voice-phase-9) below.
> The introduction that follows describes the original Phase 1–3 scope and is kept for history.

Provider abstraction, the provider-agnostic agent execution loop,
persistent task tracking (SQLite), and a context-assembly layer with a
persistent long-term memory foundation (deterministic keyword-based
retrieval — no embeddings/vector search yet). No concrete tools
(filesystem/terminal/browser), no CLI — those come in later phases.

## What's here

```
app/
├── config/settings.py       # pydantic-settings config, reads .env
├── providers/
│   ├── schemas.py           # Message, ToolCall, ToolResult, ModelResponse, ProviderError
│   ├── base.py               # AIProvider abstract interface
│   ├── gemini.py              # native Gemini function-calling
│   ├── openrouter.py          # OpenAI-compatible chat completions
│   └── ollama.py              # local Ollama, optional
├── core/
│   ├── model_router.py      # preferred provider + typed-error fallback
│   └── orchestrator.py      # the agent loop: model -> tool calls -> execute -> repeat
├── tools/
│   ├── base.py               # Tool abstraction (Pydantic args model, permission, timeout)
│   └── registry.py           # ToolRegistry — orchestrator never imports a concrete Tool
├── security/
│   ├── workspace.py          # path containment for future filesystem tools
│   ├── permissions.py        # SAFE / CONFIRM / DANGEROUS / BLOCKED
│   └── approval.py           # injectable ApprovalHandler (no interactive input in tests)
├── tasks/
│   ├── models.py              # Task, TaskRun (Pydantic) + the life-cycle state machine
│   ├── repository.py          # TaskRepository — all SQL lives here, returns typed models
│   └── manager.py             # TaskManager — enforces valid Task state transitions
├── context/
│   ├── models.py               # ContextItem/Bundle/Source/Priority (provider-agnostic)
│   └── manager.py              # ContextManager — assembly/ordering/dedup/limits; depends
│                                  on MemoryManager only, never touches SQLite
├── memory/
│   ├── models.py               # Memory, MemoryType (Pydantic)
│   ├── secrets.py              # conservative pattern-based secret detection
│   ├── repository.py           # MemoryRepository — SQL lives here
│   └── manager.py              # MemoryManager — validation + deterministic relevance scoring
└── storage/
    └── database.py            # sqlite3 connection lifecycle, schema (tasks + memories), concurrency notes
tests/                        # unit tests for all of the above
```

### Orchestrator at a glance

```python
from app.core.orchestrator import Orchestrator
from app.tools.registry import ToolRegistry
from app.security.approval import AutoDenyHandler  # swap for a real handler later

orch = Orchestrator(
    router=my_model_router,
    registry=my_tool_registry,   # empty registry is fine — no tools yet
    approval_handler=AutoDenyHandler(),
)
result = await orch.run("What is 2 + 2?")
print(result.status, result.final_response)
```

`OrchestratorResult` carries `status`, `final_response`, `provider`, `model`,
`tool_calls` (each an `ExecutedToolCall`), `iterations`, and `error` — a
stable shape for a future CLI/UI to render, not a bare dict.

No concrete `Tool` subclasses ship yet — `ToolRegistry` and `Tool` are the
abstraction only. Test doubles (`CalculatorTool`, etc.) live in
`tests/test_orchestrator.py` purely to exercise the loop.

### Optional persistence

Pass a `TaskManager` to persist each run as a `Task` in SQLite:

```python
from app.tasks.manager import TaskManager
from app.tasks.repository import TaskRepository

task_manager = TaskManager(TaskRepository())  # uses settings.resolved_db_path
orch = Orchestrator(router=..., registry=..., approval_handler=..., task_manager=task_manager)
result = await orch.run("What is 2 + 2?")

# The persisted Task, its per-iteration TaskRuns, and any ToolResults:
tasks = task_manager.list_tasks()
runs = task_manager.get_task_runs(tasks[0].id)
tool_results = task_manager.get_tool_results(tasks[0].id)
```

`task_manager` is optional and defaults to `None` — omit it and `Orchestrator`
behaves exactly as in Phase 1 (fully in-memory, no database touched).
Default database location is `<DATA_DIR>/jarvis.db` (`data/jarvis.db` by
default); override with `DB_PATH` in `.env`.

### Optional context + memory

Pass a `ContextManager` (optionally backed by a `MemoryManager`) to replace
how each run's seed messages are built:

```python
from app.context.manager import ContextManager
from app.memory.manager import MemoryManager
from app.memory.repository import MemoryRepository

memory_manager = MemoryManager(MemoryRepository())  # same SQLite db as tasks
context_manager = ContextManager(memory_manager=memory_manager)

orch = Orchestrator(router=..., registry=..., approval_handler=..., context_manager=context_manager)

memory_manager.create_memory("the user prefers concise answers", MemoryType.PREFERENCE, importance=0.9)
result = await orch.run("What's a good summary style for me?")
# -> the seed messages sent to the model include a [Memory] system entry
#    surfacing the preference above, selected by keyword/importance/recency.
```

Memory is never written automatically — `create_memory` is always an
explicit call, and it rejects content matching an obvious secret-like
pattern (`SecretDetectedError`) rather than storing it. Memory selection
is deterministic keyword + importance + recency scoring (see
`MemoryManager.select_relevant_memories`'s docstring) — no embeddings, no
vector search, no LLM judgment calls. `context_manager` is optional and
defaults to `None` — omit it and `Orchestrator` builds its seed messages
exactly as before.

## Install

```bash
cd jarvis-x
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
```

Edit `.env` and add whichever API keys you have. You don't need all three —
any subset of Gemini / OpenRouter / Ollama works; `PROVIDER_ORDER` controls
preference and the router falls back automatically.

### Sessions & conversations (Phase 4)

Distinct concepts: a **Session** is a user's ongoing interaction container;
it holds one or more **Conversations**; a conversation is an ordered list of
persisted **ConversationMessages** (`system` / `user` / `assistant` / `tool`);
a **Task** is one unit of orchestrated work; **Memory** is separate
explicit knowledge; **Context** is what is selected for one model call.
Code lives in `app/sessions/` (models, repositories, managers); tables
`sessions`, `conversations`, `messages` are added to the existing SQLite
database (additive `IF NOT EXISTS`, Phase 1-3 data untouched).

```python
from app.sessions.manager import build_session_services

session_manager, conversation_manager = build_session_services()
conv = session_manager.create_conversation(session_manager.create_session().id)

orch = Orchestrator(router=..., registry=..., approval_handler=...,
                    task_manager=..., conversation_manager=conversation_manager)
result = await orch.run("hello", conversation_id=conv.id)
```

- Ordering is by a per-conversation `sequence` allocated atomically on
  append (never timestamps). `get_recent_messages(n)` returns the last `n`
  oldest -> newest. Defaults: `MAX_RECENT_MESSAGES` (settings
  `max_recent_messages`); item counts only, no token counting.
- The user message is persisted first; an assistant turn requesting tools
  is persisted before the tools run (tool calls in `metadata`); each tool
  outcome is persisted as a TOOL message (`tool_call_id`, `tool_name`);
  the final answer last. `ToolResult` stays canonical in `tool_results`.
  Only events that really happened are stored: a provider failure stores no
  assistant message. The system prompt is never persisted.
- `ContextManager(conversation_manager=...)` reads history only via
  `ConversationManager`. When replayed, tool exchanges keep their linkage;
  orphaned tool messages (window cut) and unanswered tool calls
  (interrupted run) are dropped so providers never see invalid sequences.
- Untitled sessions get a deterministic title from the first user message
  (no LLM). A deactivated session stays readable but rejects new messages.
- Omit `conversation_manager` and the Orchestrator behaves exactly as in
  Phase 3.

### Tools & capabilities (Phase 5)

A **Capability** (`app/capabilities/`) is descriptive control-plane data
grouping one or more tools: `id` (slug), `name`, `version` (semver-like),
`category`, `source` (`builtin`/`local`/`plugin`/`future_external`),
`enabled`, declared `max_permission`, `tool_names`, `depends_on`,
`metadata`. `ToolRegistry` stays the only place tools are looked up and
executed; `CapabilityRegistry` only catalogs; `CapabilityManager` installs,
enables/disables, validates and reports.

```python
from app.capabilities.manager import CapabilityManager
from app.tools.registry import ToolRegistry

tools = ToolRegistry()
caps = CapabilityManager(tools)
caps.register_builtin_capabilities()   # idempotent; -> ["core", "text_utilities"]
orch = Orchestrator(router, tools, approval_handler)   # orchestrator unchanged

caps.disable("text_utilities")         # its tools are now unavailable
caps.list_available_tools()            # metadata: schema, permission, version, owner
caps.snapshot().to_json()              # deterministic, serializable
```

- **Disabled means unavailable, not hidden:** `ToolRegistry.get()` returns
  `None` for a disabled tool and `schemas()` omits it, so the model is not
  offered it and the orchestrator refuses it ("not available") even if the
  capability is disabled mid-run.
- **Permissions are untouched:** the tool's own `permission_level` is
  authoritative and the approval flow is unchanged. A capability's declared
  `max_permission` is only reported next to the tools' effective maximum
  (`permission_mismatch` flags an understated declaration); it never raises
  or lowers anything.
- **Dependencies:** enabling needs every dependency installed and enabled;
  disabling a dependency of an enabled capability requires `cascade=True`;
  cycles are rejected at install; unregistering a required capability is
  refused.
- **Install = register code already in the project.** Only `builtin`/`local`
  sources install; no downloading, plugin loading, or discovery. State is
  in memory (no new tables). `CAPABILITIES_ENABLED=false` makes bootstrap a
  no-op and refuses installs.
- Built-ins are harmless: `echo`, `get_current_time`, `text_transform`.

### Web research (Phase 6)

Bounded **search -> fetch -> extract -> normalize**, in `app/web/`. No
browser, JavaScript, crawling, caching or persistence of pages.

```python
from app.web.capability import build_web_research_manager, register_web_research_capability

research = build_web_research_manager()          # raises WebConfigurationError without an API key
register_web_research_capability(capabilities, research)   # installs capability "web_research"
```

- **Capability `web_research`** (INFORMATION, BUILTIN, installed through
  `CapabilityManager`, so the Phase 5 enable/disable gating applies — disabled
  tools are not offered and are refused even mid-run). Tools (both SAFE; their
  own permission stays authoritative): `web_search` (snippets only) and
  `web_research` (`search_only` | `search_and_fetch`, `max_results`, `max_pages`).
- **Layers:** Tool -> `WebResearchManager` -> `SearchProvider` / `WebFetcher` /
  `HtmlExtractor`. Search providers are separate from the AI `ModelRouter`.
  The only provider is **Brave Search API** (`BraveSearchProvider`); it needs
  `BRAVE_SEARCH_API_KEY`, and with no key nothing is registered and no fake
  results are returned. It is tested with mocked responses only.
- **Limits** (`WebLimits`, env `WEB_*`, see `.env.example`): results, pages,
  response bytes, document chars, timeout, redirects, concurrency, tool-output
  size. Model-requested values can only be clamped *down*.
- **Fetch safety (`app/web/urls.py`, `fetch.py`):** http/https only; no embedded
  credentials; localhost/internal names and legacy numeric hosts refused; every
  resolved address must be public (private, loopback, link-local/metadata,
  CGNAT, ULA, IPv4-mapped/6to4/Teredo/NAT64 embeds are blocked). Redirects are
  followed manually and each hop is re-validated. The connection goes to the
  IP that was just validated (Host header and TLS SNI/cert stay on the
  hostname), which closes the DNS-rebinding gap. Streaming size cap, per-hop
  deadline, text-like content types only, no cookies.
- **Extraction:** stdlib `html.parser`; drops script/style/nav/footer/forms,
  keeps headings and lists, normalizes whitespace, capped length, tolerant of
  malformed HTML; no LLM.
- **Untrusted data:** page text reaches the model only as the content of a
  `tool`-role message (and persisted/replayed that way via Phase 4); it is
  never placed in a system/developer message, and nothing in it can change
  capabilities, permissions, approvals or configuration. Tool output carries
  an explicit "untrusted" notice. This is a structural guarantee, not proof of
  prompt-injection immunity: the model can still be *influenced* by page text.
- Research results are temporary tool data; nothing is saved to Memory.

Limitations: one search provider; no PDF/binary documents; no JavaScript-rendered
pages; no robots.txt handling or crawling; sources carry factual metadata only
(no credibility scoring); redirect/DNS checks assume the OS resolver is honest.

### Software engineering (Phase 7) — READ-ONLY

One capability, `software_engineering` (DEVELOPMENT, BUILTIN, installed through
`CapabilityManager`; all tools SAFE and read-only), made of three layers:

- **GitHub** (`app/github/`): `GitHubClient` (abstract) / `HttpxGitHubClient`
  against the fixed `https://api.github.com`. Tools: `github_get_repository`,
  `github_search_repositories`, `github_get_file`, `github_list_directory`,
  `github_get_issue`, `github_list_issues`, `github_get_pull_request`,
  `github_list_pull_requests`, `github_get_commit`, `github_list_commits`,
  `github_list_branches`. Responses are normalized into typed models (no raw JSON).
- **Workspace** (`app/workspace/`): `WorkspaceManager` — confined, read-only
  access to `WORKSPACE_ROOT`. Tools: `workspace_list_files`, `workspace_read_file`,
  `workspace_search` (plain-text search, no shell/grep).
- **Engineering** (`app/engineering/`): deterministic project inspection
  (languages, config files, entry points), code search, a `FileChange` -> `Diff`
  proposal generator and a typed `EngineeringPlanner` (no LLM). Tools:
  `engineering_inspect_project`, `engineering_propose_diff`, `engineering_create_plan`.
  A `Diff` is a proposal (`applied` is always `False`); nothing can apply it yet.

```python
from app.engineering.capability import (
    build_github_client, build_workspace_manager, register_software_engineering_capability)

register_software_engineering_capability(capabilities, build_github_client(), build_workspace_manager())
```

Configuration (see `.env.example`): `SOFTWARE_ENGINEERING_ENABLED` (master switch),
`GITHUB_ENABLED`, `GITHUB_TOKEN` (optional; unauthenticated read access works with
lower GitHub rate limits), `GITHUB_REQUEST_TIMEOUT`, `GITHUB_MAX_RETRIES`,
`GITHUB_MAX_RESULTS`, `GITHUB_MAX_PAGES`, `GITHUB_MAX_FILE_SIZE`,
`GITHUB_MAX_DIRECTORY_ENTRIES`, `GITHUB_MAX_RESPONSE_CHARS`, `GITHUB_MAX_RESPONSE_BYTES`;
`WORKSPACE_ENABLED`, `WORKSPACE_ROOT` (the existing setting — there is no second
root variable), `WORKSPACE_MAX_FILE_SIZE`, `WORKSPACE_MAX_FILES`,
`WORKSPACE_MAX_SEARCH_RESULTS`, `WORKSPACE_MAX_OUTPUT_CHARS`; `ENGINEERING_ENABLED`,
`ENGINEERING_MAX_DIFF_CHARS`. Server-side limits always win over model-requested sizes.

Security boundaries:
- **Read-only:** no writes, shell/subprocess, git push, PR/issue creation or
  remote mutation exist. The GitHub client only sends GET; a test scans the
  three packages for write/exec/mutating-HTTP code.
- **No generic HTTP client:** repositories are `owner/name` or a validated
  https://github.com URL; paths, refs and queries are validated and URL-encoded
  per segment; the API host is fixed and redirects are followed only to it.
- **Workspace confinement:** canonical path resolution; rejects `..`, absolute
  paths, encoded traversal and symlinks leading outside the root; symlinks are
  never followed while walking. Only relative paths are reported.
- **Secrets:** the GitHub token is sent only in the Authorization header and never
  appears in errors, logs, repr or output. Likely secret files (`.env`, `*.pem`,
  `*.key`, credentials/secrets files, `.git`, `.ssh`, ...) are listed as metadata
  only and never read; files containing private-key blocks are refused;
  secret-looking text (existing detector plus a few extra shapes) is redacted in
  every GitHub and workspace output before it can reach the model or be persisted.
- **Untrusted data:** repository and file text (READMEs, issues, PRs, commit
  messages, source) is returned inside an output marked untrusted and reaches the
  model only as a `tool`-role message; it cannot change system prompts, tools,
  permissions, approvals or capabilities. As with web research this is a structural
  boundary, not proof of prompt-injection immunity.
- Nothing is cached or stored: no new tables, nothing goes to Memory.

Limitations: GitHub search is repositories only; no code search API, no GitHub
Enterprise/custom hosts; binary and oversized files return metadata only;
workspace search is plain text; no change can be applied (that is a later,
approval-gated phase).

Dev dependencies: Phase 7 adds none (`pip install -r requirements-dev.txt`, then `pytest -q`).

### Controlled self-improvement (Phase 8) — OFF BY DEFAULT

**This is NOT unrestricted autonomous self-modification.** It is infrastructure for a
research-driven, sandboxed, approval-gated, rollback-capable improvement pipeline. The model can
research, evaluate, plan, propose (into a sandbox), request validation and request a rollback. It
cannot approve, promote, run commands, change permissions or touch the running installation. Candidate code never runs on the host.

Lifecycle (`app/improvement/`): `DISCOVERED -> EVALUATED -> PLANNED -> PROPOSED -> SANDBOXED ->
VALIDATING -> VALIDATED -> APPROVED -> PROMOTED` (plus `REJECTED`, `FAILED`, `ROLLED_BACK`).
Only the listed transitions are legal; anything else raises. Every step is audited.

- **Current vs candidate.** `ReleaseStore` (`app/versioning/`) keeps immutable, hash-verified
  releases under `SELF_IMPROVEMENT_ROOT` (`releases/<version>/source`) and a single atomic
  `current.json` pointer (with a history stack for rollback). A candidate is a *copy* of the current
  release inside `candidates/<id>/source`; proposals are applied only there. Secrets (`.env`, keys,
  credentials/secrets data files, `.git`, `data/`, `logs/`, `workspace/`) are never copied.
  Promotion changes the **managed release pointer**; it does not edit the live project directory
  or hot-swap the running process. A launcher that runs from the pointer is a later phase.
- **Risk levels** (path-based, conservative; unknown => higher). LOW: documentation. MEDIUM:
  application code, new tests. HIGH: providers, storage, tasks, memory, context, web, github,
  workspace, sessions, core, dependencies, modified tests, deletions, unrecognised paths.
  CRITICAL: `app/security/`, `app/capabilities/`, `app/improvement/`, `app/sandbox/`, `app/versioning/`,
  tool registry/base, orchestrator, settings, anything with auth/permission/approval/secret/
  credential/sandbox/rollback/promotion in its name, test configuration (`conftest.py`,
  `pytest.ini`, `pyproject.toml`...), and deleted tests.
- **Approval policy.** Every promotion needs an `ApprovalDecision` (APPROVE or REJECT only) obtained
  through the existing `ApprovalHandler` (shown: what, why, risk, files, validation, tests, rollback).
  `SAFE_AUTOMATIC` (<=5 documentation files, LOW risk, no deletion, no flags) may be auto-approved by
  *policy* only if `SELF_IMPROVEMENT_SAFE_AUTOMATIC=true` (default false). `PROPOSE_ONLY` (MEDIUM) and
  `APPROVAL_REQUIRED` (HIGH/CRITICAL, deletions, dependencies, test tampering, security areas) always
  need a human. The promotion layer re-checks all of this and fails closed.
- **Validation** (`ValidationRunner`): fixed operations only, executed in the isolated container (see below) — the project's test
  suite (`python -m pytest -q`) and static analysis (`python -m pyflakes app tests`, in `requirements-dev.txt` and the image). A baseline (the current release's own passing test count) is captured in a
  pristine sandbox first and recorded once. A candidate fails if tests fail, time out, the count
  drops below the baseline, static analysis fails or is unavailable. Test/config tampering is flagged
  and escalated; output is bounded and redacted.
- **Promotion** (`PREPARE -> VERIFY -> SWITCH -> CONFIRM`, journaled): a new release is built and
  hash-verified beside the old one; only the atomic pointer swap changes "current". Failure at any
  step leaves the current release untouched; `recover()` resolves an interrupted promotion at startup.
- **Rollback** (`RollbackManager`): verifies the previous release's integrity, then swaps the pointer
  back. The rolled-back release is kept. Failures return a typed `RollbackResult`.
- **Tools** (capability `self_improvement`, DEVELOPMENT, depends on `software_engineering`):
  `improvement_research`, `improvement_evaluate`, `improvement_create_plan`, `improvement_propose`,
  `improvement_validate` (CONFIRM), `improvement_status`, `improvement_rollback` (CONFIRM).
  There is no shell/exec/promote/approve/write tool. Nothing registers unless
  `SELF_IMPROVEMENT_ENABLED=true`.
- **Persistence.** Two additive tables: `improvement_runs` (metadata only — never source, logs or
  secrets) and an append-only `improvement_events` audit trail (SQLite triggers refuse update/delete).

Isolated validation — what the boundary is and is not (`SandboxPolicy.isolation_report()` states this at runtime):
- **Candidate code runs only in a disposable container** (`ContainerBackend`, Docker or Podman CLI). There is **no
  host-execution path and no fallback**: with no runtime, no image, a misconfiguration, a failed startup, or a failed
  verification, validation raises a typed `IsolationUnavailableError`, **nothing is executed**, the candidate stays
  unvalidated (so approval and promotion are impossible) and the current release is untouched. A static test fails if any
  other module starts processes.
- **Requirements:** a working `docker` or `podman` (set `IMPROVEMENT_ISOLATION_BACKEND`, optionally
  `IMPROVEMENT_CONTAINER_OCI_RUNTIME`, e.g. `runsc` for gVisor) and the image from `docker/validation.Dockerfile`
  (`IMPROVEMENT_CONTAINER_IMAGE`, default `jarvisx-validation:1`). Build it once with network access; it is run without network.
- **Restrictions applied to every run:** `--network none` (only loopback), `--user 65534:65534`, `--read-only` root,
  `--cap-drop ALL`, `no-new-privileges`, default seccomp profile, `--pids-limit`, `--memory`/`--memory-swap`, `--cpus`,
  `--ulimit nofile/core/cpu`, in-memory tmpfs for `/work` and `/tmp` (size-limited), **one** bind mount: the candidate snapshot,
  **read-only**. No home directory, SSH keys, credentials, docker socket or other host path is mounted; no host environment
  variable is passed (only fixed constants); no model- or caller-supplied command, argument, mount or environment exists.
- **Verified, not assumed:** before candidate code runs (and again whenever the image or the 60 s attestation changes), a canary
  container with the same flags checks from the inside that it is unprivileged, has no capabilities, no-new-privileges, no network
  interface but loopback, cannot connect outbound, has a read-only root and snapshot, no writable host-backed mounts, no control
  socket and an allowlisted environment. Any failed check means `RESTRICTIONS_NOT_ESTABLISHED` and nothing runs. The result is an
  `IsolationAttestation` stored with the validation; promotion requires it, and also that validation, approval and the promoted
  tree are the **same tree** (digest-bound), unchanged since validation.
- **Bounded and cleaned up:** wall-clock timeout (container killed and removed), output caps, container named+labelled and removed
  after every run (also on timeout/crash); stale ones are removed at preflight; improvements stuck in VALIDATING after a crash are
  failed safely by `startup_recovery()`.
- **Residual risks (not guaranteed away):** a container shares the host kernel, so a kernel or container-runtime vulnerability
  (escape) could defeat it — use rootless Podman, gVisor (`runsc`) or a VM for stronger separation; Docker's daemon is a privileged
  service; resource limits depend on the host's cgroup setup (a runtime that cannot apply them makes startup fail, it does not relax
  them); validation results are produced by the candidate's own execution, so hostile code can **forge a "pass"** — the digest
  binding, test-count baseline, tamper flags, CRITICAL classification and human approval exist for that reason, but results are
  evidence, not proof; a Linux host or Linux VM is assumed (Docker Desktop/Podman machine on macOS/Windows run containers inside a VM).
- Secret redaction is pattern-based: labelled secrets and known token shapes are caught, a bare, unlabelled password string is not.
- Dependency installation or upgrades are not implemented; a dependency change is always HIGH risk and requires approval.

Tests: `tests/test_container_backend.py` uses a **mocked** runtime (argv, fail-closed paths, cleanup orchestration — it cannot prove
confinement). `tests/test_container_real.py`, the `*_real_container*` invariant tests and `tests/test_improvement_real_project.py`
run **real containers** and are **skipped** (not passed) when no runtime/image is available. Other improvement tests use the UNSAFE
host test double or mock attestations to exercise logic only.

Configuration: `SELF_IMPROVEMENT_ENABLED` (default false), `SELF_IMPROVEMENT_ROOT`, `SELF_IMPROVEMENT_SAFE_AUTOMATIC` (default false),
`IMPROVEMENT_VALIDATION_TIMEOUT`, `IMPROVEMENT_VALIDATION_MAX_OUTPUT_BYTES`, `IMPROVEMENT_VALIDATION_MEMORY_MB`,
`IMPROVEMENT_VALIDATION_CPUS`, `IMPROVEMENT_VALIDATION_PIDS`, `IMPROVEMENT_ISOLATION_BACKEND` (`auto|docker|podman`),
`IMPROVEMENT_CONTAINER_IMAGE`, `IMPROVEMENT_CONTAINER_OCI_RUNTIME`.

Validating against the real project end to end (slow; needs a container runtime + image; runs the whole suite twice in the
isolated container): `JARVIS_RUN_SLOW=1 pytest tests/test_improvement_real_project.py`.

## Dashboard, browser and voice (Phase 9)

```
USER → DASHBOARD / VOICE → SESSION → ORCHESTRATOR → CAPABILITIES (incl. browser) → RESPONSE → DASHBOARD / SPEECH
```

One local web dashboard, one controlled browser capability and optional voice input/output — all three go through the
**same** sessions, conversation store, `Orchestrator`, `CapabilityManager`/`ToolRegistry` and `ApprovalHandler` as before.
Nothing is duplicated: there is no second conversation database, no second approval path and no privileged side channel.

New code: `app/ui/` (FastAPI app + static dashboard), `app/browser/` (policy, network guard, manager, tools, capability),
`app/voice/` (recognition/synthesis providers, speech-text preparation), and `app/bootstrap.py` (composition root — Phases 1–8
shipped no assembled application, so this wires the existing components together and adds no behaviour of its own).
Phase 1–8 code is unchanged except for additive settings in `app/config/settings.py`.

### Install and start the dashboard

```bash
python3 -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                            # now includes fastapi + uvicorn
cp .env.example .env                                       # add provider keys (Gemini / OpenRouter) or run Ollama
python -m app.ui
```

The command prints the URL (default `http://127.0.0.1:8765/`) and a **random access token that is shown once** (set
`UI_AUTH_TOKEN` to use a fixed one; a configured token is never printed or logged). Open the URL, enter the token, create a
session and chat. The server never starts automatically; it only starts when you run that command.

Dashboard: chat with conversation history, session selection/creation/rename/close, tool activity (collapsible requested
calls and bounded, redacted results — including browser screenshots), task status, approval cards with Approve/Deny,
error reporting, settings and capability status (with enable/disable), and a permanent badge showing that
**self-improvement is DISABLED** (the default).

**No token streaming.** `Orchestrator.run()` returns only when the run ends and has no event hooks; adding streaming would
mean changing the stable orchestrator. Instead each message starts a background run and the page polls the persisted
conversation (about once a second), so tool calls and results appear while the run is still going.

### Local authentication and network exposure

Trust model: **one user, on this machine**. Binding to `127.0.0.1` is *not* treated as sufficient protection (other local
users/processes and web pages in your own browser can reach loopback), so:

- every `/api` route (except `/api/health` and `/api/auth/login`) requires a session cookie obtained by presenting the token
  (`HttpOnly`, `SameSite=Strict`; compared in constant time; 5 failures per minute locks login);
- the `Host` header must be an allowed host (defeats DNS rebinding); state-changing requests must carry an allowed `Origin`, the
  `X-JarvisX-Client` header and a JSON/audio content type (defeats cross-site requests); there is no CORS support at all;
- strict CSP (`default-src 'self'`, no inline script/style), `X-Frame-Options: DENY`, `nosniff`, `no-store`; the frontend renders
  everything with `textContent` and keeps no token in web storage; `/docs` and `/openapi.json` are disabled;
- responses never contain provider keys or the auth token (`/api/settings` reports only booleans such as "gemini: configured");
  errors are generic (`internal error`) and tool output shown in the UI is truncated and secret-redacted.

Remote access is **refused by default**: a non-loopback `UI_HOST` needs `UI_ALLOW_REMOTE=true` *and* a `UI_AUTH_TOKEN` of at
least 24 characters. Traffic is plain HTTP — terminate TLS in front, list the public host in `UI_EXTRA_ALLOWED_HOSTS` and set
`UI_COOKIE_SECURE=true` so the session cookie is marked `Secure`. This is a single-user tool, not a multi-tenant service.

### Approval behaviour

The dashboard supplies a `WebApprovalHandler` to the Orchestrator — the existing `ApprovalHandler` injection point. Every
CONFIRM/DANGEROUS tool (including Phase 8's promotion tools, if self-improvement is enabled) pauses the run and appears in the
Approvals panel with redacted arguments. An unanswered request is **denied** after `UI_APPROVAL_TIMEOUT_SECONDS`; shutting down
denies everything pending; DANGEROUS approvals additionally need an explicit acknowledgement. Browser approvals show what you are
really approving (the link destination, the field being filled), not just an opaque id. The dashboard has **no** endpoint to
promote, roll back, edit releases/manifests/pointers or change isolation policy, and cannot enable self-improvement.

### Browser capability (`browser`) — OFF by default

```bash
pip install -r requirements-browser.txt                    # installs Playwright (optional)
python -m playwright install chromium                      # YOU install the browser; JARVIS-X never downloads one
# or point BROWSER_EXECUTABLE_PATH at an existing Chromium/Chrome
# .env:  BROWSER_ENABLED=true     (plus BROWSER_NO_SANDBOX=true only if running as root / in a container)
```

If Playwright or the binary is missing the capability is simply not installed (the dashboard says why) — the core agent is
unaffected. Disabling the capability (config or dashboard) removes the tools and closes any live browser; the tools also
re-check capability state at execution time, so disabling while an approval is pending still blocks the call.

| Tool | Permission | What it does |
|---|---|---|
| `browser_open(url)` | CONFIRM | open a public http(s) URL; returns title + bounded visible text |
| `browser_get_state` | SAFE | current URL (query stripped), title, bounded text |
| `browser_list_links` / `browser_list_form_fields` / `browser_list_clickables` | SAFE | enumerate visible elements with ids and an *allowed/denied + reason* flag |
| `browser_screenshot` | SAFE | bounded JPEG held **in memory** for the dashboard; the model gets metadata only (the providers are text-only) |
| `browser_back` / `browser_forward` | SAFE | history navigation (still goes through the network guard) |
| `browser_follow_link(link_id)` | CONFIRM | navigate to an allowed link |
| `browser_fill_field(field_id, value)` | CONFIRM | type into one permitted text field — **never submits** |
| `browser_click(element_id)` | CONFIRM | only toggle-style buttons / `<summary>` outside forms |
| `browser_close` | SAFE | discard the browser and all state |

There is no JavaScript-evaluation, shell, file or download tool. Arguments are typed Pydantic models (`extra=forbid`, bounded).
All page-derived text is wrapped with an "untrusted data" notice and returned only as a normal tool message.

**What is enforced in code (not by prompting):**
- *Every* request the browser makes is intercepted and answered by JARVIS-X itself: the target passes Phase 6's `UrlValidator`
  (schemes, credentials, private/loopback/link-local/metadata addresses, IP-literal tricks) plus a port allow-list (default 80/443)
  and optional domain allow-list, then a single `GET` is made **to the validated IP** (Host/SNI kept). Because Chromium never opens
  its own connection to a page-chosen host, redirects to private addresses and DNS rebinding cannot reach internal services.
  Every redirect hop is validated; a redirecting top-level navigation is aborted and re-issued by the manager hop by hop
  (we verified that a fulfilled 3xx is followed by Chromium *without* re-entering the interceptor, so redirects are never handed back).
- Non-GET/HEAD requests, WebSockets, beacons, media and other resource types are blocked; downloads (`attachment`, archives,
  executables, PDFs, octet-stream) are blocked; cookies are never sent and `Set-Cookie` is dropped; permissions are denied;
  service workers and popups are blocked; page dialogs are dismissed.
- Page JavaScript is **off by default** (`BROWSER_JAVASCRIPT_ENABLED=false`). DOM reads use Playwright locators (isolated world),
  never evaluated scripts. Login/signup/payment/CAPTCHA/upload/post/send/delete-looking links and controls, password/file/hidden/
  payment fields, fields in POST forms or in forms containing sensitive fields, and secret-looking values are refused.
- Limits: navigation/action timeouts, actions per session (30), redirects (5), requests per page (150), per-resource (5 MB) and
  total (25 MB) bytes, text (8,000 chars), links (50), fields (30), screenshot size (400 KB, hard error if exceeded), idle expiry (5 min).
- Defence in depth: Chromium is launched with a dead proxy (`--proxy-server=http://127.0.0.1:9`, loopback not bypassed), so a request
  that ever escaped interception **fails closed** (covered by a real-browser test).

**Lifecycle:** start (lazy, on the first approved `browser_open`) → validate target → navigate → inspect → bounded result →
clean up. One incognito context at a time, no cookies/profile/storage persisted, discarded on `browser_close`, idle expiry,
crash, capability disable or server shutdown. Tools carry no conversation identity, so the single browser is **shared by
whichever conversation uses it** (it is not isolated per conversation). After a crash/expiry, read operations fail with a clear
message and require an explicit `browser_open` (they never silently relaunch).

**Honest security boundary.** This is a policy-enforced browser, *not* a sandbox you should treat as an isolation boundary.
It runs as a child process of the app under your user account; Chromium's own sandbox is the only process isolation (and must
be disabled as root/in some containers via `BROWSER_NO_SANDBOX`, which weakens it). Known residual risks: a GET to an allowed
public URL can still have side effects on that site (mitigated by per-URL approval and the state-changing link heuristics, not
eliminated); with JavaScript enabled, page scripts run inside Chromium and a Chromium exploit is out of scope; `file://` loads
from http(s) pages are refused by Chromium itself (verified in a test) rather than by our interceptor; keyword heuristics are a
second layer, not the first. If you need stronger isolation, run the whole app (or just the browser) in a container/VM.

### Voice (optional; text always works)

Voice is an **alternative input method, never an authorization**. A transcript is only a *draft*: the dashboard shows it
(editable) and nothing is sent until you press **Confirm & send** (the API rejects `source: "voice"` messages without
`confirmed: true`). The message is then an ordinary user message, so tool permissions and approvals apply unchanged; there is no
voice endpoint that can answer an approval. Recording is push-to-talk only (explicit click, browser microphone permission prompt,
30-second cap, tracks stopped afterwards) — no always-on or background listening. Raw audio is never stored by JARVIS-X.

| Direction | Provider | Where it runs | Notes |
|---|---|---|---|
| recognition | `browser` | **your browser** (Web Speech API) | JARVIS-X never receives audio. **Chrome/Edge send audio to the browser vendor's cloud**; Firefox may not support it. |
| recognition | `faster_whisper` | **local**, in memory | optional dep (`pip install -r requirements-voice.txt`); needs a local model dir (`VOICE_STT_MODEL_PATH`) — downloads only if `VOICE_STT_ALLOW_DOWNLOAD=true` |
| synthesis | `browser` | your browser (`speechSynthesis`) | most OS voices are local; some browser voices (e.g. Chrome's "Google …") are network voices |

Enable with `VOICE_INPUT_ENABLED=true` + `VOICE_STT_PROVIDER=…` and/or `SPEECH_OUTPUT_ENABLED=true` + `SPEECH_SYNTHESIS_PROVIDER=browser`.
No paid speech API is needed anywhere. Server-side synthesis is an extension point only (`SpeechSynthesizer` + `/api/voice/synthesize`,
tested with a stub provider): a CLI engine such as `espeak-ng` was deliberately **not** shipped because Phase 8's invariant
(`tests/test_sandbox.py`) forbids any module other than the container wrapper from starting host processes.
A misconfigured or unavailable provider just leaves that direction disabled with a reason in the Settings tab. Spoken replies:
the text stays on screen; code blocks are omitted, URLs/markdown stripped, secrets redacted, long replies truncated at
`SPEECH_MAX_CHARS` and played chunk by chunk; synthesis is asynchronous and the **Stop speaking** button cancels playback.

### Security restrictions (summary)

Prohibited in the browser: CAPTCHA solving, login/credential submission, account creation, purchases, sending messages/emails,
posting, uploads, downloads, extensions, arbitrary JavaScript, local-file access, cookie/password-store access, and any
localhost/private-network target. Prohibited in the dashboard: promoting/rolling back/editing releases, changing isolation
policy, enabling self-improvement, shell/command/patch execution. Phase 9 does not weaken any Phase 8 control and adds no
automatic code modification: `SELF_IMPROVEMENT_ENABLED=false` remains the default.

### Known limitations and platform notes

- No token streaming (see above); runs cannot be cancelled mid-flight (they are bounded by `MAX_ITERATIONS`/`MAX_TOOL_CALLS`;
  you can deny pending approvals).
- Linux was the only platform exercised. macOS/Windows should work for the dashboard and Playwright but are untested; the
  Chromium sandbox requirements differ per OS.
- The browser capability starts one Chromium child process (via Playwright) — the only process Phase 9 starts. Phase 8's container
  wrapper remains the only code of *this project* that spawns processes for candidate code.
- Browser-side speech recognition (`browser` provider) and `faster_whisper` with a real model are **not covered by automated tests**
  (headless CI has no cloud recognizer; no model could be downloaded). The record → transcribe → confirm flow is tested with a
  stub recognizer and Chromium's fake microphone.
- The single shared browser context and the shared dashboard token are consequences of the single-user trust model.
- Approvals are held in memory (and logged by id/tool/decision); a server restart denies and forgets anything pending.

## Run the tests

Dependencies are split on purpose: `requirements.txt` is runtime only;
`requirements-dev.txt` adds the test tooling (`pytest`, `pytest-asyncio`,
`respx`) and includes `requirements.txt`. The suite needs the dev file —
installing only `requirements.txt` will fail on `import respx`.

```bash
# from a clean checkout / unzipped project
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q
```

`requirements-dev.txt` also installs the optional Playwright dependency so the browser tests can run. The **real-browser** tests
(`tests/test_browser_real.py`, `tests/test_ui_frontend_real.py`, one case in `tests/test_ui_integration.py`) need an actual
Chromium and are **skipped** — with the reason printed by `pytest -rs` — when none can be launched. Provide one with
`python -m playwright install chromium` or `JARVIS_TEST_BROWSER_PATH=/path/to/chromium` (running as root needs no-sandbox, which
the tests enable automatically). Tests that use `FakeDriver` are *mocked* (logic only) and say so; they do not demonstrate browser
isolation. Real-container isolation tests from Phase 8 are still skipped without Docker/Podman.

### Expected result

All tests pass without any API keys or a running Ollama instance — HTTP
calls are mocked with `respx`, and the "requires API key" tests intentionally
exercise the no-key path. You should see something like:

```
tests/test_model_router.py ..........                                  [ XX%]
tests/test_providers.py ..............                                 [ XX%]
tests/test_schemas.py .....                                            [ XX%]
tests/test_workspace.py ...                                            [100%]

======================== XX passed in X.XXs ========================
```

If any test fails with an import error for `google.genai`, re-run
`pip install -r requirements-dev.txt` — the Gemini SDK is a hard dependency
even for tests that don't touch it, since `app/providers/__init__.py`
imports all three providers eagerly.

## Why these dependencies

- **httpx** — async HTTP client for OpenRouter and Ollama; avoids pulling in
  a bigger framework for two REST calls.
- **google-genai** — Gemini's current official SDK (the older
  `google-generativeai` package is fully deprecated/EOL); it owns the native
  function-calling request/response shape, which we convert at the edges.
- **pydantic / pydantic-settings** — typed config and schema validation,
  already listed as a preference.
- **respx** (dev only) — mocks `httpx` calls in tests so the suite needs no
  network access or real credentials.
- **fastapi / uvicorn** (Phase 9) — the local dashboard API and ASGI server; the frontend is plain HTML/JS/CSS with no build step.
- **playwright** (optional, Phase 9) — only for the browser capability; **faster-whisper** (optional) — only for local speech recognition.
- No agent framework, no vector DB.

## What's deliberately NOT here yet

- (historical list from Phase 1–3; browser/UI/voice arrived in Phase 9, see above)
- Embeddings / vector search / semantic memory retrieval (memory selection
  is deterministic keyword+importance+recency scoring — see
  `MemoryManager.select_relevant_memories`)
- LLM-based memory extraction (every memory is created via an explicit
  `MemoryManager.create_memory` call, never inferred from conversation)
- Token-budget-aware context limits (ContextManager uses simple
  configurable item counts, not token counting)
- Conversation summarization/compaction (persistence boundary exists;
  no LLM summarization yet)
- A CLI entrypoint (`run.py`) — the dashboard (`python -m app.ui`) is the only assembled entrypoint
- A YAML/config-driven permission policy engine (permission levels are
  currently set per-Tool in code — intentionally minimal for now)
- Any cybersecurity/recon functionality

These are later phases, built incrementally per the project's development
rules.

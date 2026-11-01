"""`python -m app.ui` — start the local dashboard."""
from __future__ import annotations

import ipaddress
import logging
import sys

from app.config.settings import settings

MIN_REMOTE_TOKEN = 24


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_bind_policy() -> str | None:
    """Returns an error message if the configured bind is not allowed, else None."""
    if not settings.ui_enabled:
        return "UI_ENABLED is false; refusing to start the dashboard."
    if not _is_loopback(settings.ui_host):
        if not settings.ui_allow_remote:
            return (f"UI_HOST={settings.ui_host} is not a loopback address. Set UI_ALLOW_REMOTE=true to expose the "
                    "dashboard on the network (requires UI_AUTH_TOKEN, and you should add TLS in front).")
        if not settings.ui_auth_token or len(settings.ui_auth_token) < MIN_REMOTE_TOKEN:
            return f"Remote binding requires UI_AUTH_TOKEN of at least {MIN_REMOTE_TOKEN} characters."
    return None


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    problem = check_bind_policy()
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    import uvicorn

    from app.bootstrap import build_services
    from app.ui.app import create_app

    services, token, generated = build_services()
    app = create_app(services)
    url = f"http://{settings.ui_host}:{settings.ui_port}/"
    print(f"\nJARVIS-X dashboard: {url}")
    if generated:
        print(f"Access token (generated for this run, shown once): {token}")
    else:
        print("Access token: the value of UI_AUTH_TOKEN")
    if settings.ui_allow_remote and not _is_loopback(settings.ui_host):
        print("WARNING: network exposure enabled; traffic is plain HTTP unless you terminate TLS in front.")
    print(f"Self-improvement: {'ENABLED (config)' if settings.self_improvement_enabled else 'DISABLED'}\n")
    uvicorn.run(app, host=settings.ui_host, port=settings.ui_port, server_header=False, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

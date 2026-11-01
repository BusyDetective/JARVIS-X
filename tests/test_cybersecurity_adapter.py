from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest

import app.cybersecurity.adapter as adapter
from app.cybersecurity.authorization import AuthorizedTarget
from app.cybersecurity.errors import NoPriorResults, ReportPathError
from app.cybersecurity.models import AuthorizedScope, CyberLimits, OperationType, utcnow
from app.cybersecurity.scope import ScopeStore


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=tuple(OperationType),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
        max_targets=5,
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


@pytest.fixture(autouse=True)
def _reset_adapter_state():
    """The scan cache is module-level/process-lifetime by design — reset
    it between tests so they don't see each other's cached results."""
    adapter._cache = None
    yield
    adapter._cache = None


@pytest.fixture
def store():
    return ScopeStore([_scope()])


@pytest.fixture
def limits():
    return CyberLimits(max_subdomains=5, max_hosts=3, max_endpoints=4, max_findings_per_result=2,
                        operation_timeout_seconds=5, request_timeout_seconds=5)


@pytest.fixture(autouse=True)
def _authorize_example_com(monkeypatch):
    """Authorization itself is tested in test_cybersecurity_authorization.py
    — here it's stubbed to a fixed, already-validated target so adapter
    tests exercise only the adapter's own bounding/normalization/caching
    logic."""

    async def _fake_authorize(request, scope_store):
        scope = scope_store.find_for_domain(request.target, request.operation)
        scope_store.record_usage(scope, request.target)
        return AuthorizedTarget(domain=request.target, scope=scope, addresses=("93.184.216.34",))

    monkeypatch.setattr(adapter, "authorize", _fake_authorize)


@pytest.fixture
def fake_engine(monkeypatch):
    engine = SimpleNamespace()
    monkeypatch.setattr(adapter._Engine, "get", classmethod(lambda cls: engine))
    return engine


# ───────────────────────── subdomain_enum ─────────────────────────


async def test_subdomain_enum_normalizes_and_bounds_results(store, limits, fake_engine):
    fake_engine.get_subdomains = lambda domain: [f"h{i}.example.com" for i in range(20)]
    result = await adapter.run_subdomain_enum("example.com", store, limits)
    assert result.counts["subdomains"] == 5  # bounded by max_subdomains even though 20 were "found"
    assert len(result.findings) <= limits.max_findings_per_result
    assert result.truncated is True
    assert all(f.type == "subdomain" for f in result.findings)
    assert not result.errors


async def test_subdomain_enum_handles_empty_result(store, limits, fake_engine):
    fake_engine.get_subdomains = lambda domain: []
    result = await adapter.run_subdomain_enum("example.com", store, limits)
    assert result.counts["subdomains"] == 1  # falls back to [domain] itself
    assert not result.errors


async def test_engine_failure_is_recovered_not_raised(store, limits, fake_engine):
    def _boom(domain):
        raise RuntimeError("some internal detail that must not leak: /etc/shadow contents")

    fake_engine.get_subdomains = _boom
    result = await adapter.run_subdomain_enum("example.com", store, limits)
    assert result.errors
    assert "etc/shadow" not in result.errors[0]
    assert "unexpectedly" in result.errors[0]


async def test_operation_times_out_cleanly(store, limits, fake_engine):
    def _slow(domain):
        import time
        time.sleep(2)
        return []

    fast_limits = CyberLimits(operation_timeout_seconds=0.05)
    fake_engine.get_subdomains = _slow
    result = await adapter.run_subdomain_enum("example.com", store, fast_limits)
    assert result.errors and "timed out" in result.errors[0]


# ───────────────────────── alive_check ─────────────────────────


async def test_alive_check_filters_out_of_domain_hosts(store, limits, fake_engine):
    fake_engine.get_subdomains = lambda domain: ["a.example.com"]
    fake_engine.check_alive = lambda subs: [
        {"url": "https://a.example.com", "status": 200, "title": "A"},
        {"url": "https://attacker.net", "status": 200, "title": "should be filtered"},
    ]
    result = await adapter.run_alive_check("example.com", store, limits)
    assert result.counts["live_hosts"] == 1
    assert result.findings[0].target == "https://a.example.com"


async def test_alive_check_caches_live_hosts_for_reuse(store, limits, fake_engine):
    calls = []
    fake_engine.get_subdomains = lambda domain: ["a.example.com"]

    def _check_alive(subs):
        calls.append(subs)
        return [{"url": "https://a.example.com", "status": 200, "title": "A"}]

    fake_engine.check_alive = _check_alive
    await adapter.run_alive_check("example.com", store, limits)
    await adapter.run_alive_check("example.com", store, limits)
    assert len(calls) == 1  # second call served from cache, no re-scan


# ───────────────────────── endpoint_discovery ─────────────────────────


async def test_endpoint_discovery_filters_and_tags(store, limits, fake_engine):
    fake_engine.get_subdomains = lambda domain: ["a.example.com"]
    fake_engine.check_alive = lambda subs: [{"url": "https://a.example.com", "status": 200, "title": "A"}]
    fake_engine.fetch_wayback_urls = lambda domain: [
        "https://a.example.com/admin", "https://external.net/leak",
    ]
    fake_engine.basic_crawler = lambda hosts: (["https://a.example.com/login"], [])
    fake_engine.filter_important_urls = lambda urls: urls
    fake_engine.classify_endpoint = lambda url: ["AUTH"] if "admin" in url or "login" in url else []

    result = await adapter.run_endpoint_discovery("example.com", store, limits)
    targets = {f.target for f in result.findings}
    assert "https://external.net/leak" not in targets
    assert any("admin" in t for t in targets)


# ───────────────────────── risk_scoring / report (cache-dependent) ─────────────────────────


async def test_risk_scoring_requires_prior_results(store, limits, fake_engine):
    with pytest.raises(NoPriorResults):
        await adapter.run_risk_scoring("example.com", store, limits)


async def test_risk_scoring_uses_cached_results_without_new_network_calls(store, limits, fake_engine):
    fake_engine.get_subdomains = lambda domain: ["a.example.com"]
    fake_engine.check_alive = lambda subs: [{"url": "https://a.example.com", "status": 200, "title": "A"}]
    fake_engine.fetch_wayback_urls = lambda domain: []
    fake_engine.basic_crawler = lambda hosts: ([], [])
    fake_engine.filter_important_urls = lambda urls: urls
    fake_engine.classify_endpoint = lambda url: []
    await adapter.run_endpoint_discovery("example.com", store, limits)

    risk_calls = []

    def _calculate_risk(endpoints, alive_hosts, findings):
        risk_calls.append((endpoints, alive_hosts, findings))
        return {"summary": {"overall_risk_level": "LOW", "security_score": 90}}

    fake_engine.calculate_risk = _calculate_risk
    result = await adapter.run_risk_scoring("example.com", store, limits)
    assert len(risk_calls) == 1
    assert risk_calls[0][2] == []  # no vulnerability findings are ever passed — none are produced
    assert "LOW" in result.findings[0].detail


async def test_report_generation_requires_prior_results(store, limits, fake_engine):
    with pytest.raises(NoPriorResults):
        await adapter.run_report_generation("example.com", store, limits)


async def test_report_generation_confines_output_to_configured_directory(
    store, limits, fake_engine, tmp_path, monkeypatch
):
    from app.config.settings import settings

    report_dir = tmp_path / "reports_out"
    monkeypatch.setattr(settings, "cybersecurity_report_dir", report_dir)

    # Simulate the vendored generator's behavior: writes to a hardcoded
    # "reports/<domain>_report.txt" RELATIVE TO CWD.
    vendor_reports = tmp_path / "reports"
    vendor_reports.mkdir()

    def _fake_generate_report(domain, alive_hosts, endpoints, findings, risk):
        p = vendor_reports / f"{domain.replace('.', '_')}_report.txt"
        p.write_text("fake report body")
        return str(p)

    fake_engine.get_subdomains = lambda domain: ["a.example.com"]
    fake_engine.check_alive = lambda subs: [{"url": "https://a.example.com", "status": 200, "title": "A"}]
    fake_engine.fetch_wayback_urls = lambda domain: []
    fake_engine.basic_crawler = lambda hosts: ([], [])
    fake_engine.filter_important_urls = lambda urls: urls
    fake_engine.classify_endpoint = lambda url: []
    await adapter.run_endpoint_discovery("example.com", store, limits)

    fake_engine.generate_report = _fake_generate_report
    metadata = await adapter.run_report_generation("example.com", store, limits)

    final_path = report_dir / metadata.relative_path
    assert final_path.is_file()
    assert final_path.read_text() == "fake report body"
    # The original vendor-side file must be gone (moved, not copied) and
    # the final path must actually sit inside report_dir.
    assert not (vendor_reports / "example_com_report.txt").exists()
    assert report_dir.resolve() in final_path.resolve().parents


async def test_report_generation_fails_closed_with_no_configured_directory(
    store, limits, fake_engine, monkeypatch
):
    from app.config.settings import settings

    monkeypatch.setattr(settings, "cybersecurity_report_dir", None)
    fake_engine.get_subdomains = lambda domain: ["a.example.com"]
    fake_engine.check_alive = lambda subs: [{"url": "https://a.example.com", "status": 200, "title": "A"}]
    fake_engine.fetch_wayback_urls = lambda domain: []
    fake_engine.basic_crawler = lambda hosts: ([], [])
    fake_engine.filter_important_urls = lambda urls: urls
    fake_engine.classify_endpoint = lambda url: []
    await adapter.run_endpoint_discovery("example.com", store, limits)

    with pytest.raises(ReportPathError):
        await adapter.run_report_generation("example.com", store, limits)


# ───────────────────────── engine import failure ─────────────────────────


async def test_engine_unavailable_is_reported_not_raised(store, limits, monkeypatch):
    from app.cybersecurity.errors import EngineUnavailable

    def _boom(cls):
        raise EngineUnavailable("vendored recon engine dependencies are not importable: ImportError")

    monkeypatch.setattr(adapter._Engine, "get", classmethod(_boom))
    result = await adapter.run_subdomain_enum("example.com", store, limits)
    assert result.errors and "not importable" in result.errors[0]

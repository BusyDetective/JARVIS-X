from __future__ import annotations

import pytest

from app.engineering.models import PlanStage
from app.improvement.discovery import ImprovementDiscovery
from app.improvement.evaluator import ImprovementEvaluator, ResearchEvidence, summarize_research
from app.improvement.models import RecommendedAction as A
from app.improvement.models import RiskLevel as R
from app.improvement.planner import ImprovementPlanner
from app.versioning.manifest import build_manifest
from app.web.limits import WebLimits
from app.web.models import ResearchMode
from app.web.research import WebResearchManager
from tests.improvement_helpers import make_project
from tests.web_helpers import FakeFetcher, FakeSearchProvider

D = ImprovementDiscovery()
E = ImprovementEvaluator()
GOOD = ResearchEvidence(source_count=5, distinct_domains=4, https_sources=5, fetched_pages=3)


def req(goal, scope=None):
    return D.create_request(goal, scope or [])


def test_evaluation_is_deterministic():
    r = req("Improve performance of the string utilities", ["app/util/strings.py"])
    a, b = E.evaluate(r, GOOD), E.evaluate(r, GOOD)
    assert a == b and a.heuristic is True


def test_scores_are_bounded_and_explained():
    ev = E.evaluate(req("Fix a performance bug in utilities"), GOOD, ["app/util/strings.py"])
    for v in (ev.score, ev.benefit_score, ev.compatibility_score, ev.risk_score, ev.confidence_score):
        assert 0 <= v <= 100
    assert ev.risk_level is R.MEDIUM and ev.rationale and any("confidence" in line for line in ev.rationale)
    assert ev.recommended_action is A.PROPOSE


def test_no_paths_means_conservative_high_risk_and_approval():
    ev = E.evaluate(req("Improve the documentation formatting"), GOOD)
    assert ev.risk_level is R.HIGH and any("no concrete paths" in r for r in ev.risks)
    assert ev.recommended_action is A.REQUIRE_APPROVAL


def test_evidence_changes_confidence_and_action():
    r = req("Improve performance of the string utilities", ["app/util/strings.py"])
    paths = ["app/util/strings.py"]
    none = E.evaluate(r, None, paths)
    assert none.confidence_score == 20 and none.recommended_action is A.RESEARCH_MORE
    some = E.evaluate(r, ResearchEvidence(source_count=3, distinct_domains=3, https_sources=3, fetched_pages=2), paths)
    assert some.confidence_score > none.confidence_score and some.recommended_action is A.PROPOSE
    assert E.evaluate(r, GOOD, paths).confidence_score > some.confidence_score


@pytest.mark.parametrize("goal", ["Change how authentication works", "Relax permission checks for tools", "Update the sandbox policy",
                                  "Modify rollback behaviour", "Disable the approval step", "Store credentials differently",
                                  "Change capability enforcement"])
def test_security_sensitive_goals_are_critical_and_require_approval(goal):
    ev = E.evaluate(req(goal), GOOD, ["app/util/x.py"])
    assert ev.risk_level is R.CRITICAL and ev.recommended_action is A.REQUIRE_APPROVAL
    assert any("security-sensitive" in r for r in ev.risks)


def test_dependency_goals_always_require_approval():
    ev = E.evaluate(req("Upgrade the httpx library to a newer version"), GOOD, ["app/util/x.py"])
    assert ev.risk_level.rank >= R.HIGH.rank and ev.recommended_action is A.REQUIRE_APPROVAL
    assert ev.compatibility_score < 80 and any("dependency" in r for r in ev.risks)
    ev2 = E.evaluate(req("Tidy something harmless here"), GOOD, ["requirements.txt"])
    assert ev2.risk_level.rank >= R.HIGH.rank and ev2.recommended_action is A.REQUIRE_APPROVAL


def test_breaking_change_wording_lowers_compatibility():
    plain = E.evaluate(req("Improve the string helpers"), GOOD, ["app/util/s.py"])
    breaking = E.evaluate(req("Rewrite and migrate the string helpers"), GOOD, ["app/util/s.py"])
    assert breaking.compatibility_score < plain.compatibility_score


@pytest.mark.parametrize("path", [".env", "config/.env.production", "keys/server.pem", "id_rsa"])
def test_protected_secret_targets_are_blockers(path):
    ev = E.evaluate(req("Improve the configuration loading"), GOOD, [path])
    assert ev.blockers and ev.recommended_action is A.IGNORE


@pytest.mark.parametrize("path", ["../outside.py", "/etc/passwd", "a/../../b", "a\\b"])
def test_unsafe_planned_paths_are_blockers(path):
    ev = E.evaluate(req("Improve the configuration loading"), GOOD, [path])
    assert any("not a safe relative path" in b for b in ev.blockers) and ev.recommended_action is A.IGNORE


def test_critical_protected_areas_from_paths():
    ev = E.evaluate(req("Make a small improvement here"), GOOD, ["app/security/permissions.py"])
    assert ev.risk_level is R.CRITICAL and ev.recommended_action is A.REQUIRE_APPROVAL


def test_summarize_research_counts_only():
    provider = FakeSearchProvider([f"https://s{i}.example.com/p" for i in range(3)])
    result = __import__("asyncio").run(WebResearchManager(provider, FakeFetcher(), WebLimits()).research("q", ResearchMode.SEARCH_AND_FETCH, max_pages=2))
    ev = summarize_research(result)
    assert ev.source_count == 3 and ev.distinct_domains == 3 and ev.https_sources == 3 and ev.fetched_pages == 2
    assert set(ev.model_dump()) == {"source_count", "distinct_domains", "https_sources", "fetched_pages"}


def test_dependency_candidates_from_manifest(tmp_path):
    project = make_project(tmp_path / "p")
    cands = D.dependency_candidates(build_manifest(project))
    assert [(c.name, c.specifier, c.group) for c in cands] == [("pytest", ">=8", "dev"), ("httpx", ">=0.27", "runtime")]


def test_planner_reuses_the_engineering_plan(tmp_path):
    from app.engineering.analysis import ProjectInspector
    from app.workspace.manager import WorkspaceManager
    project = make_project(tmp_path / "p")
    structure = ProjectInspector(WorkspaceManager(project)).inspect()
    r = req("Improve the util module", ["app/util.py"])
    plan = ImprovementPlanner().create_plan(r, structure, E.evaluate(r, GOOD, ["app/util.py"]))
    assert [t.stage for t in plan.tasks] == list(PlanStage) and plan.requires_approval is True
    assert plan.tasks[2].files == ["app/util.py"]
    assert any("Estimated risk" in n for n in plan.notes) and any("sandbox" in n for n in plan.notes)


def test_discovery_requests_are_structured_not_executed():
    r = D.create_request("Investigate whether better approaches to provider routing exist", ["app/providers"], ["no breaking changes"], "alice")
    assert r.requested_by == "alice" and r.scope == ["app/providers"] and r.constraints == ["no breaking changes"]
    with pytest.raises(ValueError):
        D.create_request("tiny")

from __future__ import annotations

import re

from pydantic import BaseModel

from app.improvement.classification import classify_changes, classify_path
from app.improvement.models import (
    AutomationMode,
    ChangeOperation,
    EvaluationResult,
    ImprovementRequest,
    RecommendedAction,
    RiskLevel,
)
from app.web.models import ResearchResult
from app.workspace.manager import is_protected_path

_BENEFIT_WORDS = re.compile(r"\b(secur\w*|vulnerab\w*|cve|fix\w*|bug\w*|perform\w*|faster|speed\w*|reliab\w*|improv\w*|upgrad\w*|update\w*)\b", re.I)
_BREAKING_WORDS = re.compile(r"\b(major|breaking|rewrite|migrat\w*|replace\w*|overhaul)\b", re.I)
_DEPENDENCY_WORDS = re.compile(r"\b(dependenc\w*|librar\w*|package\w*|version\w*|upgrade\w*)\b", re.I)
_SECURITY_AREA_WORDS = re.compile(
    r"\b(auth\w*|permission\w*|approval|secret\w*|credential\w*|sandbox\w*|rollback|capabilit\w*|security boundar\w*|update engine)\b", re.I)
_RISK_SCORE = {RiskLevel.LOW: 10, RiskLevel.MEDIUM: 35, RiskLevel.HIGH: 65, RiskLevel.CRITICAL: 90}


class ResearchEvidence(BaseModel):
    """Counts and facts about web research — never its content."""

    source_count: int = 0
    distinct_domains: int = 0
    https_sources: int = 0
    fetched_pages: int = 0


def summarize_research(result: ResearchResult) -> ResearchEvidence:
    return ResearchEvidence(
        source_count=len(result.sources), distinct_domains=len({s.domain for s in result.sources}),
        https_sources=sum(1 for s in result.sources if s.https), fetched_pages=result.usage.pages_fetched)


def _clamp(v: float) -> float:
    return float(max(0, min(100, round(v, 1))))


class ImprovementEvaluator:
    """Deterministic, explainable scoring. These are heuristics over counts and
    path classification — NOT an authoritative judgement, and no LLM is involved.
    The final risk level always comes from the actual change set (see
    classification.py), which can only raise what is estimated here."""

    def evaluate(
        self, request: ImprovementRequest, evidence: ResearchEvidence | None = None,
        planned_paths: list[str] | None = None,
    ) -> EvaluationResult:
        ev = evidence or ResearchEvidence()
        text = " ".join([request.goal, *request.scope, *request.constraints])
        rationale: list[str] = []
        risks: list[str] = []
        blockers: list[str] = []

        # --- risk (from planned paths when known; otherwise conservative) ---
        paths = list(planned_paths or [])
        for p in paths:
            if p.startswith(("/", "~")) or ".." in p.split("/") or "\\" in p:
                blockers.append(f"planned path is not a safe relative path: {p[:80]}")
            elif is_protected_path(p):
                blockers.append(f"planned path targets a protected secret file: {p}")
        safe_paths = [p for p in paths if not any(p in b for b in blockers)]
        if safe_paths:
            assessment = classify_changes([(p, ChangeOperation.MODIFY) for p in safe_paths])
            risk_level, mode = assessment.risk, assessment.mode
            risks += assessment.reasons
        else:
            risk_level, mode = RiskLevel.HIGH, AutomationMode.APPROVAL_REQUIRED
            risks.append("no concrete paths yet: risk assumed HIGH until a change set exists")
        if _SECURITY_AREA_WORDS.search(text):
            risk_level = RiskLevel.CRITICAL
            mode = AutomationMode.APPROVAL_REQUIRED
            risks.append("goal touches security-sensitive functionality")
        dependency = bool(_DEPENDENCY_WORDS.search(text)) or any(
            classify_path(p, ChangeOperation.MODIFY)[2] & {"dependency_change"} for p in safe_paths)
        if dependency:
            risks.append("dependency change: installing or upgrading always requires explicit approval")
            if risk_level.rank < RiskLevel.HIGH.rank:
                risk_level = RiskLevel.HIGH
            mode = AutomationMode.APPROVAL_REQUIRED
        risk_score = _RISK_SCORE[risk_level] + (10 if len(safe_paths) > 10 else 0)

        # --- benefit ---
        benefit = 50 + (10 if _BENEFIT_WORDS.search(text) else 0) + 4 * min(ev.source_count, 5)
        rationale.append(f"benefit {_clamp(benefit)}: goal keywords and {ev.source_count} research source(s)")

        # --- compatibility ---
        compat = 80 - (15 if _BREAKING_WORDS.search(text) else 0) - (20 if dependency else 0)
        if _BREAKING_WORDS.search(text):
            risks.append("goal suggests a breaking or large-scale change")
        rationale.append(f"compatibility {_clamp(compat)}: starts at 80, reduced for breaking-change wording or dependency work")

        # --- confidence ---
        if ev.source_count == 0:
            confidence = 20.0
            rationale.append("confidence 20: no research evidence yet")
        else:
            confidence = (30 + 10 * min(ev.distinct_domains, 4) + (10 if ev.https_sources == ev.source_count else 0)
                          + (10 if ev.source_count >= 3 else 0))
            rationale.append(f"confidence {_clamp(confidence)}: {ev.distinct_domains} domain(s), {ev.https_sources}/{ev.source_count} https")

        benefit, compat, confidence, risk_score = _clamp(benefit), _clamp(compat), _clamp(confidence), _clamp(risk_score)
        score = _clamp(0.35 * benefit + 0.25 * compat + 0.25 * (100 - risk_score) + 0.15 * confidence)

        if blockers:
            action = RecommendedAction.IGNORE
        elif confidence < 40:
            action = RecommendedAction.RESEARCH_MORE
        elif risk_level.rank >= RiskLevel.CRITICAL.rank or mode == AutomationMode.APPROVAL_REQUIRED:
            action = RecommendedAction.REQUIRE_APPROVAL
        elif score >= 50:
            action = RecommendedAction.PROPOSE
        else:
            action = RecommendedAction.IGNORE
        rationale.append(f"overall score {score}; recommended action {action.value}")
        return EvaluationResult(
            score=score, benefit_score=benefit, compatibility_score=compat, risk_score=risk_score,
            confidence_score=confidence, risk_level=risk_level, rationale=rationale, risks=risks,
            blockers=blockers, recommended_action=action)

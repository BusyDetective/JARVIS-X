"""
Report Generator v3.0

Professional security reporting engine comparable to Burp Enterprise,
Nessus Expert, and commercial AppSec platforms.

Generates:
  - Text reports  (.txt)  — structured, human-readable
  - JSON exports  (.json) — full fidelity for API consumers
  - Markdown      (.md)   — GitHub/GitLab/Confluence ready

Public API (backwards-compatible):
    generate_text_report(domain, scan_metadata, endpoints, findings, risk, attack_surface) -> str
    generate_json_report(domain, scan_metadata, endpoints, findings, risk, attack_surface) -> str
    generate_markdown_report(domain, scan_metadata, endpoints, findings, risk, attack_surface) -> str
    generate_report(domain, alive_hosts, endpoints, findings, risk) -> str   # legacy shim
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

# ===============================================
# CONSTANTS
# ===============================================

_SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
}

_SEVERITY_EMOJI: dict[str, str] = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "⚪",
}

_RECOMMENDATIONS: list[str] = [
    "1.  Prioritize fixing all Critical and High severity findings immediately.",
    "2.  Implement input validation and sanitization on all user inputs.",
    "3.  Use parameterized queries to prevent SQL injection.",
    "4.  Implement Content Security Policy (CSP) headers.",
    "5.  Enable HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options).",
    "6.  Conduct security code review for authentication and authorization logic.",
    "7.  Implement proper API access controls and rate limiting.",
    "8.  Review and restrict administrative endpoints.",
    "9.  Keep all software dependencies up to date.",
    "10. Establish a vulnerability disclosure program.",
]

# CWE / OWASP / CAPEC mappings (extended)
_VULN_META: dict[str, dict] = {
    "SQL Injection":      {"cwe": "CWE-89",  "owasp": "A03:2021", "capec": "CAPEC-66",  "impact": "Data breach, authentication bypass, full database compromise."},
    "XSS":                {"cwe": "CWE-79",  "owasp": "A03:2021", "capec": "CAPEC-86",  "impact": "Session hijacking, credential theft, UI redressing."},
    "Reflected XSS":      {"cwe": "CWE-79",  "owasp": "A03:2021", "capec": "CAPEC-86",  "impact": "Session hijacking, credential theft, phishing."},
    "Stored XSS":         {"cwe": "CWE-79",  "owasp": "A03:2021", "capec": "CAPEC-86",  "impact": "Persistent session hijacking, worm propagation."},
    "SSRF":               {"cwe": "CWE-918", "owasp": "A10:2021", "capec": "CAPEC-664", "impact": "Internal network pivoting, cloud metadata exfiltration, RCE."},
    "LFI":                {"cwe": "CWE-22",  "owasp": "A01:2021", "capec": "CAPEC-252", "impact": "Sensitive file disclosure, potential RCE via log poisoning."},
    "SSTI":               {"cwe": "CWE-94",  "owasp": "A03:2021", "capec": "CAPEC-242", "impact": "Remote code execution on the server."},
    "Open Redirect":      {"cwe": "CWE-601", "owasp": "A01:2021", "capec": "CAPEC-194", "impact": "Phishing attacks, OAuth token theft."},
    "Path Traversal":     {"cwe": "CWE-22",  "owasp": "A01:2021", "capec": "CAPEC-139", "impact": "Sensitive file disclosure, configuration leakage."},
    "Command Injection":  {"cwe": "CWE-78",  "owasp": "A03:2021", "capec": "CAPEC-88",  "impact": "Full server compromise, lateral movement."},
    "XXE":                {"cwe": "CWE-611", "owasp": "A05:2021", "capec": "CAPEC-221", "impact": "File disclosure, SSRF, DoS."},
    "Insecure Deserialization": {"cwe": "CWE-502", "owasp": "A08:2021", "capec": "CAPEC-586", "impact": "RCE, privilege escalation."},
    "Broken Auth":        {"cwe": "CWE-287", "owasp": "A07:2021", "capec": "CAPEC-196", "impact": "Account takeover, privilege escalation."},
    "Sensitive Data":     {"cwe": "CWE-200", "owasp": "A02:2021", "capec": "CAPEC-118", "impact": "Credential leakage, PII exposure, compliance violations."},
    "Missing Security Header": {"cwe": "CWE-693", "owasp": "A05:2021", "capec": "CAPEC-154", "impact": "Increased attack surface for XSS, clickjacking, MIME sniffing."},
}

_DEFAULT_META: dict = {"cwe": "N/A", "owasp": "N/A", "capec": "N/A", "impact": "See finding details."}

# ===============================================
# INTERNAL HELPERS
# ===============================================

def _safe_domain(domain: str) -> str:
    return domain.replace(".", "_").replace("/", "_")


def _ensure_reports_dir() -> None:
    os.makedirs("reports", exist_ok=True)


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "Low"), 4),
    )


def _get_vuln_meta(finding: dict) -> dict:
    vuln_type = finding.get("type", "")
    for key in _VULN_META:
        if key.lower() in vuln_type.lower():
            return _VULN_META[key]
    return _DEFAULT_META


def _validation_bucket(finding: dict) -> str:
    """Classify finding into validation tier."""
    confirmed  = finding.get("validated", False) or finding.get("confirmed", False)
    confidence = int(finding.get("confidence", 0))
    if confirmed or confidence >= 80:
        return "Confirmed"
    if confidence >= 50:
        return "Likely"
    if confidence >= 20:
        return "Needs Manual Review"
    return "Rejected"

# ===============================================
# SCAN STATISTICS  (computed once, reused everywhere)
# ===============================================

def _compute_stats(
    findings:      list[dict],
    endpoints:     list[dict],
    risk:          dict,
    attack_surface:dict,
    scan_metadata: dict,
) -> dict:
    """
    Compute all statistics and summaries in one pass.
    Returns a rich stats dict reused by all three generators.
    """
    # ---------------------------------------------------------------
    # Risk counts: prefer risk["summary"] (set by risk_scoring) so we
    # never re-derive severity from the bucket lists, which would
    # diverge if deduplication or capping changed the list length.
    # ---------------------------------------------------------------
    summary        = risk.get("summary", {})
    critical_count = summary.get("critical", len(risk.get("critical", [])))
    high_count     = summary.get("high",     len(risk.get("high",     [])))
    medium_count   = summary.get("medium",   len(risk.get("medium",   [])))
    low_count      = summary.get("low",      len(risk.get("low",      [])))
    total_findings = len(findings)

    overall_level  = summary.get("overall_risk_level", "UNKNOWN")
    # security_score is always set by risk_scoring.calculate_risk(); default 100
    # guards against old callers that pass a risk dict without a summary.
    security_score = summary.get("security_score", 100)
    if not isinstance(security_score, (int, float)):
        security_score = 100
    security_score = max(int(security_score), 0)
    top_risk_score = summary.get("top_risk_score", "N/A")

    # Sorted findings (cached)
    sorted_findings = _sort_findings(findings)

    # Technology extraction from endpoints
    tech_counter: Counter = Counter()
    for ep in endpoints:
        for tag in ep.get("tags", []):
            tech_counter[tag] += 1

    # Technologies from scan_metadata (if fingerprinter populated it)
    tech_details: list[dict] = scan_metadata.get("technologies", [])

    # Validation distribution
    validation_dist: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        validation_dist[_validation_bucket(f)].append(f)

    # Finding type distribution
    type_counter: Counter = Counter(f.get("type", "Unknown") for f in findings)

    # Attack surface counters
    as_summary    = attack_surface.get("summary", {})
    subdomains    = attack_surface.get("subdomains",       [])
    alive_hosts   = attack_surface.get("alive_hosts",      [])
    interesting   = attack_surface.get("interesting_urls", [])
    js_files      = attack_surface.get("js_files",         [])
    secrets       = attack_surface.get("secrets",          [])
    directories   = attack_surface.get("directories",      [])
    hvt           = attack_surface.get("high_value_targets",[])
    chains        = attack_surface.get("chains",           [])

    # Parameters from endpoints
    param_count = sum(
        len(ep.get("params", ep.get("parameters", [])))
        for ep in endpoints
        if isinstance(ep, dict)
    )

    # Chart data
    severity_pie = {
        "Critical": critical_count,
        "High":     high_count,
        "Medium":   medium_count,
        "Low":      low_count,
    }
    tech_dist     = dict(tech_counter.most_common(15))
    validation_dist_counts = {k: len(v) for k, v in validation_dist.items()}

    chart_data = {
        "severity_pie":         severity_pie,
        "risk_bar":             severity_pie,
        "technology_distribution": tech_dist,
        "validation_distribution": validation_dist_counts,
        "finding_type_distribution": dict(type_counter.most_common(10)),
        "attack_surface_graph": {
            "subdomains":  len(subdomains),
            "alive_hosts": len(alive_hosts),
            "endpoints":   len(endpoints),
            "js_files":    len(js_files),
            "secrets":     len(secrets),
        },
    }

    return {
        # Counts
        "critical_count":   critical_count,
        "high_count":       high_count,
        "medium_count":     medium_count,
        "low_count":        low_count,
        "total_findings":   total_findings,
        # Risk summary
        "overall_level":    overall_level,
        "security_score":   security_score,
        "top_risk_score":   top_risk_score,
        # Sorted findings
        "sorted_findings":  sorted_findings,
        # Tech
        "tech_counter":     tech_counter,
        "tech_details":     tech_details,
        # Validation
        "validation_dist":  validation_dist,
        # Attack surface components
        "as_summary":       as_summary,
        "subdomains":       subdomains,
        "alive_hosts":      alive_hosts,
        "interesting":      interesting,
        "js_files":         js_files,
        "secrets":          secrets,
        "directories":      directories,
        "hvt":              hvt,
        "chains":           chains,
        # Parameters
        "param_count":      param_count,
        # Charts
        "chart_data":       chart_data,
        # Other
        "type_counter":     type_counter,
    }

# ===============================================
# TEXT REPORT SECTIONS
# ===============================================

def _txt_header(domain: str, scan_metadata: dict, st: dict) -> list[str]:
    lines = []
    lines.append("=" * 80)
    lines.append("  AI BUG BOUNTY RECONNAISSANCE REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"  Domain:           {domain}")
    lines.append(f"  Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if scan_metadata.get("duration"):
        lines.append(f"  Scan Duration:    {scan_metadata['duration']} seconds")
    if scan_metadata.get("scan_id"):
        lines.append(f"  Scan ID:          {scan_metadata['scan_id']}")
    lines.append("")
    return lines


def _txt_executive_summary(domain: str, st: dict, scan_metadata: dict) -> list[str]:
    lines = []
    lines.append("=" * 80)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"  Overall Risk Level  : {st['overall_level']}")
    lines.append(f"  Security Score      : {st['security_score']}/100")
    lines.append(f"  Top Finding Score   : {st['top_risk_score']}")
    lines.append("")

    lines.append("  Risk Distribution:")
    lines.append(f"    Critical  : {st['critical_count']:>4}")
    lines.append(f"    High      : {st['high_count']:>4}")
    lines.append(f"    Medium    : {st['medium_count']:>4}")
    lines.append(f"    Low       : {st['low_count']:>4}")
    lines.append(f"    Total     : {st['total_findings']:>4}")
    lines.append("")

    # Highest risk findings
    top = st["sorted_findings"][:5]
    if top:
        lines.append("  Highest Risk Findings:")
        for f in top:
            sev  = f.get("severity", "?")
            cvss = f.get("cvss", "N/A")
            t    = f.get("type", "Unknown")
            url  = f.get("url", "")[:60]
            lines.append(f"    [{sev:<8}] CVSS {cvss:<5}  {t} — {url}")
        lines.append("")

    # Technology summary
    if st["tech_counter"]:
        lines.append("  Technology Summary:")
        for tech, count in st["tech_counter"].most_common(8):
            lines.append(f"    • {tech} ({count} endpoints)")
        lines.append("")

    # Framework summary (tech_details from fingerprinter)
    frameworks = [t for t in st["tech_details"] if t.get("category") in ("Frontend", "Backend", "CMS")]
    if frameworks:
        lines.append("  Framework Summary:")
        for fw in frameworks[:6]:
            ver = f" v{fw['version']}" if fw.get("version") else ""
            lines.append(f"    • {fw['name']}{ver} [{fw.get('category','')}]")
        lines.append("")

    # Attack surface summary
    as_s = st["as_summary"]
    if as_s:
        lines.append("  Attack Surface Summary:")
        lines.append(f"    Subdomains      : {len(st['subdomains'])}")
        lines.append(f"    Alive Hosts     : {len(st['alive_hosts'])}")
        lines.append(f"    Endpoints       : {as_s.get('total_endpoints', 0)}")
        lines.append(f"    High-Value      : {as_s.get('high_value', 0)}")
        lines.append(f"    Attack Chains   : {as_s.get('attack_chains', 0)}")
        lines.append("")

    # Validation summary
    vd = st["validation_dist"]
    if any(vd.values()):
        lines.append("  Validation Summary:")
        for bucket in ("Confirmed", "Likely", "Needs Manual Review", "Rejected"):
            cnt = len(vd.get(bucket, []))
            lines.append(f"    {bucket:<22}: {cnt}")
        lines.append("")

    return lines


def _txt_findings(st: dict) -> list[str]:
    lines = []
    if not st["sorted_findings"]:
        return lines

    lines.append("=" * 80)
    lines.append("  DETAILED FINDINGS")
    lines.append("=" * 80)
    lines.append("")

    for idx, finding in enumerate(st["sorted_findings"][:100], 1):
        vuln_type   = finding.get("type",        "Unknown")
        url         = finding.get("url",         "")
        severity    = finding.get("severity",    "Low")
        cvss        = finding.get("cvss",        "N/A")
        confidence  = finding.get("confidence",  "N/A")
        param       = finding.get("param",       "")
        payload     = finding.get("payload",     "")
        evidence    = finding.get("evidence",    "")
        remediation = finding.get("remediation", "")
        poc         = finding.get("poc",         "")
        validated   = finding.get("validated",   False)
        val_status  = _validation_bucket(finding)

        meta        = _get_vuln_meta(finding)
        tech_ctx    = finding.get("technology",  finding.get("tech_context", ""))

        lines.append(f"\n[{idx:>3}] {vuln_type.upper()} — {severity.upper()}")
        lines.append("-" * 76)
        lines.append(f"       URL              : {url}")
        if param:
            lines.append(f"       Parameter        : {param}")
        if payload:
            lines.append(f"       Payload          : {payload[:100]}")
        lines.append(f"       Severity         : {severity}")
        lines.append(f"       CVSS Score       : {cvss}")
        lines.append(f"       Confidence       : {confidence}%")
        lines.append(f"       Validation       : {val_status}")
        lines.append(f"       CWE              : {meta['cwe']}")
        lines.append(f"       OWASP            : {meta['owasp']}")
        lines.append(f"       CAPEC            : {meta['capec']}")
        if tech_ctx:
            lines.append(f"       Tech Context     : {tech_ctx}")
        lines.append(f"       Business Impact  : {meta['impact']}")

        if evidence:
            lines.append(f"\n       Evidence:")
            lines.append(f"         {evidence}")

        if remediation:
            lines.append(f"\n       Remediation:")
            for line in remediation.split("\n"):
                if line.strip():
                    lines.append(f"         {line}")

        refs = finding.get("references", [])
        if refs:
            lines.append(f"\n       References:")
            for ref in refs[:3]:
                lines.append(f"         • {ref}")

        if poc:
            lines.append(f"\n       PoC URL          : {poc}")

        lines.append("")

    return lines


def _txt_attack_surface(st: dict) -> list[str]:
    lines = []
    if not st["as_summary"] and not st["subdomains"]:
        return lines

    lines.append("=" * 80)
    lines.append("  ATTACK SURFACE ANALYSIS")
    lines.append("=" * 80)
    lines.append("")

    as_s = st["as_summary"]
    lines.append(f"  Total Endpoints    : {as_s.get('total_endpoints', 0)}")
    lines.append(f"  High-Value Targets : {as_s.get('high_value', 0)}")
    lines.append(f"  Attack Chains      : {as_s.get('attack_chains', 0)}")
    lines.append(f"  Choke Points       : {as_s.get('choke_points', 0)}")
    lines.append(f"  Subdomains         : {len(st['subdomains'])}")
    lines.append(f"  Alive Hosts        : {len(st['alive_hosts'])}")
    lines.append(f"  JS Files           : {len(st['js_files'])}")
    lines.append(f"  Secrets Found      : {len(st['secrets'])}")
    lines.append(f"  Directories        : {len(st['directories'])}")
    lines.append("")

    if st["subdomains"]:
        lines.append("  Subdomains (top 20):")
        for s in st["subdomains"][:20]:
            lines.append(f"    • {s}")
        lines.append("")

    if st["alive_hosts"]:
        lines.append("  Alive Hosts (top 20):")
        for h in st["alive_hosts"][:20]:
            url = h.get("url", h) if isinstance(h, dict) else h
            lines.append(f"    • {url}")
        lines.append("")

    if st["interesting"]:
        lines.append("  Interesting URLs (top 15):")
        for u in st["interesting"][:15]:
            lines.append(f"    • {u}")
        lines.append("")

    if st["js_files"]:
        lines.append("  JavaScript Files (top 10):")
        for js in st["js_files"][:10]:
            lines.append(f"    • {js}")
        lines.append("")

    if st["secrets"]:
        lines.append("  Secrets Found:")
        for sec in st["secrets"][:10]:
            if isinstance(sec, dict):
                lines.append(f"    • [{sec.get('type','?')}] {sec.get('url','')}")
            else:
                lines.append(f"    • {sec}")
        lines.append("")

    if st["hvt"]:
        lines.append("  High-Value Targets:")
        for target in st["hvt"][:8]:
            score = target.get("score", 0)
            url   = target.get("url",   "")
            lines.append(f"    [{score:>3}] {url[:72]}")
        lines.append("")

    if st["chains"]:
        lines.append("  Attack Chains:")
        for chain in st["chains"][:5]:
            lines.append(f"\n    Chain Score  : {chain.get('chain_score', 'N/A')}")
            lines.append(f"    Description  : {chain.get('description', '')}")
            lines.append(f"    Entry   →  {chain.get('entry',  '')[:60]}")
            if chain.get("pivot"):
                lines.append(f"    Pivot   →  {chain['pivot'][:60]}")
            lines.append(f"    Target  →  {chain.get('target', '')[:60]}")
        lines.append("")

    return lines


def _txt_technology(endpoints: list[dict], st: dict) -> list[str]:
    lines = []

    # From tech_details (fingerprinter output)
    if st["tech_details"]:
        lines.append("=" * 80)
        lines.append("  TECHNOLOGY INTELLIGENCE")
        lines.append("=" * 80)
        lines.append("")
        for t in st["tech_details"][:30]:
            name     = t.get("name",       "?")
            version  = t.get("version",    "")
            category = t.get("category",   "")
            conf     = t.get("confidence", "")
            evidence = t.get("evidence",   [])
            ver_str  = f" v{version}" if version else ""
            conf_str = f" [{conf}% confidence]" if conf else ""
            lines.append(f"  • {name}{ver_str} [{category}]{conf_str}")
            if evidence and isinstance(evidence, list):
                lines.append(f"      Evidence: {evidence[0]}")
        lines.append("")

    # Fallback: from endpoint tags
    elif st["tech_counter"]:
        lines.append("=" * 80)
        lines.append("  TECHNOLOGY STACK")
        lines.append("=" * 80)
        lines.append("")
        for tech, count in st["tech_counter"].most_common():
            lines.append(f"  • {tech} ({count} endpoints)")
        lines.append("")

    return lines


def _txt_validation(st: dict) -> list[str]:
    lines = []
    vd = st["validation_dist"]
    if not any(vd.values()):
        return lines

    lines.append("=" * 80)
    lines.append("  VALIDATION RESULTS")
    lines.append("=" * 80)
    lines.append("")

    for bucket in ("Confirmed", "Likely", "Needs Manual Review", "Rejected"):
        items = vd.get(bucket, [])
        if not items:
            continue
        lines.append(f"  {bucket} ({len(items)}):")
        for f in items[:10]:
            vuln  = f.get("type", "Unknown")
            url   = f.get("url",  "")[:60]
            conf  = f.get("confidence", "?")
            lines.append(f"    • [{conf}%] {vuln} — {url}")
        lines.append("")

    return lines


def _txt_statistics(
    endpoints:     list[dict],
    st:            dict,
    scan_metadata: dict,
) -> list[str]:
    lines = []
    lines.append("=" * 80)
    lines.append("  SCAN STATISTICS")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"  Total URLs         : {len(endpoints)}")
    lines.append(f"  Total Endpoints    : {st['as_summary'].get('total_endpoints', len(endpoints))}")
    lines.append(f"  Parameters Found   : {st['param_count']}")
    lines.append(f"  Total Findings     : {st['total_findings']}")
    lines.append(f"  Scan Duration      : {scan_metadata.get('duration', 'N/A')} seconds")
    if scan_metadata.get("requests"):
        lines.append(f"  Total Requests     : {scan_metadata['requests']}")
    if scan_metadata.get("avg_response_time"):
        lines.append(f"  Avg Response Time  : {scan_metadata['avg_response_time']} ms")

    lines.append("")
    lines.append("  Risk Distribution:")
    lines.append(f"    Critical  : {st['critical_count']}")
    lines.append(f"    High      : {st['high_count']}")
    lines.append(f"    Medium    : {st['medium_count']}")
    lines.append(f"    Low       : {st['low_count']}")
    lines.append("")

    if st["tech_counter"]:
        lines.append(f"  Technologies Detected : {len(st['tech_counter'])}")
    if scan_metadata.get("waf_detected"):
        lines.append(f"  WAF Detected          : {scan_metadata['waf_detected']}")
    lines.append("")

    return lines


# ===============================================
# TEXT REPORT (public)
# ===============================================

def generate_text_report(
    domain:         str,
    scan_metadata:  dict,
    endpoints:      list,
    findings:       list,
    risk:           dict,
    attack_surface: dict,
) -> str:
    """
    Generate a professional text report.

    Args:
        domain:            target domain
        scan_metadata:     dict with scan_date, duration, etc.
        endpoints:         list of endpoint dicts
        findings:          list of finding dicts
        risk:              dict from calculate_risk()
        attack_surface:    dict from map_attack_surface()

    Returns:
        filepath to saved report
    """
    _ensure_reports_dir()
    st = _compute_stats(findings, endpoints, risk, attack_surface, scan_metadata)

    lines: list[str] = []
    lines += _txt_header(domain, scan_metadata, st)
    lines += _txt_executive_summary(domain, st, scan_metadata)
    lines += _txt_findings(st)
    lines += _txt_technology(endpoints, st)
    lines += _txt_attack_surface(st)
    lines += _txt_validation(st)
    lines += _txt_statistics(endpoints, st, scan_metadata)

    # Recommendations
    lines.append("=" * 80)
    lines.append("  RECOMMENDATIONS")
    lines.append("=" * 80)
    lines.append("")
    for rec in _RECOMMENDATIONS:
        lines.append(f"  {rec}")
    lines.append("")

    # Endpoint summary
    if endpoints:
        lines.append("=" * 80)
        lines.append("  DISCOVERED ENDPOINTS (Top 50)")
        lines.append("=" * 80)
        lines.append("")
        for idx, ep in enumerate(endpoints[:50], 1):
            if isinstance(ep, dict):
                tags = ", ".join(ep.get("tags", []))
                url  = ep.get("url", "")
                lines.append(f"  [{tags}] {url}")
            else:
                lines.append(f"  {ep}")
        lines.append("")

    # Footer
    lines.append("=" * 80)
    lines.append("  Report generated by AI Bug Bounty Recon Platform v3.0")
    lines.append("  For security concerns, contact the target's security team.")
    lines.append("=" * 80)

    filepath = os.path.join("reports", f"{_safe_domain(domain)}_report.txt")
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[+] Text report saved: {filepath}")
    return filepath


# ===============================================
# JSON REPORT (public)
# ===============================================

def generate_json_report(
    domain:         str,
    scan_metadata:  dict,
    endpoints:      list,
    findings:       list,
    risk:           dict,
    attack_surface: dict,
) -> str:
    """
    Generate a full-fidelity JSON export for API integration.
    Expanded with scan_metadata, attack_surface detail, technology_details,
    validation_details, statistics, risk_summary, and chart_data.
    """
    _ensure_reports_dir()
    st = _compute_stats(findings, endpoints, risk, attack_surface, scan_metadata)

    # Enrich findings with validation bucket + vuln meta
    enriched_findings = []
    for f in st["sorted_findings"]:
        meta   = _get_vuln_meta(f)
        bucket = _validation_bucket(f)
        enriched_findings.append({
            **f,
            "validation_status": bucket,
            "cwe":    meta["cwe"],
            "owasp":  meta["owasp"],
            "capec":  meta["capec"],
            "business_impact": meta["impact"],
        })

    data: dict[str, Any] = {
        # Core — unchanged keys (backwards compat)
        "metadata": {
            "domain":           domain,
            "generated":        datetime.now().isoformat(),
            "duration_seconds": scan_metadata.get("duration"),
        },
        "summary":       risk.get("summary", {}),
        "findings":      findings,         # original, unmodified
        "endpoints":     endpoints,
        "attack_surface":attack_surface,

        # Extended — new keys only
        "scan_metadata": {
            **scan_metadata,
            "domain":    domain,
            "generated": datetime.now().isoformat(),
        },
        "risk_summary": {
            "overall_risk_level": st["overall_level"],
            "security_score":     st["security_score"],
            "top_risk_score":     st["top_risk_score"],
            "critical_count":     st["critical_count"],
            "high_count":         st["high_count"],
            "medium_count":       st["medium_count"],
            "low_count":          st["low_count"],
            "total_findings":     st["total_findings"],
        },
        "findings_enriched": enriched_findings,
        "attack_surface_detail": {
            **attack_surface,
            "subdomains_count":    len(st["subdomains"]),
            "alive_hosts_count":   len(st["alive_hosts"]),
            "js_files_count":      len(st["js_files"]),
            "secrets_count":       len(st["secrets"]),
            "directories_count":   len(st["directories"]),
            "interesting_count":   len(st["interesting"]),
        },
        "technology_details": st["tech_details"] or [
            {"name": tech, "count": cnt, "category": "detected"}
            for tech, cnt in st["tech_counter"].most_common()
        ],
        "validation_details": {
            bucket: [
                {"type": f.get("type"), "url": f.get("url"), "confidence": f.get("confidence")}
                for f in items
            ]
            for bucket, items in st["validation_dist"].items()
        },
        "statistics": {
            "total_urls":       len(endpoints),
            "total_endpoints":  st["as_summary"].get("total_endpoints", len(endpoints)),
            "parameters":       st["param_count"],
            "total_findings":   st["total_findings"],
            "technologies":     len(st["tech_counter"]),
            "scan_duration_s":  scan_metadata.get("duration"),
            "requests":         scan_metadata.get("requests"),
            "avg_response_ms":  scan_metadata.get("avg_response_time"),
            "waf_detected":     scan_metadata.get("waf_detected"),
        },
        "chart_data": st["chart_data"],
    }

    filepath = os.path.join("reports", f"{_safe_domain(domain)}_report.json")
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)

    print(f"[+] JSON report saved: {filepath}")
    return filepath


# ===============================================
# MARKDOWN REPORT (public)
# ===============================================

def generate_markdown_report(
    domain:         str,
    scan_metadata:  dict,
    endpoints:      list,
    findings:       list,
    risk:           dict,
    attack_surface: dict,
) -> str:
    """
    Generate a Markdown report for GitHub / GitLab / Confluence.
    Includes proper headings, tables, code blocks, and collapsible evidence.
    """
    _ensure_reports_dir()
    st = _compute_stats(findings, endpoints, risk, attack_surface, scan_metadata)

    lines: list[str] = []

    # ── Header ─────────────────────────────────────────────────────────────
    lines += [
        f"# 🔐 Security Assessment Report: `{domain}`",
        "",
        f"> **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> **Duration:** {scan_metadata.get('duration', 'N/A')} seconds  ",
        f"> **Risk Level:** **{st['overall_level']}**  ",
        f"> **Security Score:** {st['security_score']}/100",
        "",
        "---",
        "",
    ]

    # ── Table of Contents ──────────────────────────────────────────────────
    lines += [
        "## 📋 Table of Contents",
        "",
        "1. [Executive Summary](#executive-summary)",
        "2. [Findings](#findings)",
        "3. [Technology Stack](#technology-stack)",
        "4. [Attack Surface](#attack-surface)",
        "5. [Validation Results](#validation-results)",
        "6. [Statistics](#statistics)",
        "7. [Recommendations](#recommendations)",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ──────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        "### Risk Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Overall Risk Level | **{st['overall_level']}** |",
        f"| Security Score | {st['security_score']}/100 |",
        f"| Top Finding Score | {st['top_risk_score']} |",
        f"| 🔴 Critical | {st['critical_count']} |",
        f"| 🟠 High | {st['high_count']} |",
        f"| 🟡 Medium | {st['medium_count']} |",
        f"| 🟢 Low | {st['low_count']} |",
        f"| **Total** | **{st['total_findings']}** |",
        "",
    ]

    # Highest risk findings table
    top5 = st["sorted_findings"][:5]
    if top5:
        lines += [
            "### Highest Risk Findings",
            "",
            "| # | Type | Severity | CVSS | URL |",
            "|---|------|----------|------|-----|",
        ]
        for i, f in enumerate(top5, 1):
            sev  = f.get("severity", "?")
            cvss = f.get("cvss", "N/A")
            t    = f.get("type",    "Unknown")
            url  = f.get("url",    "")[:70]
            lines.append(f"| {i} | {t} | {sev} | {cvss} | `{url}` |")
        lines.append("")

    # Validation summary table
    vd = st["validation_dist"]
    if any(vd.values()):
        lines += [
            "### Validation Summary",
            "",
            "| Status | Count |",
            "|--------|-------|",
        ]
        for bucket in ("Confirmed", "Likely", "Needs Manual Review", "Rejected"):
            cnt = len(vd.get(bucket, []))
            lines.append(f"| {bucket} | {cnt} |")
        lines += ["", "---", ""]

    # ── Findings ───────────────────────────────────────────────────────────
    if st["sorted_findings"]:
        lines += ["## Findings", ""]

        sev_order = _SEVERITY_ORDER
        for idx, finding in enumerate(st["sorted_findings"][:100], 1):
            vuln_type   = finding.get("type",        "Unknown")
            url         = finding.get("url",         "")
            severity    = finding.get("severity",    "Low")
            cvss        = finding.get("cvss",        "N/A")
            confidence  = finding.get("confidence",  "N/A")
            param       = finding.get("param",       "")
            payload     = finding.get("payload",     "")
            evidence    = finding.get("evidence",    "")
            remediation = finding.get("remediation", "")
            poc         = finding.get("poc",         "")
            tech_ctx    = finding.get("technology",  finding.get("tech_context", ""))
            meta        = _get_vuln_meta(finding)
            val_status  = _validation_bucket(finding)

            lines += [
                f"### [{idx}] {vuln_type} — {severity}",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| **Severity** | {severity} |",
                f"| **CVSS** | {cvss} |",
                f"| **Confidence** | {confidence}% |",
                f"| **Validation** | {val_status} |",
                f"| **CWE** | {meta['cwe']} |",
                f"| **OWASP** | {meta['owasp']} |",
                f"| **CAPEC** | {meta['capec']} |",
                f"| **URL** | `{url}` |",
            ]
            if param:
                lines.append(f"| **Parameter** | `{param}` |")
            if payload:
                lines.append(f"| **Payload** | `{payload[:80]}` |")
            if tech_ctx:
                lines.append(f"| **Tech Context** | {tech_ctx} |")
            lines.append(f"| **Business Impact** | {meta['impact']} |")
            lines.append("")

            if evidence:
                lines += [
                    "<details>",
                    "<summary>📎 Evidence</summary>",
                    "",
                    f"```\n{evidence}\n```",
                    "",
                    "</details>",
                    "",
                ]

            if remediation:
                lines += [
                    "**Remediation:**",
                    "",
                    f"```\n{remediation}\n```",
                    "",
                ]

            refs = finding.get("references", [])
            if refs:
                lines.append("**References:**")
                for ref in refs[:3]:
                    lines.append(f"- {ref}")
                lines.append("")

            if poc:
                lines += [
                    "**Proof of Concept:**",
                    "",
                    f"```\n{poc}\n```",
                    "",
                ]

            lines.append("---")
            lines.append("")

    # ── Technology Stack ───────────────────────────────────────────────────
    lines += ["## Technology Stack", ""]

    if st["tech_details"]:
        lines += [
            "| Technology | Version | Category | Confidence | Evidence |",
            "|------------|---------|----------|------------|---------|",
        ]
        for t in st["tech_details"][:25]:
            name  = t.get("name",       "?")
            ver   = t.get("version",    "—")
            cat   = t.get("category",   "—")
            conf  = t.get("confidence", "—")
            evid  = (t.get("evidence") or ["—"])[0][:60] if t.get("evidence") else "—"
            lines.append(f"| {name} | {ver} | {cat} | {conf}% | {evid} |")
        lines.append("")
    elif st["tech_counter"]:
        lines += [
            "| Technology | Endpoints |",
            "|------------|-----------|",
        ]
        for tech, cnt in st["tech_counter"].most_common(20):
            lines.append(f"| {tech} | {cnt} |")
        lines.append("")

    lines += ["---", ""]

    # ── Attack Surface ─────────────────────────────────────────────────────
    lines += ["## Attack Surface", ""]
    as_s = st["as_summary"]
    if as_s:
        lines += [
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains | {len(st['subdomains'])} |",
            f"| Alive Hosts | {len(st['alive_hosts'])} |",
            f"| Endpoints | {as_s.get('total_endpoints', 0)} |",
            f"| High-Value Targets | {as_s.get('high_value', 0)} |",
            f"| Attack Chains | {as_s.get('attack_chains', 0)} |",
            f"| JavaScript Files | {len(st['js_files'])} |",
            f"| Secrets Found | {len(st['secrets'])} |",
            f"| Directories | {len(st['directories'])} |",
            "",
        ]

    if st["hvt"]:
        lines += ["### High-Value Targets", "", "| Score | URL |", "|-------|-----|"]
        for t in st["hvt"][:8]:
            lines.append(f"| {t.get('score',0)} | `{t.get('url','')[:70]}` |")
        lines.append("")

    if st["chains"]:
        lines += ["### Attack Chains", ""]
        for i, chain in enumerate(st["chains"][:5], 1):
            lines += [
                f"#### Chain {i} — Score: {chain.get('chain_score','N/A')}",
                "",
                f"**Description:** {chain.get('description','')}",
                "",
                f"```",
                f"Entry  → {chain.get('entry','')}",
            ]
            if chain.get("pivot"):
                lines.append(f"Pivot  → {chain['pivot']}")
            lines += [
                f"Target → {chain.get('target','')}",
                "```",
                "",
            ]

    if st["secrets"]:
        lines += [
            "<details>",
            "<summary>🔑 Secrets Found</summary>",
            "",
        ]
        for sec in st["secrets"][:10]:
            if isinstance(sec, dict):
                lines.append(f"- `[{sec.get('type','?')}]` {sec.get('url','')}")
            else:
                lines.append(f"- {sec}")
        lines += ["", "</details>", ""]

    lines += ["---", ""]

    # ── Validation Results ─────────────────────────────────────────────────
    lines += ["## Validation Results", ""]
    for bucket in ("Confirmed", "Likely", "Needs Manual Review", "Rejected"):
        items = vd.get(bucket, [])
        if not items:
            continue
        lines += [f"### {bucket} ({len(items)})", ""]
        if items:
            lines += ["| Type | URL | Confidence |", "|------|-----|------------|"]
            for f in items[:15]:
                lines.append(f"| {f.get('type','?')} | `{f.get('url','')[:60]}` | {f.get('confidence','?')}% |")
        lines.append("")

    lines += ["---", ""]

    # ── Statistics ─────────────────────────────────────────────────────────
    lines += [
        "## Statistics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total URLs | {len(endpoints)} |",
        f"| Total Endpoints | {as_s.get('total_endpoints', len(endpoints))} |",
        f"| Parameters Found | {st['param_count']} |",
        f"| Total Findings | {st['total_findings']} |",
        f"| Technologies Detected | {len(st['tech_counter'])} |",
        f"| Scan Duration | {scan_metadata.get('duration','N/A')} seconds |",
    ]
    if scan_metadata.get("requests"):
        lines.append(f"| Total Requests | {scan_metadata['requests']} |")
    if scan_metadata.get("avg_response_time"):
        lines.append(f"| Avg Response Time | {scan_metadata['avg_response_time']} ms |")
    lines += ["", "---", ""]

    # ── Recommendations ────────────────────────────────────────────────────
    lines += ["## Recommendations", ""]
    for rec in _RECOMMENDATIONS:
        lines.append(f"- {rec.lstrip('0123456789. ')}")
    lines += ["", "---", ""]

    # ── Endpoints ──────────────────────────────────────────────────────────
    if endpoints:
        lines += [
            "<details>",
            "<summary>📡 Discovered Endpoints (Top 50)</summary>",
            "",
            "| Tags | URL |",
            "|------|-----|",
        ]
        for ep in endpoints[:50]:
            if isinstance(ep, dict):
                tags = ", ".join(ep.get("tags", []))
                url  = ep.get("url", "")
                lines.append(f"| {tags} | `{url}` |")
            else:
                lines.append(f"|  | `{ep}` |")
        lines += ["", "</details>", ""]

    # ── Footer ─────────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "*Report generated by AI Bug Bounty Recon Platform v3.0*",
        "",
    ]

    filepath = os.path.join("reports", f"{_safe_domain(domain)}_report.md")
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[+] Markdown report saved: {filepath}")
    return filepath


# ===============================================
# LEGACY SHIM (backwards compatibility)
# ===============================================

def generate_report(domain, alive_hosts, endpoints, findings, risk):
    """
    Legacy function — calls text generator for backwards compatibility.
    Existing callers continue to work without modification.
    """
    return generate_text_report(
        domain,
        scan_metadata={"duration": None},
        endpoints=endpoints,
        findings=findings if isinstance(findings, list) else [],
        risk=risk,
        attack_surface={},
    )


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_domain   = "example.com"
    test_metadata = {
        "duration": 42,
        "requests": 1240,
        "avg_response_time": 180,
        "waf_detected": "Cloudflare",
        "technologies": [
            {"name": "nginx",     "version": "1.24", "category": "Web Server", "confidence": 90, "evidence": ["header:server=nginx/1.24"]},
            {"name": "React",     "version": "",     "category": "Frontend",   "confidence": 80, "evidence": ["js_global:window.__REACT_DEVTOOLS"]},
            {"name": "Django",    "version": "",     "category": "Backend",    "confidence": 75, "evidence": ["cookie:csrftoken"]},
            {"name": "Cloudflare","version": "",     "category": "CDN",        "confidence": 95, "evidence": ["header:cf-ray"]},
        ],
    }
    test_endpoints = [
        {"url": "https://example.com/api/v2/users?id=1",   "tags": ["api", "user_data"], "params": ["id"]},
        {"url": "https://example.com/admin/dashboard",     "tags": ["admin"]},
        {"url": "https://example.com/login",               "tags": ["auth"]},
    ]
    test_findings = [
        {
            "type": "SQL Injection",
            "url": "https://example.com/api/v2/users?id=1",
            "param": "id",
            "payload": "' OR '1'='1' --",
            "severity": "Critical",
            "cvss": 9.4,
            "confidence": 90,
            "validated": True,
            "evidence": "SQL syntax error: You have an error in your SQL syntax",
            "remediation": "Use parameterized queries instead of concatenating user input.",
            "poc": "https://example.com/api/v2/users?id=1%27+OR+%271%27%3D%271",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        },
        {
            "type": "Reflected XSS",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "severity": "Medium",
            "cvss": 5.6,
            "confidence": 75,
            "evidence": "Payload reflected verbatim in HTML response",
            "remediation": "HTML-encode all user-controlled output.",
            "poc": "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C/script%3E",
        },
    ]
    test_risk = {
        "critical": ["https://example.com/api/v2/users?id=1"],
        "high": [],
        "medium": ["https://example.com/search?q=test"],
        "low": [],
        "summary": {"overall_risk_level": "CRITICAL", "security_score": 65, "top_risk_score": 94.0},
    }
    test_attack_surface = {
        "summary":      {"total_endpoints": 3, "high_value": 1, "attack_chains": 2, "choke_points": 0},
        "subdomains":   ["api.example.com", "admin.example.com"],
        "alive_hosts":  [{"url": "https://example.com"}, {"url": "https://api.example.com"}],
        "interesting_urls": ["https://example.com/admin/config"],
        "js_files":     ["https://example.com/static/app.js"],
        "secrets":      [{"type": "AWS_KEY", "url": "https://example.com/static/app.js"}],
        "directories":  ["/admin/", "/api/"],
        "high_value_targets": [{"score": 85, "url": "https://example.com/admin/dashboard"}],
        "chains": [{
            "chain_score": 87.5,
            "description": "Compromise login → pivot through API → reach admin",
            "entry":  "https://example.com/login",
            "pivot":  "https://example.com/api/v2/users?id=1",
            "target": "https://example.com/admin/dashboard",
        }],
    }

    print("[+] Generating test reports...\n")
    txt_path  = generate_text_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)
    json_path = generate_json_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)
    md_path   = generate_markdown_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)

    print(f"\n[+] All reports generated")
    print(f"    Text     : {txt_path}")
    print(f"    JSON     : {json_path}")
    print(f"    Markdown : {md_path}")

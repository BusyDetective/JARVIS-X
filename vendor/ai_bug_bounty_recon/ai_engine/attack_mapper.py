"""
Attack Surface Mapper v2.0

Replaces naive nested-loop chain generation with scored, logical
attack path mapping based on real pentest methodology.

Key improvements:
- Endpoint scoring based on multiple factors
- Logical attack chains (not every permutation)
- Kill chain methodology (Recon → Initial Access → Privilege Escalation → Impact)
- Choke point identification
- Attack surface summary for PDF reports
"""

from urllib.parse import urlparse


# =========================
# ENDPOINT CATEGORY RULES
# =========================

CATEGORY_RULES = {
    "authentication": {
        "keywords": ["login", "auth", "signin", "signup", "oauth", "sso",
                     "saml", "token", "register", "forgot", "reset", "verify"],
        "base_score": 75,
        "kill_chain_phase": "initial_access",
    },
    "admin": {
        "keywords": ["admin", "dashboard", "manage", "management", "console",
                     "superuser", "root", "control", "panel", "cms", "staff"],
        "base_score": 90,
        "kill_chain_phase": "privilege_escalation",
    },
    "api": {
        "keywords": ["/api/", "/v1/", "/v2/", "/v3/", "graphql", "rest",
                     "/rpc/", "endpoint", "swagger", "openapi"],
        "base_score": 70,
        "kill_chain_phase": "initial_access",
    },
    "upload": {
        "keywords": ["upload", "file", "avatar", "import", "attachment",
                     "media", "document", "image", "asset"],
        "base_score": 80,
        "kill_chain_phase": "execution",
    },
    "payment": {
        "keywords": ["payment", "billing", "checkout", "stripe", "paypal",
                     "invoice", "subscription", "purchase", "order", "cart"],
        "base_score": 85,
        "kill_chain_phase": "impact",
    },
    "user_data": {
        "keywords": ["user", "account", "profile", "settings", "preference",
                     "personal", "private", "data", "export", "download"],
        "base_score": 65,
        "kill_chain_phase": "exfiltration",
    },
    "internal": {
        "keywords": ["internal", "debug", "dev", "staging", "test", "beta",
                     "preview", "backdoor", "secret", "hidden", "temp"],
        "base_score": 85,
        "kill_chain_phase": "discovery",
    },
    "search": {
        "keywords": ["search", "query", "find", "filter", "lookup"],
        "base_score": 50,
        "kill_chain_phase": "discovery",
    },
}

# Kill chain phase ordering (lower = earlier in attack)
KILL_CHAIN_ORDER = {
    "reconnaissance": 1,
    "discovery":      2,
    "initial_access": 3,
    "execution":      4,
    "privilege_escalation": 5,
    "exfiltration":   6,
    "impact":         7,
}


# =========================
# ENDPOINT SCORING
# =========================

def _score_endpoint(ep: dict) -> dict:
    """
    Score an endpoint based on multiple factors.
    Returns enriched endpoint dict with score and metadata.
    """
    url      = ep.get("url", "")
    tags     = ep.get("tags", [])
    url_low  = url.lower()
    parsed   = urlparse(url)

    score        = 0
    categories   = []
    kill_phases  = []

    # --- Category matching ---
    for cat_name, cat_info in CATEGORY_RULES.items():
        for keyword in cat_info["keywords"]:
            if keyword in url_low:
                if cat_name not in categories:
                    categories.append(cat_name)
                    score = max(score, cat_info["base_score"])
                    kill_phases.append(cat_info["kill_chain_phase"])
                break

    # --- Bonus scoring ---

    # Has parameters = more attack surface
    if "?" in url and "=" in url:
        score += 8

    # API versioning = active maintained endpoint
    import re
    if re.search(r"/(v\d+)/", url_low):
        score += 5

    # Path depth = more specific/interesting
    path_depth = len([p for p in parsed.path.split("/") if p])
    if path_depth >= 3:
        score += 5

    # Sensitive parameter names
    sensitive_params = ["id", "user", "admin", "token", "key", "secret",
                        "password", "redirect", "file", "path", "cmd"]
    if any(p in url_low for p in sensitive_params):
        score += 10

    # Multiple categories = higher value target
    if len(categories) >= 2:
        score += 15

    # Tags from classifier (if available)
    high_value_tags = {"auth", "admin", "api", "upload", "payment"}
    tag_set = set(t.lower() for t in tags)
    if tag_set & high_value_tags:
        score += 10

    score = min(score, 100)

    # Primary kill chain phase
    primary_phase = "discovery"
    if kill_phases:
        # Use the latest phase (most impactful)
        primary_phase = max(kill_phases, key=lambda p: KILL_CHAIN_ORDER.get(p, 0))

    return {
        **ep,
        "attack_score":  score,
        "categories":    categories,
        "kill_phase":    primary_phase,
        "path":          parsed.path,
        "has_params":    "?" in url and "=" in url,
    }


# =========================
# ATTACK CHAIN LOGIC
# =========================

def _build_attack_chains(scored_endpoints: list) -> list:
    """
    Build realistic attack chains following kill chain methodology.

    A chain is: Entry Point → Pivot → Target
    - Entry: authentication/discovery endpoints (initial foothold)
    - Pivot: API/internal endpoints (lateral movement)
    - Target: admin/payment/data endpoints (high impact)

    Chains are scored and ranked — not every permutation.
    """
    chains = []

    # Bucket endpoints by role
    entry_points  = []
    pivot_points  = []
    target_points = []

    for ep in scored_endpoints:
        phase = ep.get("kill_phase", "discovery")
        score = ep.get("attack_score", 0)

        if score < 30:
            continue  # Skip low-value endpoints

        if phase in ("initial_access", "discovery"):
            entry_points.append(ep)
        elif phase in ("execution", "privilege_escalation"):
            pivot_points.append(ep)
        elif phase in ("exfiltration", "impact"):
            target_points.append(ep)
        else:
            entry_points.append(ep)

    # Sort each bucket by score descending
    entry_points.sort(key=lambda x: x["attack_score"], reverse=True)
    pivot_points.sort(key=lambda x: x["attack_score"], reverse=True)
    target_points.sort(key=lambda x: x["attack_score"], reverse=True)

    # Limit to top candidates to avoid combinatorial explosion
    top_entries  = entry_points[:6]
    top_pivots   = pivot_points[:6]
    top_targets  = target_points[:6]

    # --- Build 3-step chains (entry → pivot → target) ---
    for entry in top_entries:
        for target in top_targets:

            # Skip if same URL
            if entry["url"] == target["url"]:
                continue

            # Compute chain score
            chain_score = (
                entry["attack_score"] * 0.3 +
                target["attack_score"] * 0.5
            )

            # Find best pivot (or go direct if none)
            best_pivot = None
            best_pivot_score = 0

            for pivot in top_pivots:
                if pivot["url"] in (entry["url"], target["url"]):
                    continue
                if pivot["attack_score"] > best_pivot_score:
                    best_pivot      = pivot
                    best_pivot_score = pivot["attack_score"]

            if best_pivot:
                chain_score += best_pivot["attack_score"] * 0.2

            chains.append({
                "entry":        entry["url"],
                "entry_phase":  entry["kill_phase"],
                "entry_score":  entry["attack_score"],
                "pivot":        best_pivot["url"] if best_pivot else None,
                "pivot_phase":  best_pivot["kill_phase"] if best_pivot else None,
                "target":       target["url"],
                "target_phase": target["kill_phase"],
                "target_score": target["attack_score"],
                "chain_score":  round(chain_score, 1),
                "description":  _describe_chain(entry, best_pivot, target),
            })

    # --- Also add direct 2-step chains for high-value direct attacks ---
    for entry in top_entries[:3]:
        for target in top_targets[:3]:
            if entry["url"] == target["url"]:
                continue

            chain_score = entry["attack_score"] * 0.4 + target["attack_score"] * 0.6

            # Check if this pair already has a 3-step chain
            already_exists = any(
                c["entry"] == entry["url"] and c["target"] == target["url"]
                for c in chains
            )
            if not already_exists:
                chains.append({
                    "entry":        entry["url"],
                    "entry_phase":  entry["kill_phase"],
                    "entry_score":  entry["attack_score"],
                    "pivot":        None,
                    "pivot_phase":  None,
                    "target":       target["url"],
                    "target_phase": target["kill_phase"],
                    "target_score": target["attack_score"],
                    "chain_score":  round(chain_score, 1),
                    "description":  _describe_chain(entry, None, target),
                })

    # Sort by chain score and deduplicate
    chains.sort(key=lambda x: x["chain_score"], reverse=True)

    # Deduplicate by (entry, target) pair
    seen = set()
    unique_chains = []
    for chain in chains:
        key = (chain["entry"], chain["target"])
        if key not in seen:
            seen.add(key)
            unique_chains.append(chain)

    return unique_chains[:20]  # Top 20 chains maximum


def _describe_chain(entry: dict, pivot: dict | None, target: dict) -> str:
    """Generate a human-readable description of an attack chain."""
    entry_cats  = entry.get("categories", ["endpoint"])
    target_cats = target.get("categories", ["endpoint"])

    entry_label  = entry_cats[0] if entry_cats else "endpoint"
    target_label = target_cats[0] if target_cats else "endpoint"

    if pivot:
        pivot_cats  = pivot.get("categories", ["api"])
        pivot_label = pivot_cats[0] if pivot_cats else "api"
        return (
            f"Compromise {entry_label} endpoint → "
            f"pivot through {pivot_label} → "
            f"reach {target_label} target"
        )
    else:
        return (
            f"Direct attack: {entry_label} endpoint → "
            f"{target_label} target"
        )


# =========================
# CHOKE POINT DETECTION
# =========================

def _find_choke_points(scored_endpoints: list) -> list:
    """
    Identify choke points — endpoints that appear in multiple
    attack chains and are therefore highest priority to fix.
    """
    # Score by how many categories an endpoint spans
    choke_points = []

    for ep in scored_endpoints:
        if ep["attack_score"] >= 70 and len(ep.get("categories", [])) >= 2:
            choke_points.append({
                "url":        ep["url"],
                "score":      ep["attack_score"],
                "categories": ep["categories"],
                "reason":     f"Spans {len(ep['categories'])} attack categories: "
                              f"{', '.join(ep['categories'])}",
            })

    choke_points.sort(key=lambda x: x["score"], reverse=True)
    return choke_points[:10]


# =========================
# MAIN PUBLIC FUNCTION
# =========================

def map_attack_surface(endpoints: list) -> dict:
    """
    Map the complete attack surface from a list of endpoints.

    Args:
        endpoints: list of dicts with 'url' and optional 'tags' keys

    Returns:
        {
            "categories":         dict of category → endpoint lists,
            "scored_endpoints":   all endpoints with scores,
            "high_value_targets": top scoring endpoints,
            "chains":             ranked attack chains,
            "choke_points":       endpoints appearing in multiple chains,
            "kill_chain_map":     endpoints grouped by kill chain phase,
            "summary":            attack surface summary dict,
        }
    """
    print("[+] Mapping attack surface...")

    if not endpoints:
        return {
            "categories":        {},
            "scored_endpoints":  [],
            "high_value_targets": [],
            "chains":            [],
            "choke_points":      [],
            "kill_chain_map":    {},
            "summary":           {"total": 0, "high_value": 0, "chains": 0},
        }

    # --- Score all endpoints ---
    scored = [_score_endpoint(ep) for ep in endpoints]
    scored.sort(key=lambda x: x["attack_score"], reverse=True)

    # --- Categorize ---
    categories = {cat: [] for cat in CATEGORY_RULES}
    kill_chain_map = {phase: [] for phase in KILL_CHAIN_ORDER}

    for ep in scored:
        for cat in ep.get("categories", []):
            if cat in categories:
                categories[cat].append(ep)

        phase = ep.get("kill_phase", "discovery")
        if phase in kill_chain_map:
            kill_chain_map[phase].append(ep)

    # --- High value targets (score >= 70) ---
    high_value_targets = [
        {
            "url":        ep["url"],
            "score":      ep["attack_score"],
            "categories": ep["categories"],
            "kill_phase": ep["kill_phase"],
        }
        for ep in scored if ep["attack_score"] >= 70
    ]

    # --- Build attack chains ---
    chains = _build_attack_chains(scored)

    # --- Find choke points ---
    choke_points = _find_choke_points(scored)

    # --- Summary ---
    summary = {
        "total_endpoints":    len(scored),
        "high_value":         len(high_value_targets),
        "attack_chains":      len(chains),
        "choke_points":       len(choke_points),
        "top_score":          scored[0]["attack_score"] if scored else 0,
        "categories_found":   [c for c, eps in categories.items() if eps],
        "kill_phases_covered": [p for p, eps in kill_chain_map.items() if eps],
    }

    print(f"[+] Attack surface mapped:")
    print(f"    Endpoints scored  : {len(scored)}")
    print(f"    High value targets: {len(high_value_targets)}")
    print(f"    Attack chains     : {len(chains)}")
    print(f"    Choke points      : {len(choke_points)}")

    if high_value_targets:
        print(f"\n    Top 3 High Value Targets:")
        for hvt in high_value_targets[:3]:
            print(f"      [{hvt['score']:>3}] {hvt['url'][:70]}")

    if chains:
        print(f"\n    Top 3 Attack Chains:")
        for chain in chains[:3]:
            print(f"      [{chain['chain_score']:>5.1f}] {chain['description']}")
            print(f"              Entry  → {chain['entry'][:60]}")
            if chain["pivot"]:
                print(f"              Pivot  → {chain['pivot'][:60]}")
            print(f"              Target → {chain['target'][:60]}")

    return {
        "categories":         categories,
        "scored_endpoints":   scored,
        "high_value_targets": high_value_targets,
        "chains":             chains,
        "choke_points":       choke_points,
        "kill_chain_map":     kill_chain_map,
        "summary":            summary,
    }


# =========================
# QUICK TEST
# =========================
if __name__ == "__main__":

    test_endpoints = [
        {"url": "https://example.com/login", "tags": ["auth"]},
        {"url": "https://example.com/auth/oauth/callback?code=abc", "tags": ["auth"]},
        {"url": "https://example.com/api/v2/users?id=1", "tags": ["api"]},
        {"url": "https://example.com/api/v2/admin/settings", "tags": ["api", "admin"]},
        {"url": "https://example.com/admin/dashboard", "tags": ["admin"]},
        {"url": "https://example.com/admin/users/delete?id=5", "tags": ["admin"]},
        {"url": "https://example.com/upload/avatar", "tags": ["upload"]},
        {"url": "https://example.com/payment/checkout?plan=pro", "tags": ["payment"]},
        {"url": "https://example.com/user/profile/export", "tags": ["user_data"]},
        {"url": "https://example.com/debug/info", "tags": ["internal"]},
        {"url": "https://example.com/search?q=test", "tags": []},
        {"url": "https://example.com/about", "tags": []},
        {"url": "https://example.com/static/logo.png", "tags": []},
    ]

    result = map_attack_surface(test_endpoints)

    print("\n" + "="*60)
    print("FULL RESULTS")
    print("="*60)
    print(f"\nSummary: {result['summary']}")
    print(f"\nHigh Value Targets ({len(result['high_value_targets'])}):")
    for hvt in result["high_value_targets"]:
        print(f"  [{hvt['score']:>3}] [{hvt['kill_phase']:<22}] {hvt['url']}")

    print(f"\nChoke Points ({len(result['choke_points'])}):")
    for cp in result["choke_points"]:
        print(f"  [{cp['score']:>3}] {cp['url']}")
        print(f"         {cp['reason']}")

    print(f"\nTop 5 Attack Chains:")
    for i, chain in enumerate(result["chains"][:5], 1):
        print(f"\n  Chain {i} [Score: {chain['chain_score']}]")
        print(f"  Description: {chain['description']}")
        print(f"  Entry  → {chain['entry']}")
        if chain["pivot"]:
            print(f"  Pivot  → {chain['pivot']}")
        print(f"  Target → {chain['target']}")
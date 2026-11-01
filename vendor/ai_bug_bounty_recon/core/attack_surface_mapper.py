"""
Attack Surface Mapper — generates an interactive vis.js network graph
saved as static/attack_surface.html.

Node types:
  ⭐ star   — Root domain (blue)
  ●  dot    — Subdomain (green)
  ■  box    — Endpoint (amber = general, cyan = API)
  ◆  diamond— Auth/sensitive finding (red)
  ▲  triangle — Vulnerability finding (orange-red)
  ★  star   — High Value Target (pink, reasonable size)
"""

import json
import os
import re
from urllib.parse import urlparse


# ===============================================
# NODE BUILDERS
# ===============================================

def _truncate(text, max_len=40):
    """Truncate long labels for display."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _is_api_endpoint(url):
    """Return True if URL looks like an API endpoint."""
    return any(kw in url.lower() for kw in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"])


def _is_auth_endpoint(url):
    """Return True if URL looks like an auth/sensitive endpoint."""
    return any(kw in url.lower() for kw in [
        "login", "auth", "oauth", "dashboard", "redirect",
        "callback", "admin", "password", "token", "connect/authorize",
        "account/login", "/error"
    ])


def _has_uuid(url):
    """Return True if URL contains a UUID."""
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return bool(re.search(uuid_pattern, url.lower()))


def _has_numeric_id(url):
    """Return True if URL path contains a numeric ID segment."""
    path = urlparse(url).path
    return bool(re.search(r'/\d{1,10}(?:/|$)', path))


def build_node(node_id, label, color, shape, size, title=None):
    return {
        "id":    node_id,
        "label": label,
        "title": title or node_id,
        "color": color,
        "shape": shape,
        "size":  size,
        "font":  {"color": "#c8d8e8"},
    }


def build_edge(from_id, to_id, color="#1a2d4a", width=1):
    return {
        "from":  from_id,
        "to":    to_id,
        "color": color,
        "width": width,
    }


# ===============================================
# GRAPH DATA BUILDER
# ===============================================

def build_graph(data):
    """
    Build vis.js nodes and edges from recon data dict.

    Args:
        data: dict with keys: domain, subdomains, endpoints, findings, attack_surface

    Returns:
        (nodes list, edges list)
    """
    domain     = data.get("domain", "target")
    subdomains = data.get("subdomains", [])
    endpoints  = data.get("endpoints", [])
    findings   = data.get("findings", [])
    attack     = data.get("attack_surface", {})

    nodes  = []
    edges  = []
    seen   = set()

    def add_node(node):
        if node["id"] not in seen:
            seen.add(node["id"])
            nodes.append(node)

    # ── Root domain ───────────────────────────────
    add_node(build_node(
        node_id = domain,
        label   = domain,
        color   = "#38bdf8",
        shape   = "star",
        size    = 40,
        title   = f"Root domain: {domain}"
    ))

    # ── Subdomains ────────────────────────────────
    for sub in subdomains[:30]:
        sub = sub.strip()
        if not sub:
            continue
        add_node(build_node(
            node_id = sub,
            label   = _truncate(sub, 30),
            color   = "#00ff88",
            shape   = "dot",
            size    = 18,
            title   = sub
        ))
        edges.append(build_edge(domain, sub, color="#1a2d4a"))

    # ── Endpoints ────────────────────────────────
    for ep in endpoints[:80]:
        url = ep["url"] if isinstance(ep, dict) else ep
        url = url.strip()
        if not url:
            continue

        # Determine which subdomain this endpoint belongs to
        parsed_host = urlparse(url).netloc
        parent = parsed_host if parsed_host in seen else domain

        # Color and shape by type
        if _is_auth_endpoint(url):
            color = "#ef4444"
            shape = "diamond"
            size  = 20
        elif _is_api_endpoint(url):
            color = "#06b6d4"
            shape = "box"
            size  = 16
        else:
            color = "#f59e0b"
            shape = "box"
            size  = 12

        path = urlparse(url).path
        label = _truncate(path or url, 28)

        add_node(build_node(
            node_id = url,
            label   = label,
            color   = color,
            shape   = shape,
            size    = size,
            title   = url
        ))
        edges.append(build_edge(parent, url, color="#22333a"))

    # ── Findings / vulnerabilities ────────────────
    for f in findings[:30]:
        if not isinstance(f, dict):
            continue

        f_url  = f.get("url", "")
        f_type = f.get("type", "Finding")
        f_sev  = f.get("severity", "Low")
        node_id = f"[{f_type}] {f_url[:60]}"

        color = {
            "Critical": "#a78bfa",
            "High":     "#ef4444",
            "Medium":   "#f59e0b",
            "Low":      "#00ff88",
        }.get(f_sev, "#f59e0b")

        add_node(build_node(
            node_id = node_id,
            label   = _truncate(f_type, 22),
            color   = color,
            shape   = "triangle",
            size    = 20,
            title   = f"{f_type} | {f_sev} | {f_url}"
        ))

        # Connect to the endpoint node if it exists
        if f_url in seen:
            edges.append(build_edge(f_url, node_id, color=color, width=2))
        else:
            edges.append(build_edge(domain, node_id, color=color, width=1))

    # ── High Value Targets ────────────────────────
    hvts = attack.get("high_value_targets", [])
    for hvt in hvts[:20]:
        hvt_url = hvt.get("url", "") if isinstance(hvt, dict) else str(hvt)
        hvt_score = hvt.get("score", 0) if isinstance(hvt, dict) else 0

        if not hvt_url:
            continue

        hvt_id = f"HVT:{hvt_url}"

        add_node(build_node(
            node_id = hvt_id,
            label   = "★ " + _truncate(urlparse(hvt_url).path or hvt_url, 24),
            color   = "#ff006e",
            shape   = "star",
            size    = 30,          # Was 150 — now reasonable
            title   = f"High Value Target (score={hvt_score})\n{hvt_url}"
        ))

        # Connect HVT to its endpoint node or domain
        parent_id = hvt_url if hvt_url in seen else domain
        edges.append(build_edge(parent_id, hvt_id, color="#ff006e", width=2))

    # ── IDOR candidates from findings ─────────────
    for ep in endpoints[:80]:
        url = ep["url"] if isinstance(ep, dict) else ep
        if (_has_uuid(url) or _has_numeric_id(url)) and url in seen:
            idor_id = f"[IDOR?] {url[:60]}"
            if idor_id not in seen:
                add_node(build_node(
                    node_id = idor_id,
                    label   = "IDOR?",
                    color   = "#ef4444",
                    shape   = "triangle",
                    size    = 18,
                    title   = f"Potential IDOR candidate:\n{url}"
                ))
                edges.append(build_edge(url, idor_id, color="#ef4444", width=1))

    return nodes, edges


# ===============================================
# HTML TEMPLATE
# ===============================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface — {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css"
          integrity="sha512-WgxfT5LWjfszlPHXRmBWHkV2eceiWTOBvrKCNbdgDYTHrT2AeLCGbF4sZlZw3UMN3WtL0tGUoIAKsu8mllg/XA=="
          crossorigin="anonymous" referrerpolicy="no-referrer"/>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js"
            integrity="sha512-LnvoEWDFrqGHlHmDD2101OrLcbsfkrzoSpvtSQtxK3RMnRV0eOkhhBN2dXHKRrUU8p2DGRTk35n4O8nWSVe1mQ=="
            crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <style>
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        :root {{
            --bg:      #080f1a;
            --surface: #0d1829;
            --border:  #1a2d4a;
            --green:   #00ff88;
            --blue:    #38bdf8;
            --red:     #ff4d6d;
            --amber:   #fbbf24;
            --text:    #c8d8e8;
            --muted:   #4a6080;
            --mono:    'JetBrains Mono', monospace;
        }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: var(--mono);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }}

        /* ── Nav ── */
        nav {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            flex-shrink: 0;
            z-index: 100;
        }}

        .nav-logo {{ font-size: 13px; color: var(--green); letter-spacing: 0.08em; }}
        .nav-logo span {{ color: var(--muted); }}
        .nav-title {{ font-size: 12px; color: var(--muted); }}

        .nav-links {{ display: flex; gap: 20px; }}
        .nav-links a {{
            font-size: 11px;
            color: var(--muted);
            text-decoration: none;
            letter-spacing: 0.05em;
            transition: color 0.2s;
        }}
        .nav-links a:hover {{ color: var(--green); }}

        /* ── Graph container ── */
        #graph-wrap {{
            flex: 1;
            position: relative;
            overflow: hidden;
        }}

        #network {{
            width: 100%;
            height: 100%;
            background: var(--bg);
        }}

        /* ── Legend ── */
        .legend {{
            position: absolute;
            top: 16px;
            right: 16px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 14px 16px;
            font-size: 11px;
            color: var(--text);
            z-index: 50;
            min-width: 160px;
        }}

        .legend-title {{
            font-size: 10px;
            color: var(--muted);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 11px;
        }}

        .legend-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }}

        /* ── Stats bar ── */
        .stats-bar {{
            position: absolute;
            bottom: 16px;
            left: 16px;
            display: flex;
            gap: 16px;
            z-index: 50;
        }}

        .stat-pill {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 6px 12px;
            font-size: 11px;
            color: var(--muted);
        }}

        .stat-pill span {{ color: var(--text); font-weight: 600; }}

        /* ── Loading bar ── */
        #loadingBar {{
            position: absolute;
            inset: 0;
            background: rgba(8,15,26,0.9);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 200;
            transition: opacity 0.5s;
        }}

        .loading-label {{
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 12px;
            letter-spacing: 0.1em;
        }}

        .loading-track {{
            width: 300px;
            height: 3px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
        }}

        .loading-fill {{
            height: 100%;
            background: var(--green);
            border-radius: 2px;
            width: 0%;
            transition: width 0.3s;
            box-shadow: 0 0 8px rgba(0,255,136,0.5);
        }}

        #loadingPct {{
            font-size: 11px;
            color: var(--muted);
            margin-top: 8px;
        }}

        /* ── vis.js config panel dark override ── */
        .vis-configuration-wrapper {{
            display: none !important;
        }}
    </style>
</head>
<body>

<nav>
    <div>
        <div class="nav-logo"><span>//</span> recon.ai</div>
        <div class="nav-title" style="margin-top:3px">Attack Surface — {domain}</div>
    </div>
    <div class="nav-links">
        <a href="javascript:history.back()">← back to results</a>
        <a href="/">new scan</a>
    </div>
</nav>

<div id="graph-wrap">
    <div id="network"></div>

    <!-- Legend -->
    <div class="legend">
        <div class="legend-title">Legend</div>
        <div class="legend-item"><div class="legend-dot" style="background:#38bdf8;border-radius:0;transform:rotate(45deg)"></div> Root Domain</div>
        <div class="legend-item"><div class="legend-dot" style="background:#00ff88"></div> Subdomain</div>
        <div class="legend-item"><div class="legend-dot" style="background:#06b6d4;border-radius:2px"></div> API Endpoint</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f59e0b;border-radius:2px"></div> Endpoint</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ef4444;transform:rotate(45deg);border-radius:0"></div> Auth / Sensitive</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ef4444;clip-path:polygon(50% 0%,100% 100%,0% 100%)"></div> Vulnerability</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ff006e"></div> High Value Target</div>
    </div>

    <!-- Stats bar -->
    <div class="stats-bar">
        <div class="stat-pill">Nodes <span id="nodeCount">—</span></div>
        <div class="stat-pill">Edges <span id="edgeCount">—</span></div>
        <div class="stat-pill">HVTs <span id="hvtCount" style="color:#ff006e">—</span></div>
    </div>

    <!-- Loading overlay -->
    <div id="loadingBar">
        <div class="loading-label">BUILDING ATTACK SURFACE GRAPH</div>
        <div class="loading-track">
            <div class="loading-fill" id="loadingFill"></div>
        </div>
        <div id="loadingPct">0%</div>
    </div>
</div>

<script>
    var nodes = new vis.DataSet({NODES_JSON});
    var edges = new vis.DataSet({EDGES_JSON});

    var container = document.getElementById("network");
    var data      = {{ nodes: nodes, edges: edges }};

    var options = {{
        nodes: {{
            borderWidth: 1,
            borderWidthSelected: 2,
        }},
        edges: {{
            smooth: {{ enabled: true, type: "dynamic" }},
            color:  {{ inherit: false }},
        }},
        interaction: {{
            dragNodes:        true,
            hideEdgesOnDrag:  true,
            tooltipDelay:     100,
            navigationButtons: false,
            keyboard: true,
        }},
        physics: {{
            barnesHut: {{
                gravitationalConstant: -8000,
                centralGravity:        0.3,
                springLength:          200,
                springConstant:        0.04,
                damping:               0.15,
                avoidOverlap:          0.1,
            }},
            stabilization: {{
                enabled:      true,
                iterations:   800,
                fit:          true,
                updateInterval: 30,
            }},
        }},
    }};

    var network = new vis.Network(container, data, options);

    // Update stats
    document.getElementById("nodeCount").textContent = nodes.length;
    document.getElementById("edgeCount").textContent = edges.length;
    document.getElementById("hvtCount").textContent  = nodes.get().filter(n => n.id.startsWith("HVT:")).length;

    // Loading bar
    network.on("stabilizationProgress", function(params) {{
        var pct = Math.round(params.iterations / params.total * 100);
        document.getElementById("loadingFill").style.width = pct + "%";
        document.getElementById("loadingPct").textContent  = pct + "%";
    }});

    network.once("stabilizationIterationsDone", function() {{
        document.getElementById("loadingFill").style.width = "100%";
        document.getElementById("loadingPct").textContent  = "100%";
        setTimeout(function() {{
            var bar = document.getElementById("loadingBar");
            bar.style.opacity = "0";
            setTimeout(function() {{ bar.style.display = "none"; }}, 500);
        }}, 300);
    }});

    // Click node to highlight neighbours
    network.on("click", function(params) {{
        if (params.nodes.length > 0) {{
            network.selectNodes(params.nodes);
        }}
    }});
</script>

</body>
</html>"""


# ===============================================
# MAIN GENERATOR
# ===============================================

def generate_attack_surface(data, output_path=None):
    """
    Generate the attack surface HTML file.

    Args:
        data: dict with domain, subdomains, endpoints, findings, attack_surface
        output_path: where to write the HTML (default: static/attack_surface.html)

    Returns:
        output_path string
    """
    if output_path is None:
        static_dir  = os.path.join(os.path.dirname(__file__), "..", "static")
        os.makedirs(static_dir, exist_ok=True)
        output_path = os.path.join(static_dir, "attack_surface.html")

    domain = data.get("domain", "target")
    nodes, edges = build_graph(data)

    nodes_json = json.dumps(nodes, ensure_ascii=False)
    edges_json = json.dumps(edges, ensure_ascii=False)

    html = HTML_TEMPLATE.format(
        domain     = domain,
        NODES_JSON = nodes_json,
        EDGES_JSON = edges_json,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Attack surface map saved: {output_path} ({len(nodes)} nodes, {len(edges)} edges)")
    return output_path


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_data = {
        "domain": "example.com",
        "subdomains": ["api.example.com", "app.example.com", "login.example.com"],
        "endpoints": [
            {"url": "https://api.example.com/v1/users?id=1",     "tags": ["API", "IDOR"]},
            {"url": "https://app.example.com/admin/dashboard",    "tags": ["ADMIN"]},
            {"url": "https://login.example.com/auth?next=/home",  "tags": ["AUTH"]},
            {"url": "https://api.example.com/graphql",            "tags": ["GRAPHQL"]},
        ],
        "findings": [
            {"type": "XSS",          "url": "https://api.example.com/v1/users?id=1",  "severity": "High"},
            {"type": "Open Redirect","url": "https://login.example.com/auth?next=/home","severity": "Medium"},
        ],
        "attack_surface": {
            "high_value_targets": [
                {"url": "https://app.example.com/admin/dashboard", "score": 85},
                {"url": "https://api.example.com/v1/users?id=1",   "score": 72},
            ],
            "chains": []
        }
    }

    path = generate_attack_surface(test_data, output_path="/tmp/test_attack_surface.html")
    print(f"Generated: {path}")
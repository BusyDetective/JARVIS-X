from flask import Flask, render_template, request, send_file, redirect, session, send_from_directory, jsonify
from functools import wraps
from datetime import datetime, timedelta
import sys
import os
import tempfile
import shutil

# Security: Set CLI_MODE before other imports
os.environ["CLI_MODE"] = "0"

import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors as rl_colors
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest
import threading
import uuid
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.recon_core import run_recon
from database import (
    init_db,
    save_scan,
    get_scans,
    get_scan_by_id,
    get_findings_for_scan,
    create_user,
    authenticate_user,
    get_conn,
)
from utils.logger import info as log_info, success as log_success, warning as log_warning, error as log_error

# ===============================================
# FOOTER HELPER (PDF GENERATION)
# ===============================================
def add_footer(canvas, doc):
    """Add footer to PDF pages."""
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.drawString(
        40,
        20,
        f"AI Bug Bounty Recon Tool | Confidential Security Report | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )
    canvas.restoreState()


# ===============================================
# FLASK APP INITIALIZATION
# ===============================================
app = Flask(__name__)

# Security: Secret key from environment, with secure fallback
app.secret_key = os.environ.get(
    "SECRET_KEY",
    os.urandom(32).hex()  # Generate random key if not provided
)

# Optional: strict session cookie for production
if not os.environ.get("DEBUG"):
    app.config.update(
        SESSION_COOKIE_SECURE=False,      # Only send over HTTPS
        SESSION_COOKIE_HTTPONLY=True,    # No JS access
        SESSION_COOKIE_SAMESITE='Lax'    # CSRF protection
    )

# Initialize database
init_db()



# ===============================================
# RATE LIMITING (Per User Per Hour)
# ===============================================
rate_limit_store = {}  # {user: [(timestamp, domain), ...]}

def is_rate_limited(username, max_scans_per_hour=10):
    """Check if user has exceeded scan limit for this hour."""
    now = datetime.now()
    hour_ago = now - timedelta(hours=1)

    if username not in rate_limit_store:
        rate_limit_store[username] = []

    # Prune old entries
    rate_limit_store[username] = [
        (ts, domain) for ts, domain in rate_limit_store[username]
        if ts > hour_ago
    ]

    return len(rate_limit_store[username]) >= max_scans_per_hour

def record_scan(username, domain):
    """Record scan attempt for rate limiting."""
    if username not in rate_limit_store:
        rate_limit_store[username] = []
    rate_limit_store[username].append((datetime.now(), domain))


def require_auth(f):
    """Decorator to require session authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# ===============================================
# TASK STATE MANAGEMENT (Database-Backed)
# ===============================================
def _init_task_tables():
    """Create scan_tasks and scan_logs tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_tasks (
                task_id    TEXT PRIMARY KEY,
                domain     TEXT NOT NULL,
                username   TEXT NOT NULL,
                scan_id    INTEGER,
                status     TEXT DEFAULT 'Queued',
                temp_dir   TEXT,
                error      TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id    TEXT NOT NULL,
                log_entry  TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_scan_logs_task_id
                ON scan_logs(task_id);
        """)

# Create task tables on startup
_init_task_tables()


def create_task(domain, username):
    """Create a new scan task in the database."""
    task_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO scan_tasks (task_id, domain, username, status, created_at, temp_dir)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            task_id,
            domain,
            username,
            "Queued",
            datetime.now().isoformat(),
            None,
        ))
    return task_id


def get_task(task_id):
    """Retrieve task state from database."""
    with get_conn() as conn:
        row = conn.execute("""
            SELECT task_id, domain, username, status, created_at, temp_dir, error
            FROM scan_tasks WHERE task_id = ?
        """, (task_id,)).fetchone()

    if row:
        return {
            "task_id":    row[0],
            "domain":     row[1],
            "username":   row[2],
            "status":     row[3],
            "created_at": row[4],
            "temp_dir":   row[5],
            "error":      row[6],
        }
    return None


def update_task(task_id, status=None, temp_dir=None, error=None):
    """Update task status in database."""
    updates = []
    params  = []

    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if temp_dir is not None:
        updates.append("temp_dir = ?")
        params.append(temp_dir)
    if error is not None:
        updates.append("error = ?")
        params.append(error)

    if updates:
        params.append(task_id)
        query = f"UPDATE scan_tasks SET {', '.join(updates)} WHERE task_id = ?"
        with get_conn() as conn:
            conn.execute(query, params)


def save_task_results(task_id, results):
    """Save scan results to database and link to task."""
    scan_id = save_scan(
        results.get("domain"),
        results.get("risk", {}),
        results.get("findings", [])
    )

    with get_conn() as conn:
        conn.execute("""
            UPDATE scan_tasks SET scan_id = ?, status = ? WHERE task_id = ?
        """, (scan_id, "Completed", task_id))


def get_task_logs(task_id):
    """Retrieve logs for a task from database."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT log_entry FROM scan_logs WHERE task_id = ? ORDER BY created_at ASC
        """, (task_id,)).fetchall()
    return [row[0] for row in rows]


def add_log(task_id, message):
    """Add log entry to database."""
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO scan_logs (task_id, log_entry, created_at)
            VALUES (?, ?, ?)
        """, (task_id, message, datetime.now().isoformat()))
    log_info(f"[{task_id[:8]}] {message}")


# ===============================================
# BACKGROUND SCAN FUNCTION
# ===============================================
def background_scan(task_id, domain, username):
    """Run recon scan in background thread."""
    try:
        # Create temp directory for this scan
        temp_dir = tempfile.mkdtemp(prefix=f"scan_{task_id[:8]}_")
        update_task(task_id, temp_dir=temp_dir)

        add_log(task_id, "[+] Scan started")
        update_task(task_id, status="Running")
        add_log(task_id, f"[+] Target: {domain}")

        # Run recon engine
        add_log(task_id, "[+] Executing reconnaissance engine...")
        results = run_recon(domain)
        results["domain"] = domain

        add_log(task_id, f"[+] Subdomains: {len(results.get('subdomains', []))}")
        add_log(task_id, f"[+] Endpoints: {len(results.get('endpoints', []))}")
        add_log(task_id, f"[+] Findings: {len(results.get('findings', []))}")

        # Generate risk chart
        add_log(task_id, "[+] Generating risk chart...")
        risk = results.get("risk", {})

        # Chart data
        labels = []
        sizes = []
        chart_colors = []

        if risk.get("critical"):
            labels.append("Critical")
            sizes.append(len(risk["critical"]))
            chart_colors.append("#7c3aed")

        if risk.get("high"):
            labels.append("High")
            sizes.append(len(risk["high"]))
            chart_colors.append("#ef4444")

        if risk.get("medium"):
            labels.append("Medium")
            sizes.append(len(risk["medium"]))
            chart_colors.append("#f59e0b")

        if risk.get("low"):
            labels.append("Low")
            sizes.append(len(risk["low"]))
            chart_colors.append("#22c55e")

        # Create chart if findings exist
        chart_path = None
        if sum(sizes) > 0:
            try:
                plt.figure(figsize=(6, 6))
                wedges, texts, autotexts = plt.pie(
                    sizes,
                    labels=labels,
                    colors=chart_colors,
                    autopct='%1.1f%%',
                    startangle=90,
                    textprops={'fontsize': 10}
                )

                plt.title('Risk Severity Distribution', fontsize=14, fontweight='bold')
                plt.axis('equal')

                chart_path = os.path.join(temp_dir, "risk_chart.png")
                plt.savefig(chart_path, dpi=100, bbox_inches='tight')
                plt.close()

                add_log(task_id, "[+] Risk chart generated")
            except Exception as e:
                add_log(task_id, f"[!] Chart generation failed: {str(e)}")
                chart_path = None

        # Generate PDF report
        add_log(task_id, "[+] Generating PDF report...")

        safe_domain = (
            domain
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(".", "_")
        )

        pdf_filename = f"{safe_domain}_report_{task_id[:8]}.pdf"
        pdf_path = os.path.join(temp_dir, pdf_filename)

        try:
            doc = SimpleDocTemplate(pdf_path)
            styles = getSampleStyleSheet()

            # Customize styles
            styles['Heading1'].textColor = rl_colors.HexColor("#2563eb")
            styles['Heading2'].textColor = rl_colors.HexColor("#1e40af")

            content = []

            # Title
            content.append(
                Paragraph(
                    "<b>AI Reconnaissance Security Assessment Report</b>",
                    styles['Title']
                )
            )
            content.append(Spacer(1, 20))

            # Metadata
            content.append(Paragraph(f"<b>Target:</b> {domain}", styles['Normal']))
            content.append(Paragraph(f"<b>Scan ID:</b> {task_id[:8]}", styles['Normal']))
            content.append(
                Paragraph(
                    f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    styles['Normal']
                )
            )
            content.append(Spacer(1, 20))

            # Executive Summary
            content.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
            content.append(
                Paragraph(
                    "This automated reconnaissance report identifies exposed endpoints, "
                    "authentication flows, APIs, sensitive URLs, and potential security "
                    "misconfigurations discovered during scanning.",
                    styles['Normal']
                )
            )

            # Statistics
            content.append(Spacer(1, 15))
            content.append(
                Paragraph(
                    f"""
                    <b>Total Subdomains:</b> {len(results.get('subdomains', []))}<br/>
                    <b>Total Endpoints:</b> {len(results.get('endpoints', []))}<br/>
                    <b>Total Findings:</b> {len(results.get('findings', []))}
                    """,
                    styles['Normal']
                )
            )

            # Overall Risk
            content.append(Spacer(1, 15))

            # ---------------------------------------------------------------
            # Read severity summary from risk_scoring — do NOT recompute.
            # risk_scoring.calculate_risk() is the single source of truth.
            # ---------------------------------------------------------------
            risk_summary   = risk.get("summary", {})
            critical_count = risk_summary.get("critical", len(risk.get("critical", [])))
            high_count     = risk_summary.get("high",     len(risk.get("high",     [])))
            medium_count   = risk_summary.get("medium",   len(risk.get("medium",   [])))
            low_count      = risk_summary.get("low",      len(risk.get("low",      [])))

            overall_level  = risk_summary.get("overall_risk_level", "LOW")
            security_score = risk_summary.get("security_score", 100)
            if isinstance(security_score, (int, float)):
                security_score = max(int(security_score), 0)

            _LEVEL_COLOR = {
                "CRITICAL": "#7c3aed",
                "HIGH":     "#ef4444",
                "MEDIUM":   "#f59e0b",
                "LOW":      "#22c55e",
            }
            level_color = _LEVEL_COLOR.get(overall_level, "#22c55e")

            content.append(
                Paragraph(
                    f'<font color="{level_color}"><b>Overall Risk Level:</b> {overall_level}</font>',
                    styles['Heading1']
                )
            )
            content.append(
                Paragraph(
                    f"<b>Security Score:</b> {security_score}/100",
                    styles['Normal']
                )
            )

            content.append(Spacer(1, 20))
            content.append(PageBreak())

            # Subdomains
            if results.get("subdomains"):
                content.append(Paragraph("<b>Discovered Subdomains</b>", styles['Heading2']))
                content.append(Spacer(1, 10))

                for subdomain in results.get("subdomains", [])[:50]:
                    content.append(Paragraph(subdomain, styles['Normal']))

                content.append(Spacer(1, 20))
                content.append(PageBreak())

            # Live Hosts
            if results.get("live_hosts"):
                content.append(Paragraph("<b>Live Hosts</b>", styles['Heading2']))
                content.append(Spacer(1, 10))

                for host in results.get("live_hosts", [])[:20]:
                    status_code = host.get('status', 'Unknown')
                    content.append(
                        Paragraph(f"[{status_code}] {host['url']}", styles['Normal'])
                    )

                content.append(Spacer(1, 20))
                content.append(PageBreak())

            # Technologies
            if results.get("technologies"):
                content.append(Paragraph("<b>Detected Technologies</b>", styles['Heading2']))
                content.append(Spacer(1, 10))

                for host, techs in list(results.get("technologies", {}).items())[:20]:
                    content.append(Paragraph(f"<b>{host}</b>", styles['Normal']))

                    if techs:
                        for tech in techs[:10]:
                            content.append(Paragraph(f"  • {tech}", styles['Normal']))
                    else:
                        content.append(Paragraph("  (Protected/Unknown)", styles['Normal']))

                    content.append(Spacer(1, 8))

                content.append(Spacer(1, 20))
                content.append(PageBreak())

            # Endpoints
            if results.get("endpoints"):
                content.append(Paragraph("<b>Discovered Endpoints</b>", styles['Heading2']))
                content.append(Spacer(1, 10))

                for endpoint in results.get("endpoints", [])[:50]:
                    if isinstance(endpoint, dict):
                        url = endpoint.get('url', '')[:120]
                        tags = ', '.join(endpoint.get('tags', [])[:5])
                        content.append(
                            Paragraph(f"[{tags}] {url}", styles['Normal'])
                        )

                content.append(Spacer(1, 20))
                content.append(PageBreak())

            # Findings
            if results.get("findings"):
                content.append(Paragraph("<b>Security Findings</b>", styles['Heading2']))
                content.append(Spacer(1, 10))

                for idx, finding in enumerate(results.get("findings", [])[:50], 1):
                    finding_type = finding.get('type', 'Unknown')
                    url = finding.get('url', '')[:100]
                    severity = finding.get('severity', 'Low')
                    cvss = finding.get('cvss', 'N/A')
                    confidence = finding.get('confidence', 'N/A')

                    content.append(
                        Paragraph(
                            f"""
                            <b>Finding {idx}: {finding_type}</b><br/>
                            <b>URL:</b> {url}<br/>
                            <b>Severity:</b> {severity} | <b>CVSS:</b> {cvss} | <b>Confidence:</b> {confidence}%
                            """,
                            styles['Normal']
                        )
                    )
                    content.append(Spacer(1, 12))

                content.append(Spacer(1, 20))
                content.append(PageBreak())

            # Risk Summary
            content.append(Paragraph("<b>Risk Summary</b>", styles['Heading1']))
            content.append(Spacer(1, 15))

            content.append(
                Paragraph(
                    f'<font color="#7c3aed"><b>Critical:</b> {critical_count}</font>',
                    styles['Normal']
                )
            )
            content.append(
                Paragraph(
                    f'<font color="#ef4444"><b>High:</b> {high_count}</font>',
                    styles['Normal']
                )
            )
            content.append(
                Paragraph(
                    f'<font color="#f59e0b"><b>Medium:</b> {medium_count}</font>',
                    styles['Normal']
                )
            )
            content.append(
                Paragraph(
                    f'<font color="#22c55e"><b>Low:</b> {low_count}</font>',
                    styles['Normal']
                )
            )

            # Chart
            if chart_path and os.path.exists(chart_path):
                content.append(Spacer(1, 30))
                content.append(Paragraph("<b>Risk Distribution</b>", styles['Heading2']))
                content.append(Spacer(1, 15))
                content.append(Image(chart_path, width=400, height=400))

            content.append(PageBreak())

            # Recommendations
            content.append(Paragraph("<b>Remediation Recommendations</b>", styles['Heading1']))
            content.append(Spacer(1, 15))

            recommendations = [
                "Restrict access to sensitive admin and internal endpoints.",
                "Validate and sanitize all user input to prevent injection attacks.",
                "Implement proper authentication and authorization checks.",
                "Monitor and log access to sensitive APIs and endpoints.",
                "Review and remove publicly accessible debug pages and files.",
                "Implement security headers (CSP, X-Frame-Options, etc.).",
                "Use HTTPS for all communications.",
                "Keep frameworks and dependencies up-to-date.",
            ]

            for rec in recommendations:
                content.append(Paragraph(f"• {rec}", styles['Normal']))
                content.append(Spacer(1, 8))

            # Build PDF
            doc.build(content, onFirstPage=add_footer, onLaterPages=add_footer)

            add_log(task_id, "[+] PDF report created")
            results["pdf_report"] = pdf_path

        except Exception as e:
            add_log(task_id, f"[!] PDF generation failed: {str(e)}")
            log_error(f"PDF generation error: {e}")

        # Save results to database
        add_log(task_id, "[+] Saving results to database...")
        save_task_results(task_id, results)

        # Save full results JSON to temp dir for /results page
        try:
            results_path = os.path.join(temp_dir, "results.json")
            # Exclude non-serializable keys
            serializable = {k: v for k, v in results.items() if k != "pdf_report"}
            with open(results_path, "w") as f:
                json.dump(serializable, f, default=str)
        except Exception as e:
            log_error(f"Failed to save results JSON: {e}")

        update_task(task_id, status="Completed")
        add_log(task_id, "[+] Scan completed successfully")

    except Exception as e:
        log_error(f"Background scan failed: {str(e)}")
        add_log(task_id, f"[-] Scan failed: {str(e)}")
        update_task(task_id, status="Failed", error=str(e))

        # Cleanup temp directory on failure
        task = get_task(task_id)
        if task and task.get("temp_dir") and os.path.exists(task["temp_dir"]):
            try:
                shutil.rmtree(task["temp_dir"])
            except:
                pass


# ===============================================
# ROUTES
# ===============================================

@app.route('/')
@require_auth
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
@require_auth
def scan():
    """Submit a new scan."""
    username = session.get("user")
    domain = request.form.get('domain', '').strip()

    # Input validation
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Normalize domain
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    if not domain or len(domain) > 255:
        return jsonify({"error": "Invalid domain"}), 400

    # Rate limiting check
    if is_rate_limited(username, max_scans_per_hour=10):
        return jsonify({
            "error": "Rate limit exceeded (10 scans per hour)"
        }), 429

    # Record scan
    record_scan(username, domain)

    # Create task
    task_id = create_task(domain, username)

    # Start background thread
    thread = threading.Thread(
        target=background_scan,
        args=(task_id, domain, username),
        daemon=False
    )
    thread.start()

    log_success(f"Scan {task_id[:8]} started for {domain} by {username}")

    return redirect(f"/scan_status/{task_id}")


@app.route("/scan_status/<task_id>")
@require_auth
def scan_status(task_id):
    """Display scan status and logs. Returns JSON when ?json=1 is passed (for polling)."""
    task = get_task(task_id)
    if not task:
        return ("Task not found", 404) if not request.args.get("json") else (jsonify({"error": "Task not found"}), 404)

    if task["username"] != session.get("user"):
        return ("Unauthorized", 403) if not request.args.get("json") else (jsonify({"error": "Unauthorized"}), 403)

    logs = get_task_logs(task_id)

    # JSON response for scan_status.html polling
    if request.args.get("json"):
        return jsonify({
            "status": task["status"],
            "logs":   logs,
            "error":  task.get("error")
        })

    # HTML: if completed redirect to results page
    if task["status"] == "Completed":
        return redirect(f"/results/{task_id}")

    return render_template(
        "scan_status.html",
        task_id=task_id,
        status=task["status"],
        domain=task["domain"],
        logs=logs,
        error=task.get("error")
    )


@app.route("/results/<task_id>")
@require_auth
def results(task_id):
    """Display scan results."""
    task = get_task(task_id)
    if not task:
        return "Task not found", 404

    if task["username"] != session.get("user"):
        return "Unauthorized", 403

    with get_conn() as conn:
        scan_row = conn.execute("""
            SELECT id, domain, scan_date, overall_risk_level,
                   critical_count, high_count, medium_count, low_count
            FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1
        """, (task["domain"],)).fetchone()

    if not scan_row:
        return "Results not found", 404

    scan_id      = scan_row[0]
    domain       = scan_row[1]
    created_at   = scan_row[2]
    risk_level   = scan_row[3]

    # Load findings from findings table
    findings = get_findings_for_scan(scan_id)

    # Reconstruct risk dict from counts for template compatibility
    critical = scan_row[4] or 0
    high = scan_row[5] or 0
    medium = scan_row[6] or 0
    low = scan_row[7] or 0

    risk = {
        "critical": findings[:critical],
        "high": findings[
            critical:
            critical + high
        ],
        "medium": findings[
            critical + high:
            critical + high + medium
        ],
        "low": findings[
            critical + high + medium:
            critical + high + medium + low
        ],
    }

    # Load full results from task temp dir if available
    full_results = {}
    temp_dir = task.get("temp_dir")
    if temp_dir and os.path.exists(temp_dir):
        results_path = os.path.join(temp_dir, "results.json")
        if os.path.exists(results_path):
            try:
                with open(results_path) as f:
                    full_results = json.load(f)
            except Exception:
                pass

    # Build a hostname -> live host lookup
    live_host_map = {}

    for host in full_results.get("live_hosts", []):
        hostname = (
            host["url"]
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        live_host_map[hostname] = host

    return render_template(
        "results.html",
        task_id=task_id,
        domain=domain,
        findings=findings,
        risk=risk,
        created_at=created_at,
        subdomains=full_results.get("subdomains", []),
        live_hosts=full_results.get("live_hosts", []),
        live_host_map=live_host_map,
        endpoints=full_results.get("endpoints", []),
        technologies=full_results.get("technologies", {}),
        js_intelligence=full_results.get("js_intelligence", []),
        directories=full_results.get("directories", []),
        screenshots=full_results.get("screenshots", []),
        browser_recon=full_results.get("browser_recon", []),
        attack_surface=full_results.get("attack_surface", {}),
        attack_surface_map=full_results.get("attack_surface_map", {}),
        exploits=full_results.get("exploits", []),
        validated_exploits=full_results.get("validated_exploits", []),
        priorities=full_results.get("priorities", []),
        analysis_results=full_results.get("analysis", []),
        verified=full_results.get("verified", []),
    )


@app.route("/download_pdf/<task_id>")
@require_auth
def download_pdf(task_id):
    """Download PDF report for a scan."""
    task = get_task(task_id)
    if not task:
        return "Task not found", 404

    if task["username"] != session.get("user"):
        return "Unauthorized", 403

    if task["status"] != "Completed":
        return "Scan not completed", 400

    temp_dir = task.get("temp_dir")
    if not temp_dir or not os.path.exists(temp_dir):
        return "PDF not found", 404

    # Find PDF in temp directory
    for filename in os.listdir(temp_dir):
        if filename.endswith(".pdf"):
            pdf_path = os.path.join(temp_dir, filename)
            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=filename
            )

    return "PDF not found", 404


@app.route("/history")
@require_auth
def history():
    """View scan history."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id, domain, scan_date, critical_count, high_count,
                   medium_count, low_count, overall_risk_level
            FROM scans
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

    scans = []
    for row in rows:
        scans.append({
            "id":             row[0],
            "domain":         row[1],
            "created_at":     row[2],
            "critical_count": row[3] or 0,
            "high_count":     row[4] or 0,
            "medium_count":   row[5] or 0,
            "low_count":      row[6] or 0,
            "risk_level":     row[7] or "LOW",
        })

    return render_template("history.html", scans=scans)


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("register.html", error="Username and password are required")

        if len(username) < 3:
            return render_template("register.html", error="Username must be at least 3 characters")

        if len(password) < 6:
            return render_template("register.html", error="Password must be at least 6 characters")

        success = create_user(username, generate_password_hash(password))
        if not success:
            return render_template("register.html", error="Username already exists")

        log_success(f"User registered: {username}")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="Username and password are required")

        user = authenticate_user(username)
        if user and check_password_hash(user[2], password):
            session["user"] = username
            log_success(f"User logged in: {username}")
            return redirect("/")

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """User logout."""
    username = session.get("user")
    session.clear()
    if username:
        log_info(f"User logged out: {username}")
    return redirect("/login")


@app.route("/screenshots/<path:filename>")
@require_auth
def screenshots(filename):
    """Serve screenshot images."""
    screenshots_dir = os.path.abspath(
        os.path.join(app.root_path, "..", "screenshots")
    )
    return send_from_directory(screenshots_dir, filename)


# ===============================================
# ERROR HANDLERS
# ===============================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return "Page not found", 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    log_error(f"Server error: {str(e)}")
    return "Server error", 500



# ===============================================
# MAIN
# ===============================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = bool(os.environ.get("DEBUG", False))

    if not os.environ.get("SECRET_KEY"):
        log_warning("SECRET_KEY not set in environment; using random key (insecure for production)")

    log_success(f"Starting AI Bug Bounty Recon on port {port}")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True  # Allow multiple threads per process
    )
"""
Logger Utility v2.0

Provides colored console output with fallback for environments
that don't support colors (CI/CD, file output, web logs).

Usage:
    from utils.logger import info, success, warning, error, highlight

    info("Starting scan...")
    success("Found 5 vulnerabilities!")
    warning("Slow response time detected")
    error("Invalid URL provided")
    highlight("Critical finding!")
"""

import os
import sys
from enum import Enum

# Auto-detect color support
SUPPORTS_COLOR = (
    sys.stdout.isatty() and
    os.getenv("NO_COLOR") is None and
    os.getenv("FORCE_COLOR") != "0"
)

# Allow override
FORCE_COLOR = os.getenv("FORCE_COLOR", "").lower() in ("1", "true", "yes")
DISABLE_COLOR = os.getenv("NO_COLOR") is not None

ENABLE_COLORS = (FORCE_COLOR or SUPPORTS_COLOR) and not DISABLE_COLOR

# Legacy compatibility
CLI_MODE = os.getenv("CLI_MODE", "1") == "1"


class LogLevel(Enum):
    """Log verbosity levels"""
    DEBUG   = 0
    INFO    = 1
    SUCCESS = 2
    WARNING = 3
    ERROR   = 4


# Color codes (ANSI)
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

    # Foreground
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"


# Bright/High intensity
class BrightColors:
    BLACK   = "\033[90m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"


def _colorize(text: str, color: str, bold: bool = False) -> str:
    """Apply ANSI color codes to text if colors are enabled."""
    if not ENABLE_COLORS:
        return text

    prefix = ""
    if bold:
        prefix += Colors.BOLD

    return f"{prefix}{color}{text}{Colors.RESET}"


# =========================
# PUBLIC LOGGING FUNCTIONS
# =========================

def debug(msg: str) -> None:
    """Print debug message (dark gray)."""
    if ENABLE_COLORS:
        print(f"{BrightColors.BLACK}[DEBUG]{Colors.RESET} {msg}")
    else:
        print(f"[DEBUG] {msg}")


def info(msg: str) -> None:
    """Print info message (cyan)."""
    colored = _colorize(msg, Colors.CYAN)
    print(colored)


def success(msg: str) -> None:
    """Print success message (green, bold)."""
    colored = _colorize(msg, Colors.GREEN, bold=True)
    print(colored)


def warning(msg: str) -> None:
    """Print warning message (yellow)."""
    colored = _colorize(msg, Colors.YELLOW)
    print(colored)


def error(msg: str) -> None:
    """Print error message (red, bold)."""
    colored = _colorize(msg, Colors.RED, bold=True)
    print(colored)


def highlight(msg: str) -> None:
    """Print highlighted message (magenta, bold) — for critical findings."""
    colored = _colorize(msg, Colors.MAGENTA, bold=True)
    print(colored)


def status(msg: str, status_type: str = "INFO") -> None:
    """
    Print status message with label.

    Args:
        msg:         message text
        status_type: 'INFO', 'OK', 'WARN', 'ERROR', 'RUNNING'
    """
    status_colors = {
        "INFO":    Colors.CYAN,
        "OK":      Colors.GREEN,
        "WARN":    Colors.YELLOW,
        "ERROR":   Colors.RED,
        "RUNNING": Colors.BLUE,
    }

    color = status_colors.get(status_type.upper(), Colors.CYAN)

    if ENABLE_COLORS:
        status_label = _colorize(f"[{status_type.upper()}]", color, bold=True)
        print(f"{status_label} {msg}")
    else:
        print(f"[{status_type.upper()}] {msg}")


def section(title: str) -> None:
    """Print a section header."""
    if ENABLE_COLORS:
        print(f"\n{_colorize('=' * 60, Colors.BLUE, bold=True)}")
        print(_colorize(f"  {title}", Colors.CYAN, bold=True))
        print(f"{_colorize('=' * 60, Colors.BLUE, bold=True)}\n")
    else:
        print(f"\n{'=' * 60}")
        print(f"  {title}")
        print(f"{'=' * 60}\n")


def result(label: str, value: str, color: str = "CYAN") -> None:
    """
    Print a key-value result with color.

    Args:
        label: the key (left side)
        value: the value (right side)
        color: 'CYAN', 'GREEN', 'YELLOW', 'RED'
    """
    color_map = {
        "CYAN":    Colors.CYAN,
        "GREEN":   Colors.GREEN,
        "YELLOW":  Colors.YELLOW,
        "RED":     Colors.RED,
        "BLUE":    Colors.BLUE,
        "MAGENTA": Colors.MAGENTA,
    }

    use_color = color_map.get(color.upper(), Colors.CYAN)

    if ENABLE_COLORS:
        print(f"  {_colorize(label, use_color, bold=True)}: {value}")
    else:
        print(f"  {label}: {value}")


def table(headers: list, rows: list) -> None:
    """
    Print a simple aligned table.

    Args:
        headers: list of column names
        rows:    list of tuples/lists (one per row)
    """
    if not headers or not rows:
        return

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Print header
    header_str = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    if ENABLE_COLORS:
        print(_colorize(header_str, Colors.BLUE, bold=True))
        print(_colorize("-" * len(header_str), Colors.BLUE))
    else:
        print(header_str)
        print("-" * len(header_str))

    # Print rows
    for row in rows:
        print(" | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


# =========================
# BACKWARD COMPATIBILITY
# (old code expecting these exact function names)
# =========================

# Alias for old colorama imports
from colorama import Fore, Style, init as colorama_init

# Keep working if old code imports these
try:
    colorama_init(autoreset=True, strip=True)
except Exception:
    pass


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    print("Testing logger output:\n")

    info("This is an info message (cyan)")
    success("This is a success message (green, bold)")
    warning("This is a warning message (yellow)")
    error("This is an error message (red, bold)")
    highlight("This is a highlighted message (magenta, bold)")
    debug("This is a debug message (dark gray)")

    print()
    status("Scan started", "RUNNING")
    status("Module loaded", "OK")
    status("Performance warning", "WARN")
    status("Critical error detected", "ERROR")

    print()
    section("Test Section")

    result("Found vulnerabilities", "5", color="RED")
    result("Security score", "85/100", color="GREEN")
    result("Scan duration", "42 seconds", color="CYAN")

    print()
    print("Table example:")
    table(
        ["Type", "Count", "Severity"],
        [
            ("SQLi", 1, "Critical"),
            ("XSS", 3, "Medium"),
            ("IDOR", 2, "High"),
        ]
    )

    print("\nLogger test complete. Set NO_COLOR=1 to disable colors.")

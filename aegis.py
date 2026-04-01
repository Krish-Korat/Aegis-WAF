#!/usr/bin/env python3
"""
Aegis WAF – Reverse Proxy Web Application Firewall
A plug-and-play security tool that shields web applications from attacks.

Usage:
    python aegis.py start --target http://localhost:3000
    python aegis.py stop
    python aegis.py status
    python aegis.py logs
    python aegis.py logs --follow
"""

import argparse
import os
import sys
import subprocess
import time
import json
import platform
import re


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

VERSION = "2.0.0"

BANNER = r"""
    ___              _        _      __  ___   ____
   /   | ___  ____ _(_)____  | |     / / /   | / __/
  / /| |/ _ \/ __ `/ / ___/  | | /| / / / /| |/ /_
 / ___ /  __/ /_/ / (__  )   | |/ |/ / / ___ / __/
/_/  |_\___/\__, /_/____/    |__/|__/ /_/  |_/_/
           /____/
"""

INFO_BLOCK = """
  ╔══════════════════════════════════════════════════════╗
  ║  Aegis WAF v{version:<40s}  ║
  ║  Reverse Proxy Web Application Firewall              ║
  ╠══════════════════════════════════════════════════════╣
  ║                                                      ║
  ║  Protection Modules:                                 ║
  ║    • SQL Injection (SQLi)                            ║
  ║    • Cross-Site Scripting (XSS)                      ║
  ║    • Server-Side Template Injection (SSTI)           ║
  ║    • Local File Inclusion (LFI)                      ║
  ║    • Remote File Inclusion (RFI)                     ║
  ║    • OS Command Injection                            ║
  ║    • Rate Limiting (30 req/min per IP)               ║
  ║                                                      ║
  ║  Architecture:                                       ║
  ║    Client → Nginx → Python WAF → Your Backend        ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# ANSI COLORS
# ---------------------------------------------------------------------------

C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_MAGENTA = "\033[95m"
C_WHITE = "\033[97m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"

ATTACK_COLORS = {
    "sql injection": C_RED,
    "xss": C_YELLOW,
    "ssti": C_MAGENTA,
    "lfi": C_CYAN,
    "rfi": C_CYAN,
    "command injection": C_RED,
    "rate limited": C_WHITE,
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def print_banner():
    """Print the Aegis banner and info block."""
    print(BANNER)
    print(INFO_BLOCK.format(version=VERSION))


def get_project_dir():
    """Return the directory where aegis.py lives (project root)."""
    return os.path.dirname(os.path.abspath(__file__))


def docker_compose_cmd():
    """Return the correct docker compose command for this system."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, check=True
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ["docker-compose"]


def is_running():
    """Check if Aegis containers are currently running."""
    try:
        result = subprocess.run(
            docker_compose_cmd() + ["ps", "--format", "json"],
            capture_output=True, text=True,
            cwd=get_project_dir()
        )
        return result.returncode == 0 and result.stdout.strip() != ""
    except FileNotFoundError:
        return False


def validate_target(target):
    """Validate and normalize the target URL."""
    if not target:
        print(f"  {C_RED}[ERROR]{C_RESET} --target is required.")
        print(f"         Example: python aegis.py start --target http://localhost:3000")
        sys.exit(1)

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    return target


def ensure_docker_dns():
    """Ensure Docker has proper DNS configuration on Linux.

    On Kali and Ubuntu, Docker containers often can't resolve hostnames
    because the host DNS points to 127.0.0.53 (systemd-resolved stub).
    This auto-configures Google DNS (8.8.8.8) to fix the issue.
    Only runs on Linux — Docker Desktop handles DNS natively.
    """
    if platform.system() != "Linux":
        return

    daemon_json = "/etc/docker/daemon.json"
    dns_servers = ["8.8.8.8", "8.8.4.4"]

    try:
        if os.path.exists(daemon_json):
            with open(daemon_json, "r") as f:
                config = json.load(f)
                if "dns" in config:
                    return
    except (json.JSONDecodeError, PermissionError):
        pass

    print(f"  {C_CYAN}[*]{C_RESET} Configuring Docker DNS (first-time setup)...")
    print(f"      This prevents 'name resolution' errors in containers.\n")

    try:
        if os.path.exists(daemon_json):
            with open(daemon_json, "r") as f:
                config = json.load(f)
        else:
            config = {}
    except (json.JSONDecodeError, PermissionError):
        config = {}

    config["dns"] = dns_servers
    config_str = json.dumps(config, indent=2)

    subprocess.run(["sudo", "mkdir", "-p", "/etc/docker"], capture_output=True)
    result = subprocess.run(
        ["sudo", "tee", daemon_json],
        input=config_str.encode(), capture_output=True
    )

    if result.returncode != 0:
        print(f"  {C_YELLOW}[WARNING]{C_RESET} Could not configure Docker DNS automatically.")
        print(f'           Run: sudo bash -c \'echo \'{{"dns":["8.8.8.8"]}}\' > /etc/docker/daemon.json\'')
        return

    subprocess.run(["sudo", "systemctl", "restart", "docker"], capture_output=True)
    print(f"  {C_GREEN}[✓]{C_RESET} Docker DNS configured successfully.\n")


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------

def cmd_start(args):
    """Start the Aegis WAF in front of a target website."""
    print(BANNER)

    target = validate_target(args.target)
    port = args.port

    print(f"  {C_BOLD}Configuration:{C_RESET}")
    print(f"  ├─ Target    : {C_CYAN}{target}{C_RESET}")
    print(f"  ├─ Port      : {C_CYAN}{port}{C_RESET}")
    print(f"  ├─ Rate Limit: {C_CYAN}30 requests/minute per IP{C_RESET}")
    print(f"  └─ Mode      : {C_CYAN}{'Detect Only' if args.detect_only else 'Active Protection'}{C_RESET}")
    print()

    ensure_docker_dns()

    env = os.environ.copy()
    env["AEGIS_BACKEND_URL"] = target
    env["AEGIS_PORT"] = str(port)

    print(f"  {C_CYAN}[*]{C_RESET} Building and starting containers...")
    print()

    result = subprocess.run(
        docker_compose_cmd() + ["up", "--build", "-d"],
        cwd=get_project_dir(),
        env=env
    )

    if result.returncode != 0:
        print(f"\n  {C_RED}[ERROR]{C_RESET} Failed to start Aegis. Is Docker running?")
        sys.exit(1)

    print()
    print(f"  {C_GREEN}╔══════════════════════════════════════════════════════╗{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  {C_BOLD}Aegis WAF is running!{C_RESET}                                {C_GREEN}║{C_RESET}")
    print(f"  {C_GREEN}╠══════════════════════════════════════════════════════╣{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  Protected URL : {C_BOLD}http://localhost:{port}{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  Proxying to   : {target}")
    print(f"  {C_GREEN}║{C_RESET}  Rate limit    : 30 requests/minute per IP")
    print(f"  {C_GREEN}╠══════════════════════════════════════════════════════╣{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  {C_DIM}View logs  : python aegis.py logs{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  {C_DIM}Live monitor: python aegis.py logs --follow{C_RESET}")
    print(f"  {C_GREEN}║{C_RESET}  {C_DIM}Stop       : python aegis.py stop{C_RESET}")
    print(f"  {C_GREEN}╚══════════════════════════════════════════════════════╝{C_RESET}")
    print()


def cmd_stop(args):
    """Stop the Aegis WAF."""
    print(f"\n  {C_CYAN}[*]{C_RESET} Stopping Aegis WAF...\n")

    result = subprocess.run(
        docker_compose_cmd() + ["down"],
        cwd=get_project_dir()
    )

    if result.returncode == 0:
        print(f"\n  {C_GREEN}[✓]{C_RESET} Aegis WAF stopped successfully.\n")
    else:
        print(f"\n  {C_RED}[ERROR]{C_RESET} Failed to stop. Are the containers running?\n")


def cmd_status(args):
    """Show the current status of Aegis containers."""
    print(f"\n  {C_BOLD}Aegis WAF — Container Status{C_RESET}\n")

    subprocess.run(
        docker_compose_cmd() + ["ps"],
        cwd=get_project_dir()
    )
    print()


def cmd_logs(args):
    """View the attack logs from the WAF."""
    log_file = os.path.join(get_project_dir(), "waf", "logs", "attacks.log")

    if args.clear:
        if os.path.exists(log_file):
            open(log_file, "w").close()
            print(f"  {C_GREEN}[✓]{C_RESET} Attack logs cleared.\n")
        else:
            print(f"  {C_DIM}[*] No log file to clear.{C_RESET}\n")
        return

    if not os.path.exists(log_file):
        print()
        print(f"  {C_BOLD}No attack logs found yet.{C_RESET}")
        print(f"  {C_DIM}Logs are created when the first attack is detected.{C_RESET}")
        print()
        print(f"  {C_DIM}Try sending a test attack:{C_RESET}")
        print(f'  curl "http://localhost:8000/?q=<script>alert(1)</script>"')
        print()
        return

    if args.follow:
        _logs_follow(log_file)
    else:
        _logs_show(log_file)


# ---------------------------------------------------------------------------
# LOG DISPLAY ENGINE
# ---------------------------------------------------------------------------

def _parse_log_line(line):
    """Parse a raw log line into structured fields.

    Input:  [2026-04-01 11:25:26.123456] IP: 1.2.3.4 | Attack: ['XSS'] | Payload: ...
    Output: { timestamp, ip, attack, payload } or None
    """
    match = re.match(
        r"\[(.+?)\]\s*IP:\s*(.+?)\s*\|\s*Attack:\s*(.+?)\s*\|\s*Payload:\s*(.*)",
        line.strip()
    )
    if not match:
        return None

    timestamp_raw = match.group(1).strip()
    ip = match.group(2).strip()
    attack_raw = match.group(3).strip()
    payload = match.group(4).strip()

    # Clean attack type: "['SQL Injection']" → "SQL Injection"
    attack = attack_raw.strip("[]'\"").replace("'", "").replace('"', "")

    # Shorten timestamp: "2026-04-01 11:25:26.123456" → "04-01 11:25:26"
    try:
        ts = timestamp_raw.split(".")[0]
        parts = ts.split(" ")
        if len(parts) == 2:
            date_part = "-".join(parts[0].split("-")[1:])
            timestamp = f"{date_part} {parts[1]}"
        else:
            timestamp = ts
    except Exception:
        timestamp = timestamp_raw

    if len(payload) > 80:
        payload = payload[:77] + "..."

    return {"timestamp": timestamp, "ip": ip, "attack": attack, "payload": payload}


def _color_attack(text):
    """Wrap attack type text in its ANSI color."""
    key = text.lower().strip()
    for name, color in ATTACK_COLORS.items():
        if name in key:
            return f"{color}{text}{C_RESET}"
    return text


def _print_log_entry(entry):
    """Print one formatted log line."""
    colored = _color_attack(entry["attack"])
    print(
        f"  {C_DIM}{entry['timestamp']}{C_RESET}"
        f"  {C_BOLD}{entry['ip']:>15}{C_RESET}"
        f"  {colored:<30}"
        f"  {C_DIM}{entry['payload']}{C_RESET}"
    )


def _print_header():
    """Print column headers for log table."""
    print(
        f"  {C_DIM}{'TIME':<14}"
        f"  {'IP':>15}"
        f"  {'ATTACK':<30}"
        f"  {'PAYLOAD'}{C_RESET}"
    )
    print(f"  {C_DIM}{'─' * 90}{C_RESET}")


def _logs_show(log_file):
    """Display existing logs with summary statistics."""
    with open(log_file, "r") as f:
        lines = f.readlines()

    if not lines:
        print(f"  {C_DIM}[*] Log file is empty — no attacks detected yet.{C_RESET}\n")
        return

    entries = [_parse_log_line(l) for l in lines]
    entries = [e for e in entries if e]

    if not entries:
        print(f"  {C_DIM}[*] Log file exists but no entries could be parsed.{C_RESET}\n")
        return

    # Summary stats
    unique_ips = set(e["ip"] for e in entries)
    attack_counts = {}
    for e in entries:
        attack_counts[e["attack"]] = attack_counts.get(e["attack"], 0) + 1
    top_attack = max(attack_counts, key=attack_counts.get)

    print()
    print(f"  {C_BOLD}Aegis WAF — Attack Log{C_RESET}")
    print(f"  {C_DIM}{'─' * 40}{C_RESET}")
    print(f"  Total attacks  : {C_BOLD}{len(entries)}{C_RESET}")
    print(f"  Unique IPs     : {C_BOLD}{len(unique_ips)}{C_RESET}")
    print(f"  Top attack     : {_color_attack(top_attack)} ({attack_counts[top_attack]})")

    # Attack type breakdown
    print(f"\n  {C_DIM}Attack Breakdown:{C_RESET}")
    for attack, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 30)
        print(f"    {_color_attack(attack):<35} {C_DIM}{bar} {count}{C_RESET}")

    print()

    # Show entries (last 50 if too many)
    display = entries[-50:] if len(entries) > 50 else entries
    if len(entries) > 50:
        print(f"  {C_DIM}(showing last 50 of {len(entries)} entries){C_RESET}\n")

    _print_header()
    for entry in display:
        _print_log_entry(entry)
    print()


def _logs_follow(log_file):
    """Real-time log monitor — shows new attacks as they happen."""
    print()
    print(f"  {C_BOLD}Aegis WAF — Live Attack Monitor{C_RESET}")
    print(f"  {C_DIM}Watching for new attacks... (CTRL+C to stop){C_RESET}")
    print()
    _print_header()

    count = 0
    try:
        with open(log_file, "r") as f:
            f.seek(0, 2)  # Jump to end — only show NEW entries
            while True:
                line = f.readline()
                if line:
                    entry = _parse_log_line(line)
                    if entry:
                        count += 1
                        _print_log_entry(entry)
                else:
                    time.sleep(0.3)
    except KeyboardInterrupt:
        print()
        print(f"  {C_DIM}{'─' * 90}{C_RESET}")
        print(f"  {C_BOLD}{count}{C_RESET} new attacks captured during this session.")
        print()


# ---------------------------------------------------------------------------
# ARGUMENT PARSER
# ---------------------------------------------------------------------------

HELP_EPILOG = f"""
{C_BOLD}Commands:{C_RESET}
  start       Deploy the WAF in front of a target website
  stop        Shut down all Aegis containers
  status      Show the running state of Aegis containers
  logs        View, monitor, or clear the attack logs

{C_BOLD}Quick Start:{C_RESET}
  python aegis.py start --target http://localhost:3000
  python aegis.py start --target http://mysite.com --port 9000
  python aegis.py logs --follow
  python aegis.py stop

{C_BOLD}Protection Modules:{C_RESET}
  SQLi         SQL Injection detection
  XSS          Cross-Site Scripting detection
  SSTI         Server-Side Template Injection detection
  LFI          Local File Inclusion detection
  RFI          Remote File Inclusion detection
  CMDi         OS Command Injection detection
  Rate Limit   30 requests/minute per IP (auto-block)

{C_BOLD}Architecture:{C_RESET}
  Client → Nginx (Reverse Proxy) → Python WAF (FastAPI) → Your Backend
"""


def build_parser():
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis WAF – Reverse Proxy Web Application Firewall",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"Aegis WAF v{VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
    )

    # --- start ---
    sp_start = subparsers.add_parser(
        "start",
        help="Start the WAF to protect a target website",
        description="Deploy Aegis WAF as a reverse proxy in front of a target website.\n\n"
                    "Aegis builds and starts Docker containers that intercept all traffic,\n"
                    "scan for attacks, enforce rate limits, and forward clean requests.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python aegis.py start --target http://localhost:3000\n"
               "  python aegis.py start -t http://mysite.com -p 9000\n"
               "  python aegis.py start -t 192.168.1.100:5000\n"
               "  python aegis.py start -t http://backend --detect-only\n",
    )
    sp_start.add_argument(
        "--target", "-t", required=True, metavar="URL",
        help="URL of the website to protect (e.g. http://localhost:3000)",
    )
    sp_start.add_argument(
        "--port", "-p", default=8000, type=int, metavar="PORT",
        help="Port for Aegis to listen on (default: 8000)",
    )
    sp_start.add_argument(
        "--detect-only", action="store_true",
        help="Log attacks but don't block them (monitor mode)",
    )
    sp_start.set_defaults(func=cmd_start)

    # --- stop ---
    sp_stop = subparsers.add_parser(
        "stop",
        help="Stop the running WAF and remove containers",
        description="Shut down all Aegis WAF containers and clean up Docker resources.",
    )
    sp_stop.set_defaults(func=cmd_stop)

    # --- status ---
    sp_status = subparsers.add_parser(
        "status",
        help="Show the running state of Aegis containers",
        description="Display the current status of all Aegis Docker containers\n"
                    "(proxy, WAF engine, and backend).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp_status.set_defaults(func=cmd_status)

    # --- logs ---
    sp_logs = subparsers.add_parser(
        "logs",
        help="View, monitor, or clear the attack logs",
        description="Display attack logs with color-coded formatting, summary statistics,\n"
                    "and real-time monitoring capabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python aegis.py logs              # View all logged attacks\n"
               "  python aegis.py logs --follow      # Live monitor (real-time)\n"
               "  python aegis.py logs --clear       # Clear all logs\n",
    )
    sp_logs.add_argument(
        "--follow", "-f", action="store_true",
        help="Live monitor — watch for new attacks in real-time",
    )
    sp_logs.add_argument(
        "--clear", action="store_true",
        help="Clear all attack logs and start fresh",
    )
    sp_logs.set_defaults(func=cmd_logs)

    return parser


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
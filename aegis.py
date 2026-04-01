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


# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------

BANNER = r"""
 █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗    ██╗ █████╗ ███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║    ██║██╔══██╗██╔════╝
███████║█████╗  ██║  ███╗██║███████╗    ██║ █╗ ██║███████║█████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║███╗██║██╔══██║██╔══╝
██║  ██║███████╗╚██████╔╝██║███████║    ╚███╔███╔╝██║  ██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝
"""

VERSION = "1.1.0"


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def print_banner():
    """Print the Aegis ASCII art banner."""
    print(BANNER)


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
        print("[ERROR] --target is required. Example: --target http://localhost:3000")
        sys.exit(1)

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    return target


def ensure_docker_dns():
    """Ensure Docker has proper DNS configuration.

    On many Linux distros (especially Kali, Ubuntu with systemd-resolved),
    Docker containers can't resolve hostnames because the host's DNS is set
    to 127.0.0.53 (a local stub resolver) which doesn't work inside containers.

    This function checks if /etc/docker/daemon.json exists with DNS config.
    If not, it creates it with Google's public DNS (8.8.8.8, 8.8.4.4) and
    restarts Docker. This runs automatically so users who clone the repo
    don't have to debug DNS issues manually.

    Only runs on Linux. Windows/Mac Docker Desktop handles DNS properly.
    """
    # Only needed on Linux — Docker Desktop (Win/Mac) handles DNS fine
    if platform.system() != "Linux":
        return

    daemon_json = "/etc/docker/daemon.json"
    dns_servers = ["8.8.8.8", "8.8.4.4"]

    # Check if config already has DNS
    try:
        if os.path.exists(daemon_json):
            with open(daemon_json, "r") as f:
                config = json.load(f)
                if "dns" in config:
                    return  # DNS already configured, nothing to do
    except (json.JSONDecodeError, PermissionError):
        pass  # File exists but is broken or unreadable, we'll fix it

    print("[*] Configuring Docker DNS (first-time setup)...")
    print("    This prevents 'Temporary failure in name resolution' errors")
    print("    inside Docker containers.\n")

    # Build the config — merge with existing if possible
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

    # Need sudo to write to /etc/docker/
    result = subprocess.run(
        ["sudo", "mkdir", "-p", "/etc/docker"],
        capture_output=True
    )

    result = subprocess.run(
        ["sudo", "tee", daemon_json],
        input=config_str.encode(),
        capture_output=True
    )

    if result.returncode != 0:
        print("[WARNING] Could not configure Docker DNS automatically.")
        print("          Run manually: sudo nano /etc/docker/daemon.json")
        print(f'          Add: {{"dns": ["8.8.8.8", "8.8.4.4"]}}')
        return

    # Restart Docker to apply the new DNS
    subprocess.run(["sudo", "systemctl", "restart", "docker"], capture_output=True)
    print("[✓] Docker DNS configured successfully.\n")


# ---------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------

def cmd_start(args):
    """Start the Aegis WAF in front of a target website."""
    print_banner()

    target = validate_target(args.target)
    port = args.port

    print(f"  Target  : {target}")
    print(f"  Port    : {port}")
    print(f"  Mode    : {'Detect Only (logging)' if args.detect_only else 'Block (active protection)'}")
    print()

    # Auto-fix Docker DNS on Linux to prevent build failures
    ensure_docker_dns()

    # Pass configuration to Docker containers via environment variables.
    env = os.environ.copy()
    env["AEGIS_BACKEND_URL"] = target
    env["AEGIS_PORT"] = str(port)

    print("[*] Building and starting containers...")
    print()

    result = subprocess.run(
        docker_compose_cmd() + ["up", "--build", "-d"],
        cwd=get_project_dir(),
        env=env
    )

    if result.returncode != 0:
        print("\n[ERROR] Failed to start Aegis. Is Docker running?")
        sys.exit(1)

    print()
    print("=" * 55)
    print(f"  Aegis WAF is running!")
    print(f"  Protected URL : http://localhost:{port}")
    print(f"  Proxying to   : {target}")
    print(f"  Rate limit    : 30 requests/minute per IP")
    print(f"  View logs     : python aegis.py logs")
    print(f"  Stop          : python aegis.py stop")
    print("=" * 55)
    print()


def cmd_stop(args):
    """Stop the Aegis WAF."""
    print_banner()
    print("[*] Stopping Aegis WAF...")

    result = subprocess.run(
        docker_compose_cmd() + ["down"],
        cwd=get_project_dir()
    )

    if result.returncode == 0:
        print("[✓] Aegis WAF stopped successfully.")
    else:
        print("[ERROR] Failed to stop. Are the containers running?")


def cmd_status(args):
    """Show the current status of Aegis containers."""
    print_banner()
    print("[*] Aegis WAF Status:\n")

    subprocess.run(
        docker_compose_cmd() + ["ps"],
        cwd=get_project_dir()
    )


def cmd_logs(args):
    """View the attack logs from the WAF with clean formatting."""
    log_file = os.path.join(get_project_dir(), "waf", "logs", "attacks.log")

    if args.clear:
        # Clear the log file
        if os.path.exists(log_file):
            open(log_file, "w").close()
            print("[✓] Attack logs cleared.")
        else:
            print("[*] No log file to clear.")
        return

    if not os.path.exists(log_file):
        print("[*] No attack logs found yet.")
        print("    Logs are created when the first attack is detected.")
        print("    Try sending a test payload:")
        print('    curl "http://localhost:8000/?q=<script>alert(1)</script>"')
        return

    if args.follow:
        _logs_follow(log_file)
    else:
        _logs_show(log_file)


def _parse_log_line(line):
    """Parse a raw log line into structured fields.

    Input format:
      [2026-04-01 11:25:26.123456] IP: 1.2.3.4 | Attack: ['XSS'] | Payload: ...

    Returns a dict with keys: timestamp, ip, attack, payload
    or None if the line can't be parsed.
    """
    import re
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

    # Clean up attack type: "['SQL Injection', 'XSS']" → "SQL Injection, XSS"
    attack = attack_raw.strip("[]'\"")
    attack = attack.replace("'", "").replace('"', "")

    # Shorten timestamp: "2026-04-01 11:25:26.123456" → "04-01 11:25:26"
    try:
        parts = timestamp_raw.split(".")
        ts = parts[0]  # drop microseconds
        date_time = ts.split(" ")
        if len(date_time) == 2:
            date_part = "-".join(date_time[0].split("-")[1:])  # "04-01"
            timestamp = f"{date_part} {date_time[1]}"
        else:
            timestamp = ts
    except Exception:
        timestamp = timestamp_raw

    # Truncate long payloads
    if len(payload) > 80:
        payload = payload[:77] + "..."

    return {
        "timestamp": timestamp,
        "ip": ip,
        "attack": attack,
        "payload": payload,
    }


# --- ANSI color codes for terminal output ---
# These make different attack types visually distinct in the terminal.
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


def _color_attack(attack_text):
    """Return the attack text wrapped in its color code."""
    key = attack_text.lower().strip()
    for name, color in ATTACK_COLORS.items():
        if name in key:
            return f"{color}{attack_text}{C_RESET}"
    return attack_text


def _print_log_entry(entry):
    """Print a single parsed log entry as a clean formatted line."""
    colored_attack = _color_attack(entry['attack'])
    print(
        f"  {C_DIM}{entry['timestamp']}{C_RESET}"
        f"  {C_BOLD}{entry['ip']:>15}{C_RESET}"
        f"  {colored_attack:<30}"
        f"  {C_DIM}{entry['payload']}{C_RESET}"
    )


def _print_header():
    """Print the column header for log output."""
    print(
        f"  {C_DIM}{'TIME':<14}"
        f"  {'IP':>15}"
        f"  {'ATTACK':<30}"
        f"  {'PAYLOAD'}{C_RESET}"
    )
    print(f"  {C_DIM}{'─' * 90}{C_RESET}")


def _logs_show(log_file):
    """Display all existing logs with summary stats."""
    with open(log_file, "r") as f:
        lines = f.readlines()

    if not lines:
        print("[*] Log file is empty — no attacks detected yet.")
        return

    entries = []
    for line in lines:
        entry = _parse_log_line(line)
        if entry:
            entries.append(entry)

    if not entries:
        print("[*] Log file exists but no entries could be parsed.")
        return

    # --- Summary stats ---
    unique_ips = set(e["ip"] for e in entries)
    attack_counts = {}
    for e in entries:
        a = e["attack"]
        attack_counts[a] = attack_counts.get(a, 0) + 1
    top_attack = max(attack_counts, key=attack_counts.get) if attack_counts else "N/A"

    print()
    print(f"  {C_BOLD}Aegis WAF — Attack Log{C_RESET}")
    print(f"  {C_DIM}{'─' * 40}{C_RESET}")
    print(f"  Total attacks  : {C_BOLD}{len(entries)}{C_RESET}")
    print(f"  Unique IPs     : {C_BOLD}{len(unique_ips)}{C_RESET}")
    print(f"  Top attack     : {_color_attack(top_attack)}")
    print()

    # --- Show last N entries (default 50) or all ---
    display_entries = entries[-50:] if len(entries) > 50 else entries
    if len(entries) > 50:
        print(f"  {C_DIM}(showing last 50 of {len(entries)} entries){C_RESET}")
        print()

    _print_header()
    for entry in display_entries:
        _print_log_entry(entry)

    print()


def _logs_follow(log_file):
    """Continuously watch for new log entries in real-time."""
    print()
    print(f"  {C_BOLD}Aegis WAF — Live Attack Monitor{C_RESET}")
    print(f"  {C_DIM}Watching for new attacks... (CTRL+C to stop){C_RESET}")
    print()
    _print_header()

    count = 0
    try:
        with open(log_file, "r") as f:
            # Jump to end of file — only show NEW entries
            f.seek(0, 2)
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

def build_parser():
    """Build the argument parser that defines all CLI commands and options."""

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis WAF – Reverse Proxy Web Application Firewall",
        epilog="Examples:\n"
               "  python aegis.py start --target http://localhost:3000\n"
               "  python aegis.py start --target http://mysite.com --port 9000\n"
               "  python aegis.py stop\n"
               "  python aegis.py logs --follow\n",
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
        description="Available commands",
    )

    # --- start ---
    start_parser = subparsers.add_parser(
        "start",
        help="Start the WAF to protect a target website",
        description="Start the Aegis WAF reverse proxy in front of a target website.",
    )
    start_parser.add_argument(
        "--target", "-t",
        required=True,
        help="URL of the website to protect (e.g. http://localhost:3000)",
    )
    start_parser.add_argument(
        "--port", "-p",
        default=8000,
        type=int,
        help="Port for Aegis to listen on (default: 8000)",
    )
    start_parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Log attacks but don't block them (monitor mode)",
    )
    start_parser.set_defaults(func=cmd_start)

    # --- stop ---
    stop_parser = subparsers.add_parser(
        "stop",
        help="Stop the running WAF",
    )
    stop_parser.set_defaults(func=cmd_stop)

    # --- status ---
    status_parser = subparsers.add_parser(
        "status",
        help="Show the status of Aegis containers",
    )
    status_parser.set_defaults(func=cmd_status)

    # --- logs ---
    logs_parser = subparsers.add_parser(
        "logs",
        help="View attack logs from the WAF",
    )
    logs_parser.add_argument(
        "--follow", "-f",
        action="store_true",
        help="Continuously watch for new log entries in real-time",
    )
    logs_parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all attack logs",
    )
    logs_parser.set_defaults(func=cmd_logs)


    return parser


# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
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
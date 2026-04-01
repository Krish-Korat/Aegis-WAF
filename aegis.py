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
    """View the attack logs from the WAF."""
    log_file = os.path.join(get_project_dir(), "waf", "logs", "attacks.log")

    if not os.path.exists(log_file):
        print("[*] No attack logs found yet. The log file is created when the first attack is detected.")
        return

    if args.follow:
        print("[*] Tailing attack logs (press CTRL+C to stop)...\n")
        try:
            with open(log_file, "r") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end="")
                    else:
                        time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Stopped tailing.")
    else:
        print("[*] Attack Log:\n")
        with open(log_file, "r") as f:
            content = f.read().strip()
            if content:
                print(content)
            else:
                print("  (log file is empty — no attacks detected yet)")



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
        help="Continuously watch for new log entries (like tail -f)",
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
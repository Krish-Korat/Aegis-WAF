#!/usr/bin/env python3
"""
Aegis : Reverse Proxy Web Application Firewall
"""

import argparse
import os
import sys
import subprocess
import time
import json
import platform
import re


VERSION = "2.0.0"

BANNER = r"""
    ___              _        _      __  ___   ____
   /   | ___  ____ _(_)____  | |     / / /   | / __/
  / /| |/ _ \/ __ `/ / ___/  | | /| / / / /| |/ /_
 / ___ /  __/ /_/ / (__  )   | |/ |/ / / ___ / __/
/_/  |_\___/\__, /_/____/    |__/|__/ /_/  |_/_/
           /____/
"""

# ANSI Colors
R = "\033[91m"     # red
Y = "\033[93m"     # yellow
C = "\033[96m"     # cyan
G = "\033[92m"     # green
M = "\033[95m"     # magenta
W = "\033[97m"     # white
D = "\033[2m"      # dim
B = "\033[1m"      # bold
X = "\033[0m"      # reset

ATTACK_COLORS = {
    "sql injection": R, "xss": Y, "ssti": M,
    "lfi": C, "rfi": C, "command injection": R, "rate limited": W,
}


# ───────────────────────────────────────────────────────────────────────
# CUSTOM HELP
# ───────────────────────────────────────────────────────────────────────

HELP_TEXT = f"""{BANNER}
  {B}Aegis : Reverse Proxy Web Application Firewall{X}
  {D}Version {VERSION}{X}

{B}DESCRIPTION{X}
  Aegis is a plug-and-play WAF that protects any web application from
  common attacks. It runs as a Docker-based reverse proxy — all traffic
  passes through Aegis, gets scanned, and only clean requests reach
  your backend. No changes needed in your application code.

{B}USAGE{X}
  python aegis.py <command> [options]

{B}COMMANDS{X}
  {G}start{X}     Deploy the WAF to protect a target website
  {G}stop{X}      Shut down all Aegis containers
  {G}status{X}    Show the running state of containers
  {G}logs{X}      View, monitor, or clear attack logs

{B}START OPTIONS{X}
  {C}--target, -t{X}  <URL>     Target website URL {D}(required){X}
  {C}--port, -p{X}    <PORT>    Port Aegis listens on {D}(default: 8000){X}
  {C}--rate-limit{X}  <NUM>     Max requests per IP per minute {D}(default: 30){X}
  {C}--detect-only{X}           Log attacks but don't block them

{B}LOGS OPTIONS{X}
  {C}--follow, -f{X}            Live monitor — watch attacks in real-time
  {C}--clear{X}                 Clear all attack logs

{B}GLOBAL OPTIONS{X}
  {C}--help, -h{X}              Show this help menu
  {C}--version, -v{X}           Show version number

{B}PROTECTION MODULES{X}
  {R}SQLi{X}     SQL Injection          {R}CMDi{X}   OS Command Injection
  {Y}XSS{X}      Cross-Site Scripting   {C}LFI{X}    Local File Inclusion
  {M}SSTI{X}     Template Injection     {C}RFI{X}    Remote File Inclusion
  {W}Rate{X}     Rate Limiting          {D}(configurable per IP){X}

{B}EXAMPLES{X}
  python aegis.py start --target http://localhost:3000
  python aegis.py start -t http://mysite.com -p 9000 --rate-limit 50
  python aegis.py start -t http://192.168.1.100:5000 --detect-only
  python aegis.py logs --follow
  python aegis.py logs --clear
  python aegis.py stop

{B}ARCHITECTURE{X}
  Client → Nginx (Reverse Proxy) → Aegis WAF (FastAPI) → Your Backend
"""


# ───────────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────────

def get_project_dir():
    return os.path.dirname(os.path.abspath(__file__))


def docker_compose_cmd():
    try:
        subprocess.run(["docker", "compose", "version"],
                       capture_output=True, check=True)
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ["docker-compose"]


def validate_target(target):
    if not target:
        print(f"  {R}[ERROR]{X} --target is required.")
        print(f"         Example: python aegis.py start -t http://localhost:3000")
        sys.exit(1)
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    return target


def ensure_docker_dns():
    """Auto-configure Docker DNS on Linux to prevent build failures."""
    if platform.system() != "Linux":
        return
    daemon_json = "/etc/docker/daemon.json"
    try:
        if os.path.exists(daemon_json):
            with open(daemon_json, "r") as f:
                if "dns" in json.load(f):
                    return
    except (json.JSONDecodeError, PermissionError):
        pass

    print(f"  {C}[*]{X} Configuring Docker DNS (first-time setup)...")
    try:
        config = {}
        if os.path.exists(daemon_json):
            with open(daemon_json, "r") as f:
                config = json.load(f)
    except (json.JSONDecodeError, PermissionError):
        config = {}

    config["dns"] = ["8.8.8.8", "8.8.4.4"]
    subprocess.run(["sudo", "mkdir", "-p", "/etc/docker"], capture_output=True)
    result = subprocess.run(["sudo", "tee", daemon_json],
                            input=json.dumps(config, indent=2).encode(),
                            capture_output=True)
    if result.returncode != 0:
        print(f"  {Y}[!]{X} Could not auto-configure DNS. See README for manual fix.")
        return
    subprocess.run(["sudo", "systemctl", "restart", "docker"], capture_output=True)
    print(f"  {G}[✓]{X} Docker DNS configured.\n")


def ensure_log_file():
    """Create the log file and directory if they don't exist."""
    log_dir = os.path.join(get_project_dir(), "waf", "logs")
    log_file = os.path.join(log_dir, "attacks.log")
    os.makedirs(log_dir, exist_ok=True)
    if not os.path.exists(log_file):
        open(log_file, "w").close()
    return log_file


# ───────────────────────────────────────────────────────────────────────
# COMMANDS
# ───────────────────────────────────────────────────────────────────────

def cmd_start(args):
    target = validate_target(args.target)
    port = args.port
    rate = args.rate_limit
    mode = "Detect Only" if args.detect_only else "Active Protection"

    print(BANNER)
    print(f"  {B}Configuration{X}")
    print(f"  ├── Target     : {C}{target}{X}")
    print(f"  ├── Port       : {C}{port}{X}")
    print(f"  ├── Rate Limit : {C}{rate} req/min per IP{X}")
    print(f"  └── Mode       : {C}{mode}{X}")
    print()

    ensure_docker_dns()

    env = os.environ.copy()
    env["AEGIS_BACKEND_URL"] = target
    env["AEGIS_PORT"] = str(port)
    env["AEGIS_RATE_LIMIT"] = str(rate)
    env["AEGIS_RATE_WINDOW"] = "60"
    env["AEGIS_DETECT_ONLY"] = "true" if args.detect_only else "false"

    print(f"  {C}[*]{X} Building and starting containers...\n")

    result = subprocess.run(
        docker_compose_cmd() + ["up", "--build", "-d"],
        cwd=get_project_dir(), env=env
    )

    if result.returncode != 0:
        print(f"\n  {R}[ERROR]{X} Failed to start. Is Docker running?")
        sys.exit(1)

    # Ensure log file exists for --follow to work immediately
    ensure_log_file()

    w = 56
    def pad(text, used):
        return text + " " * max(0, w - used) + "│"

    print()
    print(f"  ┌{'─' * w}┐")
    print(f"  │  {G}Aegis WAF is running!{X}{'':>{w - 23}}│")
    print(f"  ├{'─' * w}┤")
    print(pad(f"  │  Protected URL : http://localhost:{port}", 39 + len(str(port))))
    print(pad(f"  │  Proxying to   : {target}", 21 + len(target)))
    print(pad(f"  │  Rate Limit    : {rate} req/min per IP", 35 + len(str(rate))))
    print(pad(f"  │  Mode          : {mode}", 21 + len(mode)))
    print(f"  ├{'─' * w}┤")
    print(pad(f"  │  {D}python aegis.py logs            View attack logs{X}", 51))
    print(pad(f"  │  {D}python aegis.py logs --follow   Live monitor{X}", 47))
    print(pad(f"  │  {D}python aegis.py stop            Stop the WAF{X}", 47))
    print(f"  └{'─' * w}┘")
    print()


def cmd_stop(args):
    print(f"\n  {C}[*]{X} Stopping Aegis WAF...\n")
    result = subprocess.run(docker_compose_cmd() + ["down"], cwd=get_project_dir())
    if result.returncode == 0:
        print(f"\n  {G}[✓]{X} Aegis WAF stopped.\n")
    else:
        print(f"\n  {R}[ERROR]{X} Failed to stop.\n")


def cmd_status(args):
    print(f"\n  {B}Aegis WAF — Container Status{X}\n")
    subprocess.run(docker_compose_cmd() + ["ps"], cwd=get_project_dir())
    print()


def cmd_logs(args):
    log_file = ensure_log_file()

    if args.clear:
        open(log_file, "w").close()
        print(f"\n  {G}[✓]{X} Attack logs cleared.\n")
        return

    if args.follow:
        _logs_follow(log_file)
    else:
        _logs_show(log_file)


# ───────────────────────────────────────────────────────────────────────
# LOG DISPLAY
# ───────────────────────────────────────────────────────────────────────

def _parse_log_line(line):
    match = re.match(
        r"\[(.+?)\]\s*IP:\s*(.+?)\s*\|\s*Attack:\s*(.+?)\s*\|\s*Payload:\s*(.*)",
        line.strip()
    )
    if not match:
        return None

    ts_raw = match.group(1).strip()
    ip = match.group(2).strip()
    attack = match.group(3).strip().strip("[]'\"").replace("'", "").replace('"', "")
    payload = match.group(4).strip()

    try:
        ts = ts_raw.split(".")[0]
        parts = ts.split(" ")
        timestamp = f"{'-'.join(parts[0].split('-')[1:])} {parts[1]}" if len(parts) == 2 else ts
    except Exception:
        timestamp = ts_raw

    if len(payload) > 80:
        payload = payload[:77] + "..."

    return {"timestamp": timestamp, "ip": ip, "attack": attack, "payload": payload}


def _color_attack(text):
    key = text.lower().strip()
    for name, color in ATTACK_COLORS.items():
        if name in key:
            return f"{color}{text}{X}"
    return text


def _print_entry(e):
    print(f"  {D}{e['timestamp']}{X}  {B}{e['ip']:>15}{X}  {_color_attack(e['attack']):<30}  {D}{e['payload']}{X}")


def _print_header():
    print(f"  {D}{'TIME':<14}  {'IP':>15}  {'ATTACK':<30}  {'PAYLOAD'}{X}")
    print(f"  {D}{'─' * 85}{X}")


def _logs_show(log_file):
    with open(log_file, "r") as f:
        lines = f.readlines()

    entries = [_parse_log_line(l) for l in lines if l.strip()]
    entries = [e for e in entries if e]

    if not entries:
        print(f"\n  {D}No attacks detected yet.{X}")
        print(f"  {D}Try:{X} curl \"http://localhost:8000/?q=<script>alert(1)</script>\"\n")
        return

    # Summary
    unique_ips = set(e["ip"] for e in entries)
    counts = {}
    for e in entries:
        counts[e["attack"]] = counts.get(e["attack"], 0) + 1
    top = max(counts, key=counts.get)

    print()
    print(f"  {B}Aegis WAF — Attack Log{X}")
    print(f"  {D}{'─' * 40}{X}")
    print(f"  Total Attacks  : {B}{len(entries)}{X}")
    print(f"  Unique IPs     : {B}{len(unique_ips)}{X}")
    print(f"  Top Attack     : {_color_attack(top)} ({counts[top]})")

    # Breakdown
    print(f"\n  {D}Attack Breakdown:{X}")
    for attack, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {_color_attack(attack):<35} {count}")

    print()

    display = entries[-50:] if len(entries) > 50 else entries
    if len(entries) > 50:
        print(f"  {D}(showing last 50 of {len(entries)} entries){X}\n")

    _print_header()
    for e in display:
        _print_entry(e)
    print()


def _logs_follow(log_file):
    print()
    print(f"  {B}Aegis WAF — Live Attack Monitor{X}")
    print(f"  {D}Watching for new attacks... (CTRL+C to stop){X}")
    print()
    _print_header()

    count = 0
    try:
        with open(log_file, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    e = _parse_log_line(line)
                    if e:
                        count += 1
                        _print_entry(e)
                else:
                    time.sleep(0.3)
    except KeyboardInterrupt:
        print(f"\n  {D}{'─' * 85}{X}")
        print(f"  {B}{count}{X} attacks captured during this session.\n")


# ───────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ───────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="aegis",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")

    sub = parser.add_subparsers(dest="command")

    sp = sub.add_parser("start", add_help=False)
    sp.add_argument("--target", "-t", required=True, metavar="URL")
    sp.add_argument("--port", "-p", default=8000, type=int, metavar="PORT")
    sp.add_argument("--rate-limit", "-r", default=30, type=int, metavar="NUM")
    sp.add_argument("--detect-only", action="store_true")
    sp.set_defaults(func=cmd_start)

    sub.add_parser("stop", add_help=False).set_defaults(func=cmd_stop)
    sub.add_parser("status", add_help=False).set_defaults(func=cmd_status)

    lp = sub.add_parser("logs", add_help=False)
    lp.add_argument("--follow", "-f", action="store_true")
    lp.add_argument("--clear", action="store_true")
    lp.set_defaults(func=cmd_logs)

    return parser


# ───────────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"Aegis WAF v{VERSION}")
        sys.exit(0)

    if args.help or not args.command:
        print(HELP_TEXT)
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
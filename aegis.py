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


VERSION = "1.0.0"

BANNER = r"""
 █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗    ██╗ █████╗ ███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║    ██║██╔══██╗██╔════╝
███████║█████╗  ██║  ███╗██║███████╗    ██║ █╗ ██║███████║█████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║███╗██║██╔══██║██╔══╝
██║  ██║███████╗╚██████╔╝██║███████║    ╚███╔███╔╝██║  ██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝
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
  {B}Aegis : Reverse Proxy Web Application Firewall{X}  {D}v{VERSION}{X}

  Aegis is a WAF that protects any web application from common
  attacks. It sits between users and your website as a reverse
  proxy — scanning all traffic and blocking malicious requests.
  No changes needed in your application code.

  {B}USAGE{X}
    python aegis.py <command> [options]

  {B}COMMANDS{X}
    {G}start{X}     Deploy the WAF to protect a target website
    {G}stop{X}      Shut down all Aegis containers
    {G}status{X}    Show the running state of containers
    {G}logs{X}      View, monitor, or clear attack logs

  {B}START OPTIONS{X}
    {C}--target, -t{X}  <URL>     Website to protect {D}(required){X}
    {C}--port, -p{X}    <PORT>    Port for Aegis to listen on {D}(default: 8000){X}
    {C}--rate-limit{X}  <NUM>     Max requests per IP/minute {D}(default: 30){X}
    {C}--detect-only{X}           Log attacks without blocking

  {B}LOGS OPTIONS{X}
    {C}--follow, -f{X}            Live monitor — watch attacks in real-time
    {C}--clear{X}                 Clear all attack logs

  {B}GLOBAL{X}
    {C}--help, -h{X}              Show this help menu
    {C}--version, -v{X}           Show version number

  {B}PROTECTION MODULES{X}
    {R}SQLi{X}   SQL Injection            {R}CMDi{X}   OS Command Injection
    {Y}XSS{X}    Cross-Site Scripting     {C}LFI{X}    Local File Inclusion
    {M}SSTI{X}   Template Injection       {C}RFI{X}    Remote File Inclusion
    {W}Rate{X}   Rate Limiting            {D}(configurable per IP){X}

  {B}EXAMPLES{X}
    python aegis.py start --target http://localhost:3000
    python aegis.py start -t http://mysite.com -p 9000 --rate-limit 50
    python aegis.py start -t http://192.168.1.100:5000 --detect-only
    python aegis.py logs --follow
    python aegis.py logs --clear
    python aegis.py stop

  {B}HOW IT WORKS{X}
    Your app runs on   → {D}http://localhost:3000{X}  {D}(target — your actual website){X}
    Aegis listens on   → {G}http://localhost:8000{X}  {D}(users access this URL){X}
    All traffic flows  → {G}User{X} → {C}Aegis WAF{X} → {D}Your App{X}
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


def clear_log_file(log_file):
    """Clear the log file, handling Docker's root-owned files."""
    try:
        open(log_file, "w").close()
        return True
    except PermissionError:
        # File was created by Docker (root). Use sudo on Linux.
        if platform.system() == "Linux":
            result = subprocess.run(
                ["sudo", "truncate", "-s", "0", log_file],
                capture_output=True
            )
            if result.returncode == 0:
                return True
            # Fallback: try docker exec
            result = subprocess.run(
                docker_compose_cmd() + ["exec", "python_waf", "sh", "-c", "> /app/logs/attacks.log"],
                capture_output=True,
                cwd=get_project_dir()
            )
            return result.returncode == 0
        return False


# ───────────────────────────────────────────────────────────────────────
# COMMANDS
# ───────────────────────────────────────────────────────────────────────

def is_builtin_backend(target):
    """Check if the target is the built-in test backend."""
    return target in ("http://backend", "backend")


def generate_compose(target, port, rate, detect_only):
    """Generate docker-compose.yml dynamically based on target.

    When using an external target (not the built-in backend):
    - The 'backend' service is NOT started
    - The WAF gets 'extra_hosts' so it can reach the host machine
    - 'localhost' in the target URL is rewritten to 'host.docker.internal'
    """
    use_builtin = is_builtin_backend(target)

    # Inside Docker, 'localhost' means the container itself, not the host.
    # Rewrite localhost → host.docker.internal so WAF can reach the host.
    docker_target = target
    if not use_builtin:
        docker_target = target.replace("localhost", "host.docker.internal") \
                              .replace("127.0.0.1", "host.docker.internal")

    lines = ["services:\n"]

    # Only include the demo backend if user is NOT specifying an external target
    if use_builtin:
        lines.append("""
  backend:
    image: nginx:alpine
    volumes:
      - ./backend:/usr/share/nginx/html
""")

    # WAF service
    waf_block = f"""
  python_waf:
    build: ./waf
    container_name: python_waf"""

    if use_builtin:
        waf_block += """
    depends_on:
      - backend"""

    waf_block += f"""
    environment:
      - BACKEND_URL={docker_target}
      - RATE_LIMIT={rate}
      - RATE_WINDOW=60
      - DETECT_ONLY={"true" if detect_only else "false"}"""

    # extra_hosts allows container to reach host machine's localhost
    if not use_builtin:
        waf_block += '\n    extra_hosts:\n      - "host.docker.internal:host-gateway"'

    waf_block += """
    volumes:
      - ./waf/logs:/app/logs
"""
    lines.append(waf_block)

    # Proxy
    lines.append(f"""
  proxy:
    image: nginx
    volumes:
      - ./proxy/nginx.conf:/etc/nginx/nginx.conf
    ports:
      - "{port}:80"
    depends_on:
      - python_waf
""")

    compose_path = os.path.join(get_project_dir(), "docker-compose.yml")
    with open(compose_path, "w") as f:
        f.write("".join(lines))


def cmd_start(args):
    target = validate_target(args.target)
    port = args.port
    rate = args.rate_limit
    detect_only = args.detect_only
    mode = "Detect Only" if detect_only else "Active Protection"

    print(BANNER)
    print(f"  {B}Aegis : Reverse Proxy Web Application Firewall{X}  {D}v{VERSION}{X}")
    print()
    print(f"  {B}Configuration{X}")
    print(f"  {D}───────────────────────────────────────────{X}")
    print(f"  Target (your app)  {C}{target}{X}")
    print(f"  Aegis port         {C}{port}{X}")
    print(f"  Rate limit         {C}{rate} req/min per IP{X}")
    print(f"  Mode               {C}{mode}{X}")
    print()

    ensure_docker_dns()

    # Generate docker-compose.yml dynamically based on target
    generate_compose(target, port, rate, detect_only)

    print(f"  {C}[*]{X} Building and starting containers...\n")

    result = subprocess.run(
        docker_compose_cmd() + ["up", "--build", "-d"],
        cwd=get_project_dir()
    )

    if result.returncode != 0:
        print(f"\n  {R}[ERROR]{X} Failed to start. Is Docker running?")
        sys.exit(1)

    # Ensure log file exists for --follow to work immediately
    ensure_log_file()

    print()
    print(f"  {G}[✓] Aegis WAF is running!{X}")
    print(f"  {D}{'─' * 50}{X}")
    print(f"  {B}Your app{X}       {D}{target}{X}")
    print(f"  {B}Aegis URL{X}      {G}http://localhost:{port}{X}  ← {D}users access this{X}")
    print(f"  {B}Rate limit{X}     {rate} req/min per IP")
    print(f"  {B}Mode{X}           {mode}")
    print(f"  {D}{'─' * 50}{X}")
    print(f"  {D}Traffic flow:{X}  {G}User{X} → {C}Aegis (:{port}){X} → {D}{target}{X}")
    print(f"  {D}{'─' * 50}{X}")
    print(f"  {D}View logs      python aegis.py logs{X}")
    print(f"  {D}Live monitor   python aegis.py logs --follow{X}")
    print(f"  {D}Stop           python aegis.py stop{X}")
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
        if clear_log_file(log_file):
            print(f"\n  {G}[✓]{X} Attack logs cleared.\n")
        else:
            print(f"\n  {R}[ERROR]{X} Could not clear logs. Try: sudo truncate -s 0 {log_file}\n")
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
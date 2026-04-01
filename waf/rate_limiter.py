"""
Rate Limiter for Aegis WAF

Tracks requests per IP using an in-memory dictionary.
Rate limit and window are configurable via environment variables.
"""

import os
import time
import threading


# Read from environment variables (set by docker-compose from CLI flags)
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", 30))
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", 60))

ip_requests = {}
ip_lock = threading.Lock()


def cleanup_old_entries():
    """Remove expired timestamps every 30 seconds."""
    while True:
        time.sleep(30)
        now = time.time()
        with ip_lock:
            expired = [ip for ip, ts in ip_requests.items()
                       if not [t for t in ts if now - t < RATE_WINDOW]]
            for ip in expired:
                del ip_requests[ip]
            for ip in list(ip_requests):
                ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_WINDOW]


cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
cleanup_thread.start()


def is_rate_limited(ip):
    """Check if an IP exceeded the rate limit. Returns True if blocked."""
    now = time.time()
    with ip_lock:
        if ip not in ip_requests:
            ip_requests[ip] = []

        ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_WINDOW]

        if len(ip_requests[ip]) >= RATE_LIMIT:
            return True

        ip_requests[ip].append(now)
        return False

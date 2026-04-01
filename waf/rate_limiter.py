"""
Rate Limiter for Aegis WAF

A simple in-memory rate limiter that tracks requests per IP address.

How it works:
  - We store a dictionary: { "192.168.1.5": [timestamp1, timestamp2, ...] }
  - On every request, we add the current timestamp to that IP's list.
  - We remove timestamps older than 60 seconds (the time window).
  - If the remaining count exceeds RATE_LIMIT, the request is blocked.

Why in-memory (not Redis/database)?
  - For a single-container WAF, a dictionary is fast and simple.
  - If we scale to multiple WAF containers later, we'd switch to Redis.

The cleanup thread runs every 30 seconds to remove old entries so the
dictionary doesn't grow forever from IPs that visited once and left.
"""

import time
import threading


RATE_LIMIT = 30           # max requests allowed per IP
RATE_WINDOW = 60          # time window in seconds (1 minute)

# Dictionary to track request timestamps per IP
# Format: { "ip_address": [timestamp1, timestamp2, ...] }
ip_requests = {}

# Lock for thread-safe access to ip_requests since the cleanup thread
# and the request handler both read/write to it simultaneously.
ip_lock = threading.Lock()


def cleanup_old_entries():
    """Background thread that removes expired timestamps every 30 seconds.
    Without this, IPs that visited the site once would stay in memory forever."""
    while True:
        time.sleep(30)
        now = time.time()
        with ip_lock:
            expired_ips = []
            for ip, timestamps in ip_requests.items():
                ip_requests[ip] = [t for t in timestamps if now - t < RATE_WINDOW]
                if not ip_requests[ip]:
                    expired_ips.append(ip)
            for ip in expired_ips:
                del ip_requests[ip]


# Start the cleanup thread when this module is imported.
# daemon=True means it dies automatically when the main process stops.
cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
cleanup_thread.start()


def is_rate_limited(ip):
    """Check if an IP has exceeded the rate limit. Returns True if blocked."""
    now = time.time()
    with ip_lock:
        if ip not in ip_requests:
            ip_requests[ip] = []

        # Remove timestamps outside the current window
        ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_WINDOW]

        # Check if limit exceeded
        if len(ip_requests[ip]) >= RATE_LIMIT:
            return True

        # Record this request
        ip_requests[ip].append(now)
        return False

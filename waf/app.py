from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
import requests
from detector import detect_attack
from rate_limiter import is_rate_limited, RATE_LIMIT, RATE_WINDOW
from datetime import datetime
import os

app = FastAPI()

# Read the backend URL from the environment variable set by docker-compose.
# Falls back to "http://backend" which is the default Docker service name.
BACKEND = os.environ.get("BACKEND_URL", "http://backend")


# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

def log_attack(ip, attack_type, payload):
    """Log detected attacks to a file inside the container (mounted as volume)."""

    os.makedirs("logs", exist_ok=True)

    # Sanitize the payload to prevent log injection attacks.
    sanitized_payload = payload.replace("\n", "\\n").replace("\r", "\\r")

    with open("logs/attacks.log", "a") as f:
        f.write(
            f"[{datetime.now()}] IP: {ip} | Attack: {attack_type} | Payload: {sanitized_payload}\n"
        )


# ---------------------------------------------------------------------------
# PROXY HANDLER
# ---------------------------------------------------------------------------

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request):

    # Use X-Real-IP header set by Nginx proxy to get the actual client IP.
    client_ip = request.headers.get("X-Real-IP", request.client.host)

    # --- RATE LIMIT CHECK (runs BEFORE attack detection for efficiency) ---
    if is_rate_limited(client_ip):
        log_attack(client_ip, ["Rate Limited"], "Too many requests")
        return JSONResponse(
            status_code=429,
            content={
                "status": "blocked",
                "attack_type": "Rate Limited",
                "message": f"Too many requests. Limit is {RATE_LIMIT} per {RATE_WINDOW}s.",
                "ip": client_ip
            }
        )

    body = await request.body()

    # Extract all parts of the request to scan for attacks
    url_payload = str(request.url)
    query_payload = str(request.query_params)
    body_payload = body.decode(errors="ignore")

    # Combine all input sources into one string for the detection engine
    combined_payload = url_payload + query_payload + body_payload

    # Run the combined payload through all detection rules
    attack = detect_attack(combined_payload)

    if attack:
        log_attack(client_ip, attack, combined_payload)
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "attack_type": attack,
                "ip": client_ip
            }
        )

    # Forward clean requests to the backend
    url = f"{BACKEND}/{path}" if path else BACKEND

    resp = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
        data=body
    )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=dict(resp.headers)
    )

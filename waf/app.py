from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
import requests
from detector import detect_attack
from rate_limiter import is_rate_limited, RATE_LIMIT, RATE_WINDOW
from datetime import datetime
import os

app = FastAPI()

BACKEND = os.environ.get("BACKEND_URL", "http://backend")
DETECT_ONLY = os.environ.get("DETECT_ONLY", "false").lower() == "true"


def log_attack(ip, attack_type, payload):
    """Log detected attacks to file."""
    os.makedirs("logs", exist_ok=True)
    sanitized = payload.replace("\n", "\\n").replace("\r", "\\r")
    with open("logs/attacks.log", "a") as f:
        f.write(f"[{datetime.now()}] IP: {ip} | Attack: {attack_type} | Payload: {sanitized}\n")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request):

    client_ip = request.headers.get("X-Real-IP", request.client.host)

    # Rate limit check (before attack detection for efficiency)
    if is_rate_limited(client_ip):
        log_attack(client_ip, ["Rate Limited"], "Too many requests")
        return JSONResponse(
            status_code=429,
            content={
                "status": "blocked",
                "attack_type": "Rate Limited",
                "message": f"Too many requests. Limit: {RATE_LIMIT} per {RATE_WINDOW}s.",
                "ip": client_ip
            }
        )

    body = await request.body()

    url_payload = str(request.url)
    query_payload = str(request.query_params)
    body_payload = body.decode(errors="ignore")
    combined_payload = url_payload + query_payload + body_payload

    attack = detect_attack(combined_payload)

    if attack:
        log_attack(client_ip, attack, combined_payload)

        # In detect-only mode, log the attack but don't block the request
        if not DETECT_ONLY:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",
                    "attack_type": attack,
                    "ip": client_ip
                }
            )

    # Forward to backend
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

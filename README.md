# Aegis : Reverse Proxy Web Application Firewall

Aegis is a Web Application Firewall (WAF) that protects any website from common web attacks — **without modifying a single line of your application's source code**.

It works by sitting between the user and your website as a **reverse proxy**. Every request passes through Aegis first, gets scanned for attacks, and only clean requests are forwarded to your actual website.

```
User's Browser → Aegis WAF → Your Website
```

---

## What Aegis Protects Against

| Attack Type | What It Is |
|---|---|
| **SQL Injection (SQLi)** | Attackers try to manipulate your database through input fields |
| **Cross-Site Scripting (XSS)** | Attackers try to inject malicious JavaScript into your pages |
| **Server-Side Template Injection (SSTI)** | Attackers try to execute code through template engines |
| **Local File Inclusion (LFI)** | Attackers try to read sensitive files from your server |
| **Remote File Inclusion (RFI)** | Attackers try to load malicious files from external URLs |
| **Command Injection (CMDi)** | Attackers try to execute operating system commands |
| **Rate Limiting** | Auto-blocks IPs that send too many requests (DDoS/brute-force) |

---

## Requirements

- **Docker** — [Install Docker](https://docs.docker.com/get-docker/)
- **Python 3.8+** — To run the CLI tool

That's it. Everything else runs inside Docker containers.

---

## Getting Started

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Aegis-WAF.git
cd Aegis-WAF
```

### Step 2 — Start Aegis

```bash
python aegis.py start --target http://localhost:3000
```

Replace `http://localhost:3000` with the URL of your website.

### Step 3 — Access your protected website

Open your browser and go to:

```
http://localhost:8000
```

This is your website, but now every request goes through the Aegis firewall first.

### Step 4 — Try an attack (to verify it works)

```bash
# SQL Injection — should be BLOCKED (HTTP 403)
curl "http://localhost:8000/?q=' UNION SELECT * FROM users--"

# XSS — should be BLOCKED (HTTP 403)
curl "http://localhost:8000/?q=<script>alert(1)</script>"

# Clean request — should PASS through (HTTP 200)
curl "http://localhost:8000/?q=hello+world"
```

### Step 5 — View the attack logs

```bash
python aegis.py logs
```

### Step 6 — Stop the WAF

```bash
python aegis.py stop
```

---

## All Commands

### View Help

```bash
python aegis.py --help
```

Shows all commands, options, protection modules, and examples.

### Start the WAF

```bash
python aegis.py start --target <URL> [options]
```

| Option | Short | Default | What it does |
|---|---|---|---|
| `--target` | `-t` | *(required)* | URL of your website to protect |
| `--port` | `-p` | `8000` | Port where Aegis will be available |
| `--rate-limit` | `-r` | `30` | Max requests per IP per minute |
| `--detect-only` | | off | Only log attacks, don't block them |

**Examples:**
```bash
# Basic usage
python aegis.py start -t http://localhost:3000

# Custom port
python aegis.py start -t http://localhost:3000 -p 9000

# Higher rate limit
python aegis.py start -t http://mysite.com --rate-limit 100

# Monitor mode (log attacks but don't block)
python aegis.py start -t http://mysite.com --detect-only
```

### Stop the WAF

```bash
python aegis.py stop
```

### Check Status

```bash
python aegis.py status
```

### View Attack Logs

```bash
# View all logged attacks with summary
python aegis.py logs

# Live monitor — see attacks appear in real-time
python aegis.py logs --follow

# Clear all logs
python aegis.py logs --clear
```

---

## How to Protect Your Own Website

Aegis works with **any** web application — Node.js, Python (Django/Flask), PHP, Java, React, or even static HTML sites. You don't need to change anything in your code.

### Your website is running locally

If your website is running on your machine (for example, a Node.js app on port 3000):

```bash
# Your website is at http://localhost:3000
python aegis.py start --target http://localhost:3000

# Now access it through Aegis at http://localhost:8000
# All traffic is scanned and protected
```

### Your website is on another machine in your network

If your website runs on a different machine (like a server on your LAN):

```bash
# Your website is at http://192.168.1.100:5000
python aegis.py start --target http://192.168.1.100:5000

# Access via http://localhost:8000
```

### Your website is deployed on the cloud

If your website is deployed on AWS, DigitalOcean, Azure, a VPS, or any cloud provider:

**Option A: Run Aegis on the same server as your website**

This is the recommended approach. SSH into your cloud server and:

```bash
# 1. Clone Aegis on the cloud server
git clone https://github.com/YOUR_USERNAME/Aegis-WAF.git
cd Aegis-WAF

# 2. Your website is running on port 3000 on the same server
python aegis.py start --target http://localhost:3000 --port 80

# 3. Point your domain's DNS to the server's IP
#    Users visit http://yourdomain.com → Aegis (port 80) → Your app (port 3000)
```

**Option B: Run Aegis on a separate server (dedicated WAF)**

```bash
# On the Aegis server, point to your cloud website
python aegis.py start --target http://your-cloud-server-ip:3000 --port 80

# Point your domain's DNS to the Aegis server's IP
# Traffic flow: User → Aegis Server → Cloud Server
```

**Important notes for cloud deployment:**
- Make sure Docker is installed on the cloud server
- If running on port 80, you may need `sudo` on Linux
- Configure your firewall to only allow traffic through Aegis (block direct access to your app's port)
- For HTTPS, put a reverse proxy like Caddy or Nginx with SSL in front of Aegis

### What happens when Aegis protects your website

1. A user visits `http://localhost:8000` (or your domain)
2. The request first hits **Nginx** (Aegis reverse proxy)
3. Nginx forwards it to the **Aegis WAF engine**
4. The WAF checks:
   - Is this IP sending too many requests? → **Block with HTTP 429**
   - Does the URL, query string, or body contain attack patterns? → **Block with HTTP 403**
   - Is it clean? → **Forward to your website**
5. Your website processes the clean request and sends the response back through Aegis

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User   │ ──→ │    Nginx     │ ──→ │   Aegis WAF  │ ──→ │ Your Website │
│ (Browser)│ ←── │  (Port 8000) │ ←── │   (FastAPI)  │ ←── │  (Your App)  │
└──────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                  Reverse Proxy        Rate Limiting         Your Application
                  X-Real-IP header     Attack Detection
                                       Logging
```

---

## Project Structure

```
Aegis-WAF/
├── aegis.py              ← CLI tool (start, stop, status, logs)
├── docker-compose.yml    ← Container configuration
├── README.md             ← This file
├── proxy/                ← Nginx reverse proxy config
│   └── nginx.conf
│
└── waf/                  ← The WAF engine
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py             ← Request handler (proxy + blocking)
    ├── detector.py        ← Attack detection registry
    ├── rate_limiter.py    ← Rate limiting module
    └── rules/             ← Attack detection rules
        ├── sqli.py        ← SQL Injection patterns
        ├── xss.py         ← XSS patterns
        ├── ssti.py        ← Template Injection patterns
        ├── lfi.py         ← Local File Inclusion patterns
        ├── rfi.py         ← Remote File Inclusion patterns
        └── cmd_injection.py ← Command Injection patterns
```

---

## License

This project is developed for educational and research purposes.
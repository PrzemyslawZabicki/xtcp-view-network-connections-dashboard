import psutil
import os
import certifi
import requests
import socket
import datetime
import json
import logging
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse


# -------------------------------
# Logging configuration
# -------------------------------

# Resolve absolute path to logs directory (relative to project root)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # server/ dir
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)  # ensure logs/ exists

# Common log format
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# Backend logger
backend_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "backend.logs"),
    maxBytes=5*1024*1024,
    backupCount=5,
    encoding="utf-8"
)
backend_handler.setFormatter(logging.Formatter(LOG_FORMAT))

backend_logger = logging.getLogger("backend")
backend_logger.setLevel(logging.DEBUG)
backend_logger.addHandler(backend_handler)

# Frontend logger
frontend_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "frontend.logs"),
    maxBytes=5*1024*1024,
    backupCount=5,
    encoding="utf-8"
)
frontend_handler.setFormatter(logging.Formatter(LOG_FORMAT))

frontend_logger = logging.getLogger("frontend")
frontend_logger.setLevel(logging.DEBUG)
frontend_logger.addHandler(frontend_handler)


# -------------------------------
# Utility functions
# -------------------------------

def resolve_dns(ip):
    """
    Attempt to resolve a DNS hostname for a given IP address.
    Returns the hostname if successful, otherwise 'unknown'.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"

# -------------------------------
# FastAPI application setup
# -------------------------------

app = FastAPI()

# Enable CORS so the React frontend can call this API from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # allow all origins
    allow_credentials=True,
    allow_methods=["*"],       # allow all HTTP methods
    allow_headers=["*"],       # allow all headers
)

# Middleware to log every incoming HTTP request and its response status
@app.middleware("http")
async def log_requests(request: Request, call_next):
    backend_logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    backend_logger.info(f"Completed response: status_code={response.status_code}")
    return response

# -------------------------------
# External API keys and endpoints
# -------------------------------

ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")   # API key for AbuseIPDB
VT_KEY    = os.getenv("VT_API_KEY")      # API key for VirusTotal

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL    = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# -------------------------------
# Streaming connections endpoint
# -------------------------------

@app.get("/api/connections/stream")
def stream_connections():
    """
    Streams live network connections using psutil.
    Each connection is serialized as JSON and streamed line-by-line.
    """
    async def generate():
        for c in psutil.net_connections(kind="inet"):
            try:
                proc_name = None
                exe = None
                cmdline = None
                create_time = None

                # Try to fetch process details if PID is available
                if c.pid:
                    try:
                        proc = psutil.Process(c.pid)
                        proc_name = proc.name()
                        exe = proc.exe()
                        cmdline = proc.cmdline()
                        create_time = datetime.datetime.fromtimestamp(proc.create_time()).isoformat()
                    except Exception:
                        backend_logger.exception(f"Process error for pid {c.pid}")

                # Determine protocol type
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                
                # Try to resolve local service name from port
                service = None
                try:
                    if c.laddr:
                        service = socket.getservbyport(c.laddr.port)
                except Exception:
                    service = "unknown"

                # Try to resolve DNS for remote IP
                dns = None
                try:
                    if c.raddr:
                        dns = resolve_dns(c.raddr.ip)
                except Exception:
                    dns = "unknown"

                # Build connection record
                item = {
                    "pid": c.pid,
                    "process": proc_name,
                    "protocol": proto,
                    "local_ip": c.laddr.ip if c.laddr else None,
                    "local_port": c.laddr.port if c.laddr else None,
                    "local_service": service,
                    "remote_ip": c.raddr.ip if c.raddr else None,
                    "dns": dns,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "status": c.status,
                    "exe": exe,
                    "cmdline": cmdline,
                    "create_time": create_time
                }
                backend_logger.debug(f"Streaming connection: {item}")
                yield json.dumps(item) + "\n"
                
            except Exception:
                backend_logger.exception(f"General error for pid {c.pid}")
              
    return StreamingResponse(generate(), media_type="application/json")

# -------------------------------
# AbuseIPDB integration
# -------------------------------

def fetch_abuse(ip: str):
    """
    Query AbuseIPDB for reputation data about an IP address.
    Returns JSON data or an error dictionary.
    """
    try:
        backend_logger.info(f"Fetching AbuseIPDB data for IP {ip}")
        resp = requests.get(
            ABUSE_URL,
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=60,
            verify=certifi.where()
        )
        if resp.status_code != 200:
            backend_logger.warning(f"AbuseIPDB returned {resp.status_code} for IP {ip}")
            return {"error": f"AbuseIPDB returned {resp.status_code}", "details": resp.text}
        json_resp = resp.json()
        if "errors" in json_resp:
            backend_logger.error(f"AbuseIPDB error for IP {ip}: {json_resp['errors']}")
            return {"error": json_resp["errors"][0].get("detail", "Unknown error")}
        return json_resp.get("data", {})
    except Exception:
        backend_logger.exception(f"AbuseIPDB fetch failed for IP {ip}")
        return {"error": "Exception occurred during AbuseIPDB fetch"}

# -------------------------------
# VirusTotal integration
# -------------------------------

def fetch_vt(ip: str):
    """
    Query VirusTotal for reputation data about an IP address.
    Returns reputation score, analysis stats, and country info.
    """
    try:
        backend_logger.info(f"Fetching VirusTotal data for IP {ip}")
        resp = requests.get(
            VT_URL.format(ip),
            headers={"x-apikey": VT_KEY},
            timeout=60,
            verify=certifi.where()
        )
        if resp.status_code != 200:
            backend_logger.warning(f"VirusTotal returned {resp.status_code} for IP {ip}")
            return {"error": f"VirusTotal returned {resp.status_code}", "details": resp.text}
        json_resp = resp.json()
        if "error" in json_resp:
            backend_logger.error(f"VirusTotal error for IP {ip}: {json_resp['error']}")
            return {"error": json_resp["error"].get("message", "Unknown error")}
        data = json_resp.get("data", {})
        attributes = data.get("attributes", {})
        return {
            "reputation": attributes.get("reputation", "N/A"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "country": attributes.get("country", "N/A")
        }
    except Exception:
        backend_logger.exception(f"VirusTotal fetch failed for IP {ip}")
        return {"error": "Exception occurred during VirusTotal fetch"}

# -------------------------------
# Combined security check endpoint
# -------------------------------

@app.get("/api/security-check/{ip}")
def security_check(ip: str):
    """
    Endpoint that fetches both AbuseIPDB and VirusTotal results for a given IP.
    Returns a combined JSON object with 'abuse' and 'vt' keys.
    """
    backend_logger.info(f"Security check requested for IP {ip}")
    abuse_data = fetch_abuse(ip)
    vt_data = fetch_vt(ip)
    backend_logger.debug(f"Security check results for {ip}: abuse={abuse_data}, vt={vt_data}")
    return {"abuse": abuse_data, "vt": vt_data}

# -------------------------------
# Frontend log ingestion endpoint
# -------------------------------

@app.post("/api/frontend-log")
async def frontend_log(request: Request):
    """
    Endpoint for the React frontend to send log messages.
    Logs are written into frontend.logs with appropriate severity.
    """
    data = await request.json()
    level = data.get("level", "info").lower()
    message = data.get("message", "")
    details = data.get("details", {})

    if level == "error":
        frontend_logger.error(f"{message} | {details}")
    elif level == "debug":
        frontend_logger.debug(f"{message} | {details}")
    elif level == "warning":
        frontend_logger.warning(f"{message} | {details}")
    else:
        frontend_logger.info(f"{message} | {details}")

    return {"status": "ok"}

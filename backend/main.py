"""
Port Analyzer — FastAPI backend
Run: uvicorn backend.main:app --reload --port 8000
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.routers import ports, auth

_cors_env = os.getenv("CORS_ORIGINS", "")
if not _cors_env or _cors_env.strip() == "*":
    # Refuse to start with a wildcard CORS policy unless explicitly opted in via
    # CORS_ALLOW_WILDCARD=1 — a wildcard + credentials header is a security risk.
    if os.getenv("CORS_ALLOW_WILDCARD", "0") != "1":
        import sys
        print(
            "ERROR: CORS_ORIGINS is unset or '*'. "
            "Set CORS_ORIGINS to your frontend origin(s) or set CORS_ALLOW_WILDCARD=1 "
            "to explicitly allow all origins (not recommended for production).",
            file=sys.stderr,
        )
        sys.exit(1)
    CORS_ORIGINS = ["*"]
else:
    CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]

# Disable interactive API docs in production (set ENABLE_DOCS=1 to turn on)
_enable_docs = os.getenv("ENABLE_DOCS", "0") == "1"

app = FastAPI(
    title="Port Analyzer API",
    description="Cybersecurity intelligence for any port — CVEs, ATT&CK techniques, CISA KEV, EPSS.",
    version="0.1.0",
    docs_url="/docs" if _enable_docs else None,
    redoc_url="/redoc" if _enable_docs else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ports.router)
app.include_router(auth.router)

# Serve web frontend from /web if it exists
_web_dir = Path(__file__).parent.parent / "web"
if _web_dir.exists():
    app.mount("/", StaticFiles(directory=str(_web_dir), html=True), name="static")

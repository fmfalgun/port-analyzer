#!/usr/bin/env python3
"""Convenience entry point — run CLI or backend server.

    python run.py 22              # CLI
    python run.py 22,443,8080     # CLI multi-port
    python run.py --serve         # start backend on :8000
"""
import sys
import os

if "--serve" in sys.argv:
    import uvicorn
    # Bind to localhost by default for development safety.
    # Override with HOST env var (e.g. HOST=0.0.0.0) for production deployments.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    reload = os.environ.get("RELOAD", "1") == "1"
    uvicorn.run("backend.main:app", host=host, port=port, reload=reload)
else:
    from port_analyzer.cli import main
    main(standalone_mode=True)

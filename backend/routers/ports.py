from fastapi import APIRouter, HTTPException, Request, Query
from port_analyzer.cache import (
    get_db, get_api_key, check_key_rate_limit,
    check_ip_rate_limit, increment_key_usage
)
from port_analyzer.engine import analyze_port, analyze_ports, parse_port_input

router = APIRouter(prefix="/api/v1", tags=["ports"])


def _auth(request: Request) -> tuple[bool, str | None]:
    """Returns (authenticated, key_or_none). Handles IP rate limit for anonymous."""
    key = request.headers.get("X-API-Key")
    db  = get_db()
    try:
        if key:
            row = get_api_key(db, key)
            if not row:
                raise HTTPException(status_code=401, detail="Invalid API key")
            allowed, used, limit = check_key_rate_limit(db, key)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded ({used}/{limit} requests today)"
                )
            increment_key_usage(db, key)
            return True, key
        else:
            ip = request.client.host if request.client else "unknown"
            if not check_ip_rate_limit(db, ip, limit=20):
                raise HTTPException(
                    status_code=429,
                    detail="Anonymous rate limit exceeded (20 req/day). Register for a free API key at /api/v1/register"
                )
            return False, None
    finally:
        db.close()


@router.get("/port/{port}")
def get_port(port: int, request: Request):
    if not (0 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Port must be 0–65535")
    _auth(request)
    db = get_db()
    try:
        return analyze_port(port, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/ports")
def get_ports(
    request: Request,
    q: str = Query(..., description="Comma-separated ports and/or ranges: 22,443,8080-8090"),
):
    _auth(request)
    try:
        ports = parse_port_input(q)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(ports) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 ports per request")

    db = get_db()
    try:
        return {"ports": analyze_ports(ports, db)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/search")
def search_by_service(
    request: Request,
    service: str = Query(..., description="Service name (e.g. 'ssh', 'http', 'mysql')"),
):
    _auth(request)
    from port_analyzer.sources.iana import PORT_SEARCH_TERMS
    service = service.strip().lower()

    matched_ports = [
        port for port, terms in PORT_SEARCH_TERMS.items()
        if service in [t.lower() for t in terms]
    ]

    if not matched_ports:
        return {"service": service, "ports": [], "message": "No known ports found for this service"}

    db = get_db()
    try:
        results = analyze_ports(matched_ports[:10], db)
        return {"service": service, "ports": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}

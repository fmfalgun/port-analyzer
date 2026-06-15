"""
VARIoT — IoT-specific vulnerability and exploit database by CIRCL (Luxembourg).
API: https://www.variot.eu/api/v1/
No API key required. Finds IoT CVEs that NVD frequently misses or under-enriches.
"""

import time
import requests
from port_analyzer.cache import (
    get_db, upsert_variot_vuln, get_variot_vulns, is_stale, update_fetch_log
)

VARIOT_BASE = "https://www.variot.eu/api/v1"
REQ_SLEEP   = 1.0
MAX_RESULTS = 50


def fetch_variot_for_port(port: int, search_terms: list[str], db=None) -> int:
    """
    Search VARIoT for IoT vulnerabilities matching this port's service names.
    Stores results in variot_vulns table. Returns count of new entries stored.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "variot", max_age_hours=48):
            return 0

        total = 0
        seen_ids: set[str] = set()

        for term in search_terms[:3]:   # cap at 3 terms to avoid too many calls
            try:
                resp = requests.get(
                    f"{VARIOT_BASE}/vulnerabilities/",
                    params={"search": term, "format": "json", "limit": MAX_RESULTS},
                    timeout=15,
                )
                if resp.status_code != 200:
                    time.sleep(REQ_SLEEP)
                    continue

                data    = resp.json()
                results = data if isinstance(data, list) else data.get("results", [])

                for item in results:
                    if not isinstance(item, dict):
                        continue

                    variot_id = str(item.get("id") or item.get("cve") or "")
                    if not variot_id or variot_id in seen_ids:
                        continue
                    seen_ids.add(variot_id)

                    cve_id  = item.get("cve") or item.get("cve_id") or None
                    # Normalise: skip entries with no CVE ID — not useful for cross-ref
                    if not cve_id or not cve_id.startswith("CVE-"):
                        cve_id = None

                    upsert_variot_vuln(
                        db,
                        variot_id   = variot_id,
                        port        = port,
                        cve_id      = cve_id,
                        title       = item.get("title") or item.get("summary") or None,
                        description = item.get("description") or None,
                        cvss_score  = _to_float(item.get("cvss") or item.get("cvss_score")),
                        published   = item.get("published") or item.get("published_at") or None,
                        affected    = _stringify(item.get("affected") or item.get("products")),
                    )
                    total += 1

                time.sleep(REQ_SLEEP)

            except requests.RequestException:
                continue
            except (ValueError, KeyError):
                continue

        if total:
            update_fetch_log(db, port, "variot")

        return total

    finally:
        if close:
            db.close()


def get_variot_for_port(port: int, db=None) -> list[dict]:
    """Return stored VARIoT vulns for this port."""
    close = False
    if db is None:
        db = get_db()
        close = True
    try:
        return get_variot_vulns(db, port)
    finally:
        if close:
            db.close()


def _to_float(val) -> float | None:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _stringify(val) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        return val
    import json
    try:
        return json.dumps(val)
    except (TypeError, ValueError):
        return str(val)

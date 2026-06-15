"""
CISA Known Exploited Vulnerabilities (KEV) feed.
Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
No API key required. Full JSON blob, cached 24h locally, filtered per-port by CVE ID.
"""

import requests
from port_analyzer.cache import (
    get_db, get_cisa_kev_cache, set_cisa_kev_cache, mark_cve_kev, get_cves
)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _fetch_kev_blob(db) -> dict | None:
    cached = get_cisa_kev_cache(db)
    if cached:
        return cached

    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        set_cisa_kev_cache(db, data)
        return data
    except requests.RequestException:
        return None


def apply_kev_to_port(port: int, db=None) -> list[str]:
    """
    Downloads CISA KEV (or uses cache), cross-references CVEs stored for this
    port, marks matching ones as exploited_in_wild=1. Returns list of KEV CVE IDs
    found for this port.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        blob = _fetch_kev_blob(db)
        if not blob:
            return []

        kev_ids = {v["cveID"] for v in blob.get("vulnerabilities", [])}

        stored_cves = get_cves(db, port)
        port_cve_ids = [r["cve_id"] for r in stored_cves]

        hits = [cve_id for cve_id in port_cve_ids if cve_id in kev_ids]
        if hits:
            mark_cve_kev(db, hits)

        return hits

    finally:
        if close:
            db.close()


def get_kev_details(port: int, db=None) -> list[dict]:
    """Return full KEV metadata for CVEs associated with this port."""
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        blob = _fetch_kev_blob(db)
        if not blob:
            return []

        stored_cves = get_cves(db, port)
        port_cve_ids = {r["cve_id"] for r in stored_cves}

        return [
            v for v in blob.get("vulnerabilities", [])
            if v["cveID"] in port_cve_ids
        ]

    finally:
        if close:
            db.close()

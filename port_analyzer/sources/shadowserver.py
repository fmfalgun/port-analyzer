"""
Shadowserver — real-time active exploitation / scanning data for CVEs.
API: https://transform.shadowserver.org/api2/cve-summary?cve={cve_id}
Requires SHADOWSERVER_API_KEY environment variable. No-op if key is absent.
Data decays fast — stale at 6h.
"""

import os
import time
import requests
from port_analyzer.cache import (
    get_db, get_cves, update_cve_shadowserver, is_stale, update_fetch_log,
)

SHADOWSERVER_API  = "https://transform.shadowserver.org/api2/cve-summary"
SHADOWSERVER_KEY  = os.getenv("SHADOWSERVER_API_KEY", "")
MAX_CVES          = 20    # only check top CVEs by CVSS
REQ_SLEEP         = 1.0   # seconds between requests


def fetch_shadowserver_for_port(port: int, db=None) -> int:
    """
    Fetch Shadowserver scanning/exploitation counts for the top CVEs stored
    for this port. Updates shadowserver_count and shadowserver_updated_at on
    each CVE row.
    Returns the count of CVEs that have active scanning data (count > 0).
    Fully no-op (returns 0) when SHADOWSERVER_API_KEY is not set.
    """
    if not SHADOWSERVER_KEY:
        return 0

    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "shadowserver", max_age_hours=6):
            return 0

        cves = get_cves(db, port)
        if not cves:
            return 0

        # Only check top N CVEs by CVSS score
        sorted_cves = sorted(cves, key=lambda r: r["cvss_score"] or 0, reverse=True)
        checked = 0
        hits    = 0

        for row in sorted_cves[:MAX_CVES]:
            cve_id = row["cve_id"]
            try:
                resp = requests.get(
                    SHADOWSERVER_API,
                    params={
                        "cve":    cve_id,
                        "apikey": SHADOWSERVER_KEY,
                    },
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()

                count = data.get("count", 0) or 0
                update_cve_shadowserver(db, cve_id, int(count))
                if count > 0:
                    hits += 1

                checked += 1
                time.sleep(REQ_SLEEP)

            except requests.RequestException:
                continue

        if checked:
            update_fetch_log(db, port, "shadowserver")

        return hits

    except Exception:
        return 0

    finally:
        if close:
            db.close()

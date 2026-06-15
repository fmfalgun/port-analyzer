"""
EPSS (Exploit Prediction Scoring System) from FIRST.org.
API: https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY,CVE-XXXX-ZZZZ
No API key required. Scores refresh daily — we update stored CVEs.
"""

import time
import requests
from port_analyzer.cache import get_db, get_cves, update_cve_epss, is_stale, update_fetch_log

EPSS_API = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100


def fetch_epss_for_port(port: int, db=None) -> int:
    """
    Fetch EPSS scores for all CVEs stored for this port.
    Only runs if scores are older than 24h. Returns count updated.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "epss", max_age_hours=24):
            return 0

        cves = get_cves(db, port)
        if not cves:
            return 0

        cve_ids = [r["cve_id"] for r in cves]
        updated = 0

        for i in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[i:i + BATCH_SIZE]
            try:
                resp = requests.get(
                    EPSS_API,
                    params={"cve": ",".join(batch)},
                    timeout=20
                )
                resp.raise_for_status()
                data = resp.json()

                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    score  = float(item.get("epss", 0))
                    pct    = float(item.get("percentile", 0))
                    if cve_id:
                        update_cve_epss(db, cve_id, score, pct)
                        updated += 1

                time.sleep(1)

            except requests.RequestException:
                continue

        if updated:
            update_fetch_log(db, port, "epss")

        return updated

    finally:
        if close:
            db.close()

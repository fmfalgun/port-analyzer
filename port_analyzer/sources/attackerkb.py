"""
AttackerKB — crowd-sourced practitioner assessments of exploitation difficulty.
API: https://api.attackerkb.com/v1/assessments?ext-cve={cve_id}
No API key required. Returns attacker-value (0-5) and exploitability scores.
"""

import time
import requests
from port_analyzer.cache import (
    get_db, get_cves, update_cve_attackerkb, is_stale, update_fetch_log,
)

AKB_API    = "https://api.attackerkb.com/v1/assessments"
MAX_CVES   = 20    # only check top CVEs by CVSS
REQ_SLEEP  = 0.5   # seconds between requests


def fetch_attackerkb_for_port(port: int, db=None) -> int:
    """
    Fetch AttackerKB assessments for the top CVEs stored for this port.
    Updates attackerkb_score and attackerkb_url on each CVE row.
    Returns the count of CVEs that have at least one AKB assessment.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "attackerkb", max_age_hours=24):
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
                    AKB_API,
                    params={"ext-cve": cve_id},
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()

                assessments = data.get("data", [])
                if assessments:
                    # Use the highest attacker-value across all assessments
                    best = max(assessments, key=lambda a: a.get("attacker-value") or 0)
                    score = best.get("attacker-value")
                    topic = best.get("topic") or {}
                    url   = topic.get("href") or f"https://attackerkb.com/topics/cve/{cve_id}"
                    if score is not None:
                        update_cve_attackerkb(db, cve_id, float(score), url)
                        hits += 1
                    else:
                        update_cve_attackerkb(db, cve_id, None, None)
                else:
                    update_cve_attackerkb(db, cve_id, None, None)

                checked += 1
                time.sleep(REQ_SLEEP)

            except requests.RequestException:
                continue

        if checked:
            update_fetch_log(db, port, "attackerkb")

        return hits

    except Exception:
        return 0

    finally:
        if close:
            db.close()

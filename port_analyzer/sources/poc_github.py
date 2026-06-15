"""
PoC-in-GitHub (nomi-sec) — public PoC availability for CVEs.
Source: https://github.com/nomi-sec/PoC-in-GitHub
URL pattern: https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{YYYY}/{CVE-ID}.json
No API key required. Returns 404 when no PoC exists, JSON array when it does.
"""

import json
import time
import requests
from port_analyzer.cache import get_db, get_cves, update_cve_poc, is_stale, update_fetch_log

RAW_BASE  = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
MAX_CVES  = 20   # only check top CVEs by CVSS — avoids hammering GitHub CDN
REQ_SLEEP = 0.5  # seconds between requests


def fetch_poc_for_port(port: int, db=None) -> int:
    """
    Check nomi-sec PoC-in-GitHub for the top CVEs stored for this port.
    Updates poc_count and poc_urls on each CVE row.
    Returns the count of CVEs with at least one public PoC.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "poc_github", max_age_hours=24):
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
            parts  = cve_id.split("-")
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            year = parts[1]

            url = f"{RAW_BASE}/{year}/{cve_id}.json"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 404:
                    update_cve_poc(db, cve_id, 0, [])
                elif resp.status_code == 200:
                    repos    = resp.json()
                    poc_list = [
                        {
                            "url":   r.get("html_url", ""),
                            "stars": r.get("stargazers_count", 0),
                            "name":  r.get("full_name", ""),
                        }
                        for r in repos if isinstance(r, dict) and r.get("html_url")
                    ]
                    update_cve_poc(db, cve_id, len(poc_list), poc_list)
                    if poc_list:
                        hits += 1
                # other status codes (rate limit, server error): skip silently
                checked += 1
                time.sleep(REQ_SLEEP)
            except requests.RequestException:
                continue

        if checked:
            update_fetch_log(db, port, "poc_github")

        return hits

    finally:
        if close:
            db.close()

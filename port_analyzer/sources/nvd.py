"""
NVD API 2.0 — incremental CVE fetching with cursor.
Docs: https://nvd.nist.gov/developers/vulnerabilities
Free API key: https://nvd.nist.gov/developers/request-an-api-key

Smart fetch: on first call fetches all historical CVEs for this port's services.
On subsequent calls, only fetches CVEs published after the last cursor date.
"""

import os
import time
import requests
from datetime import datetime, timezone, timedelta
from port_analyzer.cache import (
    get_db, upsert_cve, is_stale, update_fetch_log, get_fetch_log
)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

RESULTS_PER_PAGE = 100
RATE_SLEEP = 6.5 if not NVD_API_KEY else 0.6


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_cvss(vuln: dict) -> tuple[float | None, str | None]:
    metrics = vuln.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score  = data.get("baseScore")
            vector = data.get("vectorString")
            return score, vector
    return None, None


def _fetch_page(keyword: str, start_index: int, pub_start: str | None,
                pub_end: str | None) -> dict:
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex":     start_index,
    }
    if pub_start:
        params["pubStartDate"] = pub_start
    if pub_end:
        params["pubEndDate"] = pub_end

    time.sleep(RATE_SLEEP)
    resp = requests.get(NVD_BASE, params=params, headers=_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_nvd_for_port(port: int, search_terms: list[str], db=None) -> int:
    """
    Fetch CVEs from NVD for the given port using search_terms.
    Uses cursor to only fetch new CVEs on repeat calls.
    Returns count of new CVEs stored.
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        stale = is_stale(db, port, "nvd", max_age_hours=24)
        if not stale:
            return 0

        log = get_fetch_log(db, port, "nvd")
        cursor = log["cursor"] if log else None

        pub_start = cursor
        pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        total_new = 0

        for term in search_terms:
            start_index = 0
            while True:
                try:
                    data = _fetch_page(term, start_index, pub_start, pub_end)
                except requests.RequestException:
                    break

                vulns = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                for item in vulns:
                    cve_obj   = item.get("cve", {})
                    cve_id    = cve_obj.get("id", "")
                    if not cve_id:
                        continue

                    descs      = cve_obj.get("descriptions", [])
                    desc       = next((d["value"] for d in descs if d.get("lang") == "en"), None)
                    published  = cve_obj.get("published")
                    score, vector = _parse_cvss(cve_obj)
                    severity   = _severity_from_score(score)

                    upsert_cve(db, port, cve_id, score, vector, severity, desc, published)
                    total_new += 1

                start_index += RESULTS_PER_PAGE
                if start_index >= total_results:
                    break

        update_fetch_log(db, port, "nvd", cursor=pub_end)
        return total_new

    finally:
        if close:
            db.close()

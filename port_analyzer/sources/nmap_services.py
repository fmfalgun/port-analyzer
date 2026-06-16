"""
nmap-services — real-world port popularity/frequency data maintained by
the nmap project. Free flat text file, no key required. Cached whole for
~30 days; "frequency" is how often that port shows up open across
internet-wide scans (0.0-1.0), giving a live "how common is this port"
stat instead of a hardcoded guess.
"""

import re
import requests
from port_analyzer.cache import get_nmap_services_cache, set_nmap_services_cache, upsert_port_history

NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"

_LINE_RE = re.compile(r"^(\S+)\s+(\d+)/(tcp|udp|sctp)\s+([\d.]+)")


def _fetch_raw() -> str:
    resp = requests.get(NMAP_SERVICES_URL, timeout=20)
    resp.raise_for_status()
    return resp.text


def _max_frequency_for_port(raw_text: str, port: int) -> float | None:
    best = None
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        _, port_str, _, freq_str = m.groups()
        if int(port_str) != port:
            continue
        try:
            freq = float(freq_str)
        except ValueError:
            continue
        if best is None or freq > best:
            best = freq
    return best


def fetch_nmap_popularity_for_port(port: int, db=None) -> None:
    """
    Idempotent, never raises. Ensures the nmap-services file is cached
    (refetching if stale/missing), then upserts this port's max frequency
    into port_history if found.
    """
    if db is None:
        return
    try:
        raw = get_nmap_services_cache(db)
        if raw is None:
            raw = _fetch_raw()
            if raw:
                set_nmap_services_cache(db, raw)

        if not raw:
            return

        freq = _max_frequency_for_port(raw, port)
        if freq is not None:
            upsert_port_history(db, port, popularity_freq=freq)

    except Exception as exc:
        print(f"[!] nmap_services: failed for port {port}: {exc}")

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


def _record_for_port(raw_text: str, port: int) -> dict | None:
    """
    Scan the whole nmap-services file for every line matching this port
    (any protocol) and return the full record: per-protocol frequency,
    service name, and inline comment. Returns None if the port has no
    entries at all.
    """
    record = {"tcp": None, "udp": None, "sctp": None, "service_name": None, "comment": None}

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _LINE_RE.match(stripped)
        if not m:
            continue
        name, port_str, proto, freq_str = m.groups()
        if int(port_str) != port:
            continue
        try:
            freq = float(freq_str)
        except ValueError:
            continue

        if record[proto] is None or freq > record[proto]:
            record[proto] = freq
        if record["service_name"] is None:
            record["service_name"] = name

        rest = stripped[m.end():]
        if "#" in rest and not record["comment"]:
            comment = rest.split("#", 1)[1].strip()
            if comment:
                record["comment"] = comment

    if record["tcp"] is None and record["udp"] is None and record["sctp"] is None:
        return None
    return record


def fetch_nmap_popularity_for_port(port: int, db=None) -> None:
    """
    Idempotent, never raises. Ensures the nmap-services file is cached
    (refetching if stale/missing), then upserts this port's full record
    (per-protocol frequency, service name, comment) into port_history.
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

        record = _record_for_port(raw, port)
        if record is None:
            return

        freqs = [v for v in (record["tcp"], record["udp"], record["sctp"]) if v is not None]
        max_freq = max(freqs) if freqs else None

        upsert_port_history(
            db, port,
            popularity_freq=max_freq,
            nmap_tcp_freq=record["tcp"],
            nmap_udp_freq=record["udp"],
            nmap_sctp_freq=record["sctp"],
            nmap_service_name=record["service_name"],
            nmap_comment=record["comment"],
        )

    except Exception as exc:
        print(f"[!] nmap_services: failed for port {port}: {exc}")

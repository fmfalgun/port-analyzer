"""
MITRE ATT&CK technique seeding.
Uses the curated seed map from iana.py for fast offline operation.
Optionally refreshes from the STIX GitHub bundle (large download, ~60MB).
"""

from port_analyzer.cache import (
    get_db, get_techniques, upsert_technique, is_stale, update_fetch_log
)
from port_analyzer.sources.iana import get_techniques_seed

ATTACK_BASE = "https://attack.mitre.org/techniques/"


def seed_techniques_for_port(port: int, db=None) -> int:
    """
    Write ATT&CK techniques from the static seed map into the DB.
    Runs once per port (seed is immutable).
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "mitre", max_age_hours=8760):
            return 0

        entries = get_techniques_seed(port)
        if not entries:
            update_fetch_log(db, port, "mitre")
            return 0

        for technique_id, name, tactic in entries:
            url = f"{ATTACK_BASE}{technique_id.replace('.', '/')}/"
            upsert_technique(db, port, technique_id, name, tactic, url)

        update_fetch_log(db, port, "mitre")
        return len(entries)

    finally:
        if close:
            db.close()


def get_techniques_for_port(port: int, db=None) -> list[dict]:
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        rows = get_techniques(db, port)
        return [dict(r) for r in rows]
    finally:
        if close:
            db.close()

import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "db/port_analyzer.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS port_profiles (
    port        INTEGER NOT NULL,
    transport   TEXT    NOT NULL,
    service_name TEXT,
    description  TEXT,
    iana_status  TEXT,
    fetched_at   TEXT NOT NULL,
    PRIMARY KEY (port, transport)
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    port                INTEGER NOT NULL,
    cvss_score          REAL,
    cvss_vector         TEXT,
    cvss_severity       TEXT,
    epss_score          REAL,
    epss_percentile     REAL,
    exploit_type        TEXT,
    exploited_in_wild   INTEGER DEFAULT 0,
    description         TEXT,
    published_at        TEXT,
    fetched_at          TEXT,
    epss_updated_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_port ON cves(port);

CREATE TABLE IF NOT EXISTS techniques (
    technique_id TEXT NOT NULL,
    port         INTEGER NOT NULL,
    name         TEXT,
    tactic       TEXT,
    url          TEXT,
    fetched_at   TEXT,
    PRIMARY KEY (technique_id, port)
);

CREATE TABLE IF NOT EXISTS fetch_log (
    port         INTEGER NOT NULL,
    source       TEXT NOT NULL,
    last_fetched TEXT,
    cursor       TEXT,
    PRIMARY KEY (port, source)
);

CREATE TABLE IF NOT EXISTS cisa_kev_cache (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    fetched_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exploitdb_cache (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    fetched_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS variot_vulns (
    variot_id   TEXT NOT NULL,
    port        INTEGER NOT NULL,
    cve_id      TEXT,
    title       TEXT,
    description TEXT,
    cvss_score  REAL,
    published   TEXT,
    affected    TEXT,
    fetched_at  TEXT NOT NULL,
    PRIMARY KEY (variot_id, port)
);

CREATE INDEX IF NOT EXISTS idx_variot_port ON variot_vulns(port);

CREATE TABLE IF NOT EXISTS api_keys (
    key              TEXT PRIMARY KEY,
    email            TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL,
    last_used        TEXT,
    requests_today   INTEGER DEFAULT 0,
    rate_limit       INTEGER DEFAULT 1000,
    reset_date       TEXT
);

CREATE TABLE IF NOT EXISTS rate_limit_ip (
    ip           TEXT NOT NULL,
    date         TEXT NOT NULL,
    requests     INTEGER DEFAULT 0,
    PRIMARY KEY (ip, date)
);
"""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _migrate(db: sqlite3.Connection):
    """Add columns introduced after initial schema without dropping existing data."""
    new_cols = [
        # Tier 1 — PoC-in-GitHub
        ("cves", "poc_count",             "INTEGER DEFAULT 0"),
        ("cves", "poc_urls",              "TEXT"),
        ("cves", "poc_checked_at",        "TEXT"),
        # Tier 2 — AttackerKB
        ("cves", "attackerkb_score",      "REAL"),
        ("cves", "attackerkb_url",        "TEXT"),
        # Tier 2 — Exploit-DB
        ("cves", "exploitdb_count",       "INTEGER DEFAULT 0"),
        ("cves", "exploitdb_ids",         "TEXT"),
        # Tier 2 — Shadowserver
        ("cves", "shadowserver_count",    "INTEGER"),
        ("cves", "shadowserver_updated_at", "TEXT"),
    ]
    for table, col, typedef in new_cols:
        try:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
            db.commit()
        except sqlite3.OperationalError:
            pass  # column already exists


def get_db(path: str = DB_PATH) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    db.commit()
    _migrate(db)
    return db


# ── port profiles ──────────────────────────────────────────────────────────────

def get_port_profile(db: sqlite3.Connection, port: int) -> list[sqlite3.Row]:
    return db.execute(
        "SELECT * FROM port_profiles WHERE port=?", (port,)
    ).fetchall()


def upsert_port_profile(db: sqlite3.Connection, port: int, transport: str,
                         service_name: str, description: str, iana_status: str):
    db.execute("""
        INSERT INTO port_profiles (port, transport, service_name, description, iana_status, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(port, transport) DO UPDATE SET
            service_name = excluded.service_name,
            description  = excluded.description,
            iana_status  = excluded.iana_status,
            fetched_at   = excluded.fetched_at
    """, (port, transport, service_name, description, iana_status, now_utc()))
    db.commit()


# ── CVEs ───────────────────────────────────────────────────────────────────────

def get_cves(db: sqlite3.Connection, port: int) -> list[sqlite3.Row]:
    return db.execute("""
        SELECT * FROM cves WHERE port=?
        ORDER BY cvss_score DESC NULLS LAST
    """, (port,)).fetchall()


def upsert_cve(db: sqlite3.Connection, port: int, cve_id: str, cvss_score: float | None,
               cvss_vector: str | None, cvss_severity: str | None, description: str | None,
               published_at: str | None):
    db.execute("""
        INSERT INTO cves (cve_id, port, cvss_score, cvss_vector, cvss_severity,
                          description, published_at, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            cvss_score    = excluded.cvss_score,
            cvss_vector   = excluded.cvss_vector,
            cvss_severity = excluded.cvss_severity,
            description   = excluded.description,
            published_at  = excluded.published_at,
            fetched_at    = excluded.fetched_at
    """, (cve_id, port, cvss_score, cvss_vector, cvss_severity,
          description, published_at, now_utc()))
    db.commit()


def update_cve_epss(db: sqlite3.Connection, cve_id: str, epss_score: float, epss_percentile: float):
    db.execute("""
        UPDATE cves SET epss_score=?, epss_percentile=?, epss_updated_at=?
        WHERE cve_id=?
    """, (epss_score, epss_percentile, now_utc(), cve_id))
    db.commit()


def mark_cve_kev(db: sqlite3.Connection, cve_ids: list[str]):
    if not cve_ids:
        return
    placeholders = ",".join("?" * len(cve_ids))
    db.execute(
        f"UPDATE cves SET exploited_in_wild=1 WHERE cve_id IN ({placeholders})",
        cve_ids
    )
    db.commit()


# ── techniques ─────────────────────────────────────────────────────────────────

def get_techniques(db: sqlite3.Connection, port: int) -> list[sqlite3.Row]:
    return db.execute(
        "SELECT * FROM techniques WHERE port=?", (port,)
    ).fetchall()


def upsert_technique(db: sqlite3.Connection, port: int, technique_id: str,
                     name: str, tactic: str, url: str):
    db.execute("""
        INSERT INTO techniques (technique_id, port, name, tactic, url, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(technique_id, port) DO UPDATE SET
            name       = excluded.name,
            tactic     = excluded.tactic,
            url        = excluded.url,
            fetched_at = excluded.fetched_at
    """, (technique_id, port, name, tactic, url, now_utc()))
    db.commit()


# ── fetch log (smart cache staleness) ──────────────────────────────────────────

def get_fetch_log(db: sqlite3.Connection, port: int, source: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM fetch_log WHERE port=? AND source=?", (port, source)
    ).fetchone()


def update_fetch_log(db: sqlite3.Connection, port: int, source: str, cursor: str | None = None):
    db.execute("""
        INSERT INTO fetch_log (port, source, last_fetched, cursor)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(port, source) DO UPDATE SET
            last_fetched = excluded.last_fetched,
            cursor       = COALESCE(excluded.cursor, fetch_log.cursor)
    """, (port, source, now_utc(), cursor))
    db.commit()


def is_stale(db: sqlite3.Connection, port: int, source: str, max_age_hours: int) -> bool:
    row = get_fetch_log(db, port, source)
    if not row or not row["last_fetched"]:
        return True
    last = datetime.fromisoformat(row["last_fetched"].replace("Z", "+00:00"))
    age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
    return age_hours > max_age_hours


# ── CISA KEV blob cache ────────────────────────────────────────────────────────

def get_cisa_kev_cache(db: sqlite3.Connection) -> dict | None:
    row = db.execute("SELECT * FROM cisa_kev_cache WHERE id=1").fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00"))
    age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
    if age_hours > 24:
        return None
    return json.loads(row["data"])


def set_cisa_kev_cache(db: sqlite3.Connection, data: dict):
    db.execute("""
        INSERT INTO cisa_kev_cache (id, fetched_at, data) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET fetched_at=excluded.fetched_at, data=excluded.data
    """, (now_utc(), json.dumps(data)))
    db.commit()


# ── API keys ───────────────────────────────────────────────────────────────────

def get_api_key(db: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()


def create_api_key(db: sqlite3.Connection, email: str, key: str, rate_limit: int = 1000):
    db.execute("""
        INSERT INTO api_keys (key, email, created_at, rate_limit, reset_date)
        VALUES (?, ?, ?, ?, ?)
    """, (key, email, now_utc(), rate_limit, today_utc()))
    db.commit()


def email_exists(db: sqlite3.Connection, email: str) -> bool:
    row = db.execute("SELECT 1 FROM api_keys WHERE email=?", (email,)).fetchone()
    return row is not None


def increment_key_usage(db: sqlite3.Connection, key: str):
    today = today_utc()
    row = db.execute("SELECT reset_date, requests_today FROM api_keys WHERE key=?", (key,)).fetchone()
    if not row:
        return
    if row["reset_date"] != today:
        db.execute(
            "UPDATE api_keys SET requests_today=1, reset_date=?, last_used=? WHERE key=?",
            (today, now_utc(), key)
        )
    else:
        db.execute(
            "UPDATE api_keys SET requests_today=requests_today+1, last_used=? WHERE key=?",
            (now_utc(), key)
        )
    db.commit()


def check_key_rate_limit(db: sqlite3.Connection, key: str) -> tuple[bool, int, int]:
    """Returns (allowed, used, limit)."""
    today = today_utc()
    row = db.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    if not row:
        return False, 0, 0
    used = row["requests_today"] if row["reset_date"] == today else 0
    return used < row["rate_limit"], used, row["rate_limit"]


# ── IP rate limiting (no-key requests) ────────────────────────────────────────

# ── PoC-in-GitHub ─────────────────────────────────────────────────────────────

def update_cve_poc(db: sqlite3.Connection, cve_id: str, poc_count: int, poc_list: list):
    db.execute("""
        UPDATE cves SET poc_count=?, poc_urls=?, poc_checked_at=?
        WHERE cve_id=?
    """, (poc_count, json.dumps(poc_list), now_utc(), cve_id))
    db.commit()


# ── VARIoT ────────────────────────────────────────────────────────────────────

def upsert_variot_vuln(db: sqlite3.Connection, variot_id: str, port: int,
                       cve_id: str | None, title: str | None, description: str | None,
                       cvss_score: float | None, published: str | None, affected: str | None):
    db.execute("""
        INSERT INTO variot_vulns
            (variot_id, port, cve_id, title, description, cvss_score, published, affected, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(variot_id, port) DO UPDATE SET
            cve_id      = excluded.cve_id,
            title       = excluded.title,
            description = excluded.description,
            cvss_score  = excluded.cvss_score,
            published   = excluded.published,
            affected    = excluded.affected,
            fetched_at  = excluded.fetched_at
    """, (variot_id, port, cve_id, title, description, cvss_score, published, affected, now_utc()))
    db.commit()


def get_variot_vulns(db: sqlite3.Connection, port: int) -> list[dict]:
    rows = db.execute("""
        SELECT * FROM variot_vulns WHERE port=?
        ORDER BY cvss_score DESC NULLS LAST
    """, (port,)).fetchall()
    return [dict(r) for r in rows]


# ── AttackerKB ────────────────────────────────────────────────────────────────

def update_cve_attackerkb(db: sqlite3.Connection, cve_id: str,
                           score: float | None, url: str | None):
    db.execute("""
        UPDATE cves SET attackerkb_score=?, attackerkb_url=?
        WHERE cve_id=?
    """, (score, url, cve_id))
    db.commit()


# ── Exploit-DB ────────────────────────────────────────────────────────────────

def get_exploitdb_cache(db: sqlite3.Connection) -> str | None:
    """Return cached CSV text if less than 24h old, else None."""
    row = db.execute("SELECT * FROM exploitdb_cache WHERE id=1").fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00"))
    age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
    if age_hours > 24:
        return None
    return row["data"]


def set_exploitdb_cache(db: sqlite3.Connection, csv_text: str):
    db.execute("""
        INSERT INTO exploitdb_cache (id, fetched_at, data) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET fetched_at=excluded.fetched_at, data=excluded.data
    """, (now_utc(), csv_text))
    db.commit()


def update_cve_exploitdb(db: sqlite3.Connection, cve_id: str,
                          count: int, ids_list: list):
    db.execute("""
        UPDATE cves SET exploitdb_count=?, exploitdb_ids=?
        WHERE cve_id=?
    """, (count, json.dumps(ids_list), cve_id))
    db.commit()


# ── Shadowserver ───────────────────────────────────────────────────────────────

def update_cve_shadowserver(db: sqlite3.Connection, cve_id: str, count: int):
    db.execute("""
        UPDATE cves SET shadowserver_count=?, shadowserver_updated_at=?
        WHERE cve_id=?
    """, (count, now_utc(), cve_id))
    db.commit()


# ── IP rate limiting (no-key requests) ────────────────────────────────────────

def check_ip_rate_limit(db: sqlite3.Connection, ip: str, limit: int = 20) -> bool:
    today = today_utc()
    row = db.execute(
        "SELECT requests FROM rate_limit_ip WHERE ip=? AND date=?", (ip, today)
    ).fetchone()
    if not row:
        db.execute(
            "INSERT INTO rate_limit_ip (ip, date, requests) VALUES (?, ?, 1)",
            (ip, today)
        )
        db.commit()
        return True
    if row["requests"] >= limit:
        return False
    db.execute(
        "UPDATE rate_limit_ip SET requests=requests+1 WHERE ip=? AND date=?",
        (ip, today)
    )
    db.commit()
    return True

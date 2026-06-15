#!/usr/bin/env python3
"""
build_data.py — Fetch port intelligence for a curated list of high-value ports
and write the result to web/data/ports.json (or a custom output path).

Usage:
    python scripts/build_data.py                    # build all PORT_LIST
    python scripts/build_data.py --ports 22,443,80  # specific ports only
    python scripts/build_data.py --ports 22-90      # range
    python scripts/build_data.py --no-live          # cache only, no API calls
    python scripts/build_data.py --output path/to/custom.json
    python scripts/build_data.py --db path/to/db    # custom SQLite path
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

# ── Curated port list ──────────────────────────────────────────────────────────

WELL_KNOWN = [
    20, 21, 22, 23, 25, 53, 67, 69, 80, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465,
    502, 514, 515, 587, 631, 636, 873, 902, 993, 995,
]
REGISTERED = [
    1080, 1194, 1433, 1521, 1883, 2049, 2181, 2375, 2376,
    3000, 3306, 3389, 3690, 4443, 4505, 4506, 4848,
    5000, 5432, 5555, 5601, 5672, 5900, 5901,
    6379, 6443, 7001, 8009, 8080, 8443, 8888,
    9000, 9090, 9200, 9300, 10250, 11211,
    27017, 27018, 27019, 50070,
]
PORT_LIST = sorted(set(WELL_KNOWN + REGISTERED))

# Repo root = one level up from scripts/
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "web" / "data" / "ports.json"
DEFAULT_DB     = REPO_ROOT / "db" / "port_analyzer.db"

SOURCES = ["IANA", "NVD", "CISA KEV", "EPSS", "MITRE ATT&CK"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ports(raw: str) -> list[int]:
    """Accept '22', '22,443', '22-90', or mixed '22,80-90,443'."""
    from port_analyzer.engine import parse_port_input
    return parse_port_input(raw)


def _load_existing(output_path: Path) -> dict:
    """Load existing ports.json so we can merge rather than wipe."""
    if output_path.exists():
        try:
            with output_path.open() as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            print("[!] existing output file is unreadable — starting fresh")
    return {}


def _cache_only_result(port: int, db) -> dict:
    """
    Build a result dict from cache without hitting any live APIs.
    Mirrors the logic in cli.py --no-live mode.
    """
    from port_analyzer.cache import get_port_profile, get_cves, get_techniques
    from port_analyzer.engine import PENTEST_NOTES, DEFENSIVE_NOTES, _risk_level

    profiles  = [dict(r) for r in get_port_profile(db, port)]
    cves_rows = [dict(r) for r in get_cves(db, port)]
    tech_rows = [dict(r) for r in get_techniques(db, port)]
    kev_ids   = {c["cve_id"] for c in cves_rows if c.get("exploited_in_wild")}
    top_cves  = sorted(cves_rows, key=lambda c: c.get("cvss_score") or 0, reverse=True)[:10]
    svc_name  = profiles[0]["service_name"] if profiles else f"port-{port}"

    return {
        "port":            port,
        "service_name":    svc_name,
        "transport":       list({r["transport"] for r in profiles}) or ["TCP"],
        "iana_status":     profiles[0]["iana_status"] if profiles else "Unknown",
        "description":     profiles[0]["description"] if profiles else "",
        "risk_level":      _risk_level(cves_rows, bool(kev_ids)),
        "cve_count":       len(cves_rows),
        "kev_count":       len(kev_ids),
        "top_cves":        top_cves,
        "techniques":      tech_rows,
        "pentest_notes":   PENTEST_NOTES.get(port, []),
        "defensive_notes": DEFENSIVE_NOTES.get(port, []),
        "search_terms":    [],
    }


def _print_summary(results: list[dict]):
    """Print a plain-text summary table (no Rich — CI-friendly)."""
    print()
    print("=" * 70)
    print("  Summary")
    print("=" * 70)
    hdr = f"  {'Port':<8} {'Service':<20} {'Risk':<10} {'CVEs':<6} {'KEV'}"
    print(hdr)
    print("  " + "-" * 60)
    for r in results:
        port    = r["port"]
        svc     = r.get("service_name", f"port-{port}")[:18]
        risk    = r.get("risk_level", "UNKNOWN")
        cve_cnt = r.get("cve_count", 0)
        kev_cnt = r.get("kev_count", 0)
        kev_str = str(kev_cnt) + " [KEV]" if kev_cnt else "0"
        print(f"  {port:<8} {svc:<20} {risk:<10} {cve_cnt:<6} {kev_str}")
    print()


# ── Main CLI ──────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--ports", "ports_raw", default=None,
    help="Ports to build: '22', '22,443', '22-90', or mixed. Defaults to full PORT_LIST.",
)
@click.option(
    "--no-live", "no_live", is_flag=True,
    help="Use SQLite cache only — skip all live API calls.",
)
@click.option(
    "--output", "output_path", default=None,
    help=f"Output JSON file. Default: web/data/ports.json",
)
@click.option(
    "--db", "db_path", default=None,
    help=f"SQLite DB path. Default: db/port_analyzer.db",
)
def main(ports_raw: str | None, no_live: bool, output_path: str | None, db_path: str | None):
    """
    Fetch port intelligence and write web/data/ports.json.

    Reuses port_analyzer.engine.analyze_port() for all data fetching.
    Merges with any existing ports.json so ports not in this run are preserved.
    """
    # ── resolve paths ──────────────────────────────────────────────────────────
    out_path = Path(output_path).resolve() if output_path else DEFAULT_OUTPUT
    db_str   = str(Path(db_path).resolve() if db_path else DEFAULT_DB)

    # Propagate DB path via env so get_db() picks it up without patching
    os.environ["DB_PATH"] = db_str

    # ── resolve port list ──────────────────────────────────────────────────────
    if ports_raw:
        try:
            target_ports = _parse_ports(ports_raw)
        except ValueError as exc:
            print(f"[!] invalid --ports value: {exc}")
            sys.exit(1)
    else:
        target_ports = PORT_LIST

    total = len(target_ports)

    # ── banner ─────────────────────────────────────────────────────────────────
    print(f"[i] port-analyzer — build_data.py")
    print(f"[i] ports to process : {total}")
    print(f"[i] output           : {out_path}")
    print(f"[i] database         : {db_str}")
    if no_live:
        print("[!] --no-live: serving from cache only, skipping API calls")
    print()

    # ── open DB ───────────────────────────────────────────────────────────────
    from port_analyzer.cache import get_db
    db = get_db(db_str)

    # ── load existing output for merge ────────────────────────────────────────
    existing = _load_existing(out_path)
    # Strip _meta so we work with port-keyed entries only
    port_data: dict = {k: v for k, v in existing.items() if k != "_meta"}

    # ── process each port ─────────────────────────────────────────────────────
    results: list[dict] = []
    errors:  list[int]  = []

    for idx, port in enumerate(target_ports, start=1):
        svc_hint = ""  # filled in after success
        print(f"[>] port {idx}/{total} — {port} {svc_hint}...", end="", flush=True)

        try:
            if no_live:
                result = _cache_only_result(port, db)
            else:
                from port_analyzer.engine import analyze_port
                result = analyze_port(port, db)

            svc  = result.get("service_name", f"port-{port}")
            cvec = result.get("cve_count", 0)
            kevc = result.get("kev_count", 0)
            # Overwrite the line we started
            print(f"\r[>] port {idx}/{total} — {port} ({svc})")
            print(f"[+] done ({cvec} CVEs, {kevc} KEV)")

            results.append(result)
            port_data[str(port)] = result

        except Exception as exc:
            print()  # newline after the partial line
            print(f"[!] port {port} failed: {exc}")
            errors.append(port)

    db.close()

    # ── build final JSON structure ────────────────────────────────────────────
    output: dict = {
        "_meta": {
            "generated_at": _now_utc(),
            "port_count":   len(port_data),
            "sources":      SOURCES,
        }
    }
    # Ports in numeric order after _meta
    output.update({k: port_data[k] for k in sorted(port_data, key=lambda x: int(x))})

    # ── write output ──────────────────────────────────────────────────────────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        json.dump(output, fh, indent=2, default=str)

    print()
    print(f"[+] wrote {len(port_data)} port entries → {out_path}")
    if errors:
        print(f"[!] {len(errors)} port(s) failed: {', '.join(map(str, errors))}")

    # ── summary table ─────────────────────────────────────────────────────────
    if results:
        _print_summary(results)


if __name__ == "__main__":
    main()

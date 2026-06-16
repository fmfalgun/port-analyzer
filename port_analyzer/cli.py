#!/usr/bin/env python3
"""
port-analyzer CLI
Usage:
    python -m port_analyzer.cli 22
    python -m port_analyzer.cli 22,443,8080
    python -m port_analyzer.cli 8080-8090
    python -m port_analyzer.cli 22,80-90,443
    python -m port_analyzer.cli 22 --json
    python -m port_analyzer.cli 22 --no-live    (skip live API calls, cache only)
"""

import json
import sys
import os
import click
from rich.console import Console

console = Console()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("ports")
@click.option("--json", "output_json", is_flag=True, help="Output raw JSON (pipe-friendly)")
@click.option("--no-live", is_flag=True, help="Skip live API calls; use cache only")
@click.option("--db", default=None, help="Path to SQLite DB (overrides DB_PATH env var)")
@click.option("--top", default=5, show_default=True, help="Number of CVEs to show per port")
@click.option("--report", "report_path", default=None, metavar="PATH", help="Save a markdown report to PATH")
@click.option("--sync", is_flag=True, help="Push results to GitHub Pages dataset (requires GITHUB_PAT env var)")
def main(ports: str, output_json: bool, no_live: bool, db: str | None, top: int, report_path: str | None, sync: bool):
    """
    Port Analyzer — cybersecurity intelligence for any port or port range.

    PORTS can be a single port, comma-separated list, or range:

    \b
        port-analyzer 22
        port-analyzer 22,443,8080
        port-analyzer 8080-8090
        port-analyzer 22,80-90,443
    """
    from port_analyzer.engine import parse_port_input, analyze_port, analyze_ports
    from port_analyzer import renderer
    from port_analyzer.cache import get_db as _get_db

    if db:
        os.environ["DB_PATH"] = db

    try:
        port_list = parse_port_input(ports)
    except ValueError as e:
        renderer.err(str(e))
        sys.exit(1)

    if not output_json:
        renderer.info(f"port-analyzer v0.1.0  ·  querying {len(port_list)} port(s)")
        renderer.info("sources: IANA · NVD · CISA KEV · EPSS · MITRE ATT&CK · PoC-in-GitHub · VARIoT · Wikipedia · nmap-services")
        if no_live:
            renderer.warn("--no-live: skipping API calls, serving from cache only")
        console.print()

    conn = _get_db()

    if no_live:
        from port_analyzer.cache import (
            get_port_profile, get_cves, get_techniques, get_port_history
        )
        from port_analyzer.engine import PENTEST_NOTES, DEFENSIVE_NOTES, _risk_level

        results = []
        for p in port_list:
            profiles    = [dict(r) for r in get_port_profile(conn, p)]
            cves_rows   = [dict(r) for r in get_cves(conn, p)]
            tech_rows   = [dict(r) for r in get_techniques(conn, p)]
            history_row = get_port_history(conn, p)
            kev_ids   = {c["cve_id"] for c in cves_rows if c.get("exploited_in_wild")}
            top_cves  = sorted(cves_rows, key=lambda c: c.get("cvss_score") or 0, reverse=True)[:top]
            svc_name  = profiles[0]["service_name"] if profiles else f"port-{p}"
            results.append({
                "port":            p,
                "service_name":    svc_name,
                "transport":       list({r["transport"] for r in profiles}) or ["TCP"],
                "iana_status":     profiles[0]["iana_status"] if profiles else "Unknown",
                "description":     profiles[0]["description"] if profiles else "",
                "wiki_description": history_row["wiki_description"] if history_row else None,
                "popularity_freq":  history_row["popularity_freq"]  if history_row else None,
                "wiki_url":           history_row["wiki_url"]           if history_row else None,
                "nmap_tcp_freq":      history_row["nmap_tcp_freq"]      if history_row else None,
                "nmap_udp_freq":      history_row["nmap_udp_freq"]      if history_row else None,
                "nmap_sctp_freq":     history_row["nmap_sctp_freq"]     if history_row else None,
                "nmap_service_name":  history_row["nmap_service_name"]  if history_row else None,
                "nmap_comment":       history_row["nmap_comment"]       if history_row else None,
                "risk_level":      _risk_level(cves_rows, bool(kev_ids)),
                "cve_count":       len(cves_rows),
                "kev_count":       len(kev_ids),
                "top_cves":        top_cves,
                "techniques":      tech_rows,
                "pentest_notes":   PENTEST_NOTES.get(p, []),
                "defensive_notes": DEFENSIVE_NOTES.get(p, []),
                "search_terms":    [],
            })
    else:
        results = []
        for p in port_list:
            if not output_json:
                renderer.action(f"fetching port {p}...")
            try:
                result = analyze_port(p, conn)
                result["top_cves"] = sorted(
                    result.get("top_cves", []),
                    key=lambda c: c.get("cvss_score") or 0,
                    reverse=True
                )[:top]
                results.append(result)
            except Exception as e:
                if not output_json:
                    renderer.err(f"port {p}: {e}")
                else:
                    results.append({"port": p, "error": str(e)})

    conn.close()

    if output_json:
        click.echo(json.dumps(results, indent=2, default=str))
    else:
        renderer.render_ports(results)

    if report_path:
        sections = [renderer.render_markdown(r) for r in results]
        report_text = "\n\n---\n\n".join(sections)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(report_text + "\n")
        from rich.text import Text
        t = Text()
        t.append("[✓] ", style="green")
        t.append(f"Report saved to {report_path}")
        console.print(t)

    if sync and not output_json:
        from port_analyzer.sync import sync_ports
        from rich.text import Text
        renderer.action("syncing to GitHub Pages...")
        ok, msg = sync_ports(results)
        t = Text()
        if ok:
            t.append("[✓] ", style="green")
        else:
            t.append("[✗] ", style="red")
        t.append(msg)
        console.print(t)


if __name__ == "__main__":
    main()

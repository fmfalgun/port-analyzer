"""
Terminal renderer — web-vapt style output using Rich for colour.
Structural format: [i]/[>]/[+]/[✓]/[✗]/[!] prefixes, === headers, ─ dividers.
"""

from rich.console import Console
from rich.text import Text
from rich.rule import Rule

console = Console(highlight=False)

RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}

TACTIC_ABBREV = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Priv. Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "C2",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
    "impair-process-control": "Impair Process",
}


def _tag(color: str, label: str) -> Text:
    t = Text()
    t.append(f"[{label}]", style=color)
    return t


def info(msg: str):
    t = Text()
    t.append("[i] ", style="blue")
    t.append(msg)
    console.print(t)


def action(msg: str):
    t = Text()
    t.append("[>] ", style="cyan")
    t.append(msg)
    console.print(t)


def ok(msg: str):
    t = Text()
    t.append("[+] ", style="green")
    t.append(msg)
    console.print(t)


def warn(msg: str):
    t = Text()
    t.append("[!] ", style="yellow")
    t.append(msg)
    console.print(t)


def err(msg: str):
    t = Text()
    t.append("[!] ", style="bold red")
    t.append(msg)
    console.print(t)


def section(title: str):
    console.print()
    console.rule(f"[bold white]{title}[/bold white]", style="dim white")


def divider():
    console.print("[dim]" + "─" * 70 + "[/dim]")


def render_port(result: dict):
    port        = result["port"]
    svc         = result["service_name"].upper()
    risk        = result["risk_level"]
    risk_color  = RISK_COLOR.get(risk, "white")
    transports  = " / ".join(result.get("transport", ["TCP"]))
    cve_count   = result["cve_count"]
    kev_count   = result["kev_count"]

    section(f"Port {port} — {svc}")

    # Identity block
    console.print(f"  [dim]Transport  :[/dim] {transports}")
    console.print(f"  [dim]IANA Status:[/dim] {result['iana_status']}")
    if result.get("description"):
        console.print(f"  [dim]Description:[/dim] {result['description'][:120]}")

    risk_text = Text()
    risk_text.append("  Risk Level : ", style="dim")
    risk_text.append(f"  {risk}  ", style=f"bold {risk_color} on default")
    console.print(risk_text)

    console.print(
        f"  [dim]CVE Count  :[/dim] {cve_count}   "
        f"[dim]CISA KEV:[/dim] "
        + ("[bold red]" + str(kev_count) + " confirmed exploited[/bold red]"
           if kev_count else "[green]0[/green]")
    )

    # Use cases / description
    if result.get("search_terms"):
        console.print()
        t = Text()
        t.append("[>] ", style="cyan")
        t.append("Common Services / Search Terms")
        console.print(t)
        console.print("    " + " · ".join(result["search_terms"]))

    # Top CVEs
    top_cves = result.get("top_cves", [])
    if top_cves:
        console.print()
        t = Text()
        t.append("[>] ", style="cyan")
        t.append(f"Top CVEs by Severity ({min(len(top_cves), 5)} shown)")
        console.print(t)

        for cve in top_cves[:5]:
            cve_id   = cve["cve_id"]
            score    = cve.get("cvss_score")
            severity = cve.get("cvss_severity") or "?"
            epss     = cve.get("epss_score")
            kev      = cve.get("exploited_in_wild")
            desc     = (cve.get("description") or "")[:80]

            score_str = f"{score:.1f}" if score is not None else "N/A"
            epss_str  = f"EPSS:{epss:.2f}" if epss is not None else ""
            kev_str   = " [bold red][KEV][/bold red]" if kev else ""

            sev_color = SEVERITY_COLOR.get(severity, "white")
            line = Text()
            line.append("    ")
            line.append(f"{cve_id:<20}", style="bold cyan")
            line.append(f"CVSS:{score_str:<5} ", style=sev_color)
            line.append(f"{severity:<9} ", style=sev_color)
            if epss_str:
                line.append(f"{epss_str}  ", style="dim")
            console.print(line, end="")
            if kev:
                console.print("[bold red][KEV][/bold red]", end="")
            console.print()
            if desc:
                console.print(f"    [dim]↳ {desc}[/dim]")

    # ATT&CK techniques
    techniques = result.get("techniques", [])
    if techniques:
        console.print()
        t = Text()
        t.append("[>] ", style="cyan")
        t.append("MITRE ATT&CK Techniques")
        console.print(t)
        for tech in techniques:
            tid    = tech["technique_id"]
            name   = tech["name"]
            tactic = TACTIC_ABBREV.get(tech.get("tactic", ""), tech.get("tactic", ""))
            console.print(f"    [bold cyan]{tid:<14}[/bold cyan] [dim]{tactic:<20}[/dim]  {name}")

    # Pentest notes
    pentest = result.get("pentest_notes", [])
    if pentest:
        console.print()
        t = Text()
        t.append("[>] ", style="cyan")
        t.append("Pentest Notes")
        console.print(t)
        for note in pentest:
            console.print(f"    [dim]·[/dim] {note}")

    # Defensive notes
    defensive = result.get("defensive_notes", [])
    if defensive:
        console.print()
        t = Text()
        t.append("[>] ", style="cyan")
        t.append("Defensive Recommendations")
        console.print(t)
        for note in defensive:
            icon = "[green][✓][/green]" if not note.startswith("Never") and not note.startswith("Disable") else "[red][✗][/red]"
            console.print(f"    {icon} {note}")

    divider()


def render_markdown(result: dict) -> str:
    """Return a markdown-formatted string for a single port analysis result."""
    port       = result["port"]
    svc        = result.get("service_name", f"port-{port}")
    risk       = result.get("risk_level", "LOW")
    transports = ", ".join(result.get("transport", ["TCP"]))
    iana       = result.get("iana_status", "—")
    cve_count  = result.get("cve_count", 0)
    kev_count  = result.get("kev_count", 0)
    desc       = result.get("description", "")

    lines: list[str] = []

    # Title
    lines.append(f"# Port {port} — {svc.lower()} ({risk} RISK)")
    lines.append("")

    # Overview table
    lines.append("## Overview")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Port | {port} |")
    lines.append(f"| Service | {svc.lower()} |")
    lines.append(f"| Transport | {transports} |")
    lines.append(f"| IANA Status | {iana} |")
    lines.append(f"| Risk Level | {risk} |")
    lines.append(f"| CVE Count | {cve_count} |")
    lines.append(f"| KEV Count | {kev_count} |")
    lines.append("")

    # Description
    if desc:
        lines.append("## Description")
        lines.append(desc)
        lines.append("")

    def _nvd_link(cve_id: str) -> str:
        return f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"

    def _mitre_link(tid: str) -> str:
        url_path = tid.replace(".", "/")
        return f"[{tid}](https://attack.mitre.org/techniques/{url_path}/)"

    # Top CVEs
    top_cves = result.get("top_cves", [])
    if top_cves:
        lines.append("## Top CVEs")
        lines.append("| CVE ID | CVSS | EPSS | KEV |")
        lines.append("|---|---|---|---|")
        for cve in top_cves:
            cve_id   = cve.get("cve_id", "—")
            score    = cve.get("cvss_score")
            severity = cve.get("cvss_severity") or "?"
            epss     = cve.get("epss_score")
            kev      = cve.get("exploited_in_wild", False)

            score_str = f"{score:.1f} {severity}" if score is not None else "N/A"
            epss_str  = f"{epss:.2f}" if epss is not None else "—"
            kev_str   = "Yes" if kev else "No"
            cve_cell  = _nvd_link(cve_id) if cve_id != "—" else "—"
            lines.append(f"| {cve_cell} | {score_str} | {epss_str} | {kev_str} |")
        lines.append("")

    # MITRE ATT&CK techniques
    techniques = result.get("techniques", [])
    if techniques:
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("| Technique | Name | Tactic |")
        lines.append("|---|---|---|")
        for tech in techniques:
            tid    = tech.get("technique_id", "—")
            name   = tech.get("name", "—")
            tactic = tech.get("tactic", "—")
            tid_cell = _mitre_link(tid) if tid != "—" else "—"
            lines.append(f"| {tid_cell} | {name} | {tactic} |")
        lines.append("")

    # Pentest notes
    pentest = result.get("pentest_notes", [])
    if pentest:
        lines.append("## Pentest Notes")
        for note in pentest:
            lines.append(f"- {note}")
        lines.append("")

    # Defensive notes
    defensive = result.get("defensive_notes", [])
    if defensive:
        lines.append("## Defensive Notes")
        for note in defensive:
            lines.append(f"- {note}")
        lines.append("")

    # References
    lines.append("## References")
    lines.append(f"- **IANA Service Registry** — <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>")
    lines.append(f"- **NVD (National Vulnerability Database)** — <https://nvd.nist.gov/vuln/search?query=port+{port}&search_type=all>")
    if kev_count:
        lines.append(f"- **CISA Known Exploited Vulnerabilities** — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>")
    lines.append(f"- **EPSS (Exploit Prediction Scoring System)** — <https://www.first.org/epss/>")
    if techniques:
        lines.append(f"- **MITRE ATT&CK** — <https://attack.mitre.org/>")
    for cve in top_cves:
        cve_id = cve.get("cve_id")
        if cve_id:
            lines.append(f"  - {_nvd_link(cve_id)}")
    for tech in techniques:
        tid = tech.get("technique_id")
        name = tech.get("name", "")
        if tid:
            lines.append(f"  - {_mitre_link(tid)} — {name}")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by Port Analyzer — https://github.com/fmfalgun/port-analyzer*")

    return "\n".join(lines)


def render_ports(results: list[dict]):
    for r in results:
        render_port(r)
    console.print()
    summary_table(results)


def summary_table(results: list[dict]):
    if len(results) <= 1:
        return

    section("Summary")
    console.print(
        f"  {'Port':<8} {'Service':<20} {'Transport':<10} "
        f"{'Risk':<10} {'CVEs':<6} {'KEV':<5}"
    )
    console.print("  " + "─" * 65)

    for r in results:
        risk       = r["risk_level"]
        risk_color = RISK_COLOR.get(risk, "white")
        svc        = r["service_name"][:18]
        tp         = "/".join(r.get("transport", ["TCP"]))[:8]

        line = Text()
        line.append("  ")
        line.append(f"{r['port']:<8}", style="bold")
        line.append(f"{svc:<20}")
        line.append(f"{tp:<10}")
        line.append(f"{risk:<10}", style=risk_color)
        line.append(f"{r['cve_count']:<6}")
        if r["kev_count"]:
            line.append(f"{r['kev_count']}", style="bold red")
        else:
            line.append("0")
        console.print(line)
    console.print()

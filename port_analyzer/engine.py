"""
Query engine — orchestrates all sources + cache for a single port.
The CLI, backend API, and web all go through this.
"""

from port_analyzer.cache import get_db, get_port_profile, get_cves, get_techniques
from port_analyzer.sources.iana import fetch_iana_for_port, get_search_terms
from port_analyzer.sources.nvd import fetch_nvd_for_port
from port_analyzer.sources.cisa_kev import apply_kev_to_port, get_kev_details
from port_analyzer.sources.epss import fetch_epss_for_port
from port_analyzer.sources.mitre_attack import seed_techniques_for_port

PENTEST_NOTES: dict[int, list[str]] = {
    21:    ["Anonymous login: ftp <host> (user: anonymous)", "Banner grab: nc -nv <host> 21",
            "Brute force: hydra -l admin -P wordlist.txt ftp://<host>",
            "Tools: nmap -sV -sC -p 21, hydra, medusa, lftp"],
    22:    ["Banner grab: nc -nv <host> 22",
            "Check PasswordAuthentication and PermitRootLogin in sshd_config",
            "Audit keys: ssh-audit <host>",
            "Brute force: hydra -l root -P wordlist.txt ssh://<host>",
            "Tools: ssh-audit, nmap -sV --script ssh*"],
    23:    ["Telnet sends credentials in plaintext — sniff with Wireshark",
            "Brute force: hydra -l admin -P wordlist.txt telnet://<host>",
            "Should never be exposed externally"],
    25:    ["Banner grab: nc -nv <host> 25 → EHLO test",
            "Check open relay: RCPT TO external address",
            "Tools: smtp-user-enum, swaks, nmap --script smtp*"],
    53:    ["Zone transfer: dig axfr @<host> <domain>",
            "DNS version: dig version.bind chaos txt @<host>",
            "Tools: dnsx, dnsrecon, fierce, nmap --script dns*"],
    80:    ["Directory brute: gobuster dir -u http://<host> -w wordlist.txt",
            "Vuln scan: nikto -h <host>",
            "Tech detect: whatweb <host>",
            "Tools: burpsuite, nikto, gobuster, ffuf, nuclei"],
    110:   ["Banner grab: nc -nv <host> 110 → USER test PASS test",
            "Check for plaintext credential transmission"],
    139:   ["Enum: enum4linux -a <host>", "Null session: smbclient -L <host> -N",
            "Tools: enum4linux, smbmap, crackmapexec"],
    143:   ["Banner grab: nc -nv <host> 143",
            "Check for plaintext credential transmission"],
    443:   ["SSL/TLS audit: testssl.sh <host>:443",
            "Check cipher suites, certificate expiry, HSTS",
            "Tools: testssl.sh, sslscan, sslyze, burpsuite"],
    445:   ["Enum: smbmap -H <host>", "Check EternalBlue: nmap --script smb-vuln-ms17-010",
            "Tools: crackmapexec, impacket, enum4linux, smbclient"],
    1433:  ["Default creds: SA / (blank)", "Xp_cmdshell if enabled = RCE",
            "Tools: nmap --script ms-sql*, impacket mssqlclient.py"],
    1521:  ["Default SIDs: XE, ORCL", "Tools: odat, nmap --script oracle*"],
    2375:  ["Unauthenticated Docker API = instant RCE",
            "curl http://<host>:2375/v1.41/containers/json",
            "Escape container: mount host filesystem"],
    3306:  ["Default: root / (blank or root)", "Check skip-grant-tables",
            "Tools: hydra -l root -P wordlist.txt mysql://<host>"],
    3389:  ["BlueKeep check: nmap --script rdp-vuln-ms12-020",
            "Brute force: hydra -l administrator -P wordlist.txt rdp://<host>",
            "Tools: rdesktop, xfreerdp, crowbar"],
    5432:  ["Default: postgres/postgres", "SQL → OS if superuser: COPY FROM PROGRAM",
            "Tools: hydra, pgadmin, psql"],
    5900:  ["No-auth VNC: try connect with no password",
            "Tools: vncviewer, hydra -l <blank> -P wordlist.txt vnc://<host>"],
    6379:  ["Unauthenticated Redis = config write / SSH key injection",
            "redis-cli -h <host> INFO",
            "Tools: redis-cli, redis-rogue-server"],
    8080:  ["Same as port 80 + check /manager (Tomcat), /console (JBoss)",
            "Tools: gobuster, nikto, burpsuite, nuclei"],
    9200:  ["Unauthenticated Elasticsearch = full data dump",
            "curl http://<host>:9200/_cat/indices",
            "curl http://<host>:9200/_all/_search?size=100"],
    27017: ["Unauthenticated MongoDB = full read/write access",
            "mongo --host <host> → show dbs",
            "Tools: mongodump, NoSQLMap"],
}

DEFENSIVE_NOTES: dict[int, list[str]] = {
    21:    ["Replace FTP with SFTP (port 22) or FTPS", "Disable anonymous login",
            "Restrict to known IPs via firewall"],
    22:    ["Disable PasswordAuthentication — enforce key-based auth only",
            "Set PermitRootLogin no", "Use fail2ban or sshguard",
            "Bind to non-default port if possible (security-through-obscurity bonus)",
            "Restrict to VPN/jump-host access"],
    23:    ["Disable immediately — use SSH instead", "Should NEVER be internet-facing"],
    25:    ["Enable STARTTLS / enforce TLS", "Configure SPF, DKIM, DMARC",
            "Restrict to known sending IPs (no open relay)"],
    53:    ["Disable zone transfers to unauthorised IPs", "Rate-limit recursive queries",
            "Use DNSSEC", "Separate authoritative and recursive resolvers"],
    80:    ["Redirect all HTTP → HTTPS (301)", "Enable HSTS", "WAF recommended for production",
            "Disable directory listing and default error pages"],
    443:   ["Enforce TLS 1.2+ only (disable SSLv3, TLS 1.0, 1.1)",
            "Use strong cipher suites (ECDHE + AES-GCM)", "Enable HSTS with preloading",
            "Rotate and monitor certificates (use ACME/Let's Encrypt)"],
    445:   ["Block at perimeter — SMB should NEVER be internet-facing",
            "Patch MS17-010 (EternalBlue), MS08-067", "Require SMB signing",
            "Disable SMBv1 entirely"],
    1433:  ["Never expose to internet — use VPN + firewall rules",
            "Disable xp_cmdshell", "Use least-privilege service accounts"],
    2375:  ["NEVER expose Docker API without TLS + mutual auth",
            "Use unix socket only, or bind to 127.0.0.1"],
    3306:  ["Bind to 127.0.0.1 or private network only",
            "Disable root remote login", "Use strong passwords + user grants"],
    3389:  ["Enable NLA (Network Level Authentication)", "Restrict to VPN/known IPs",
            "Patch BlueKeep (CVE-2019-0708) and DejaBlue", "Use RD Gateway"],
    5432:  ["Bind to 127.0.0.1 or private IP", "pg_hba.conf: restrict hosts",
            "Revoke superuser from application accounts"],
    5900:  ["Require VNC password or use SSH tunnel", "Never expose to internet",
            "Prefer RDP/SSH with MFA"],
    6379:  ["Bind to 127.0.0.1 — never expose to internet",
            "Enable requirepass", "Disable CONFIG, FLUSHALL if not needed"],
    9200:  ["Bind to 127.0.0.1 or private network", "Enable X-Pack security (auth + TLS)",
            "Never expose to internet without authentication"],
    27017: ["Enable --auth flag", "Bind to 127.0.0.1 or private IP",
            "Use role-based access control"],
}


def analyze_port(port: int, db=None, verbose: bool = False) -> dict:
    """
    Full port analysis. Returns a structured dict with all layers.
    First call fetches from APIs and caches. Subsequent calls use cache +
    only fetch incremental updates (new CVEs, updated EPSS scores).
    """
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if verbose:
            print(f"[i] querying port {port}...")

        # 1. IANA identity
        iana_rows = fetch_iana_for_port(port, db)

        # Derive primary service name for NVD search
        service_name = None
        if iana_rows:
            service_name = iana_rows[0].get("service_name") or None

        # 2. ATT&CK techniques (seed, very fast)
        seed_techniques_for_port(port, db)

        # 3. NVD CVEs (incremental)
        search_terms = get_search_terms(port, service_name)
        fetch_nvd_for_port(port, search_terms, db)

        # 4. CISA KEV cross-reference
        apply_kev_to_port(port, db)

        # 5. EPSS scores for all stored CVEs
        fetch_epss_for_port(port, db)

        # ── assemble result ────────────────────────────────────────────────────
        profiles   = [dict(r) for r in get_port_profile(db, port)]
        cves_rows  = [dict(r) for r in get_cves(db, port)]
        tech_rows  = [dict(r) for r in get_techniques(db, port)]

        kev_cve_ids = {c["cve_id"] for c in cves_rows if c.get("exploited_in_wild")}
        top_cves    = sorted(cves_rows, key=lambda c: c.get("cvss_score") or 0, reverse=True)[:10]

        risk = _risk_level(cves_rows, bool(kev_cve_ids))

        # Determine protocol list
        transports = list({p["transport"] for p in profiles}) if profiles else ["TCP"]

        return {
            "port":            port,
            "service_name":    service_name or f"port-{port}",
            "transport":       transports,
            "iana_status":     profiles[0]["iana_status"] if profiles else "Unknown",
            "description":     profiles[0]["description"] if profiles else "",
            "risk_level":      risk,
            "cve_count":       len(cves_rows),
            "kev_count":       len(kev_cve_ids),
            "top_cves":        top_cves,
            "techniques":      tech_rows,
            "pentest_notes":   PENTEST_NOTES.get(port, []),
            "defensive_notes": DEFENSIVE_NOTES.get(port, []),
            "search_terms":    search_terms,
        }

    finally:
        if close:
            db.close()


def analyze_ports(ports: list[int], db=None) -> list[dict]:
    close = False
    if db is None:
        db = get_db()
        close = True
    try:
        return [analyze_port(p, db) for p in ports]
    finally:
        if close:
            db.close()


def _risk_level(cves: list[dict], has_kev: bool) -> str:
    if has_kev:
        return "CRITICAL"
    if not cves:
        return "LOW"
    max_score = max((c.get("cvss_score") or 0) for c in cves)
    if max_score >= 9.0:
        return "CRITICAL"
    if max_score >= 7.0:
        return "HIGH"
    if max_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def parse_port_input(raw: str) -> list[int]:
    """
    Parse CLI input into a list of port numbers.
    Accepts: '22', '22,443,8080', '8080-8090', '22,80-90,443'
    """
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            if lo > hi:
                lo, hi = hi, lo
            if hi - lo > 1000:
                raise ValueError(f"Range {lo}-{hi} is too large (max 1000 ports at once)")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))

    # Validate
    for p in ports:
        if not (0 <= p <= 65535):
            raise ValueError(f"Port {p} is out of range (0-65535)")

    return sorted(set(ports))

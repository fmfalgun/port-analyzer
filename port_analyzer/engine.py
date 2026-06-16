"""
Query engine — orchestrates all sources + cache for a single port.
The CLI, backend API, and web all go through this.
"""

from port_analyzer.cache import get_db, get_port_profile, get_cves, get_techniques, get_variot_vulns, get_port_history
from port_analyzer.sources.iana import fetch_iana_for_port, get_search_terms
from port_analyzer.sources.nvd import fetch_nvd_for_port
from port_analyzer.sources.cisa_kev import apply_kev_to_port, get_kev_details
from port_analyzer.sources.epss import fetch_epss_for_port
from port_analyzer.sources.mitre_attack import seed_techniques_for_port
from port_analyzer.sources.poc_github import fetch_poc_for_port
from port_analyzer.sources.variot import fetch_variot_for_port
from port_analyzer.sources.attackerkb import fetch_attackerkb_for_port
from port_analyzer.sources.exploitdb import apply_exploitdb_to_port
from port_analyzer.sources.shadowserver import fetch_shadowserver_for_port
from port_analyzer.sources.wikipedia_history import fetch_wikipedia_history_for_port
from port_analyzer.sources.nmap_services import fetch_nmap_popularity_for_port

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
    # New ports added in expansion
    88:    ["Kerberoasting: GetUserSPNs.py -request -dc-ip <dc> <domain>/<user>",
            "AS-REP Roasting: GetNPUsers.py <domain>/ -usersfile users.txt -no-pass",
            "Pass-the-Ticket: mimikatz sekurlsa::tickets /export → kerberos::ptt",
            "Golden Ticket: mimikatz kerberos::golden /user:Administrator /domain:<d> /sid:<s> /krbtgt:<h>",
            "Tools: impacket, mimikatz, Rubeus, kerbrute"],
    500:   ["IKE aggressive mode scan: ike-scan --aggressive <host>",
            "Identify PSK hashes: ike-scan -M --aggressive -P out.txt <host>",
            "Crack PSK offline: psk-crack -d wordlist.txt out.txt",
            "Identify transforms: ike-scan --showbackoff <host>",
            "Tools: ike-scan, psk-crack, strongswan, ikeprobe"],
    512:   ["rexec executes commands with minimal auth — try null/weak credentials",
            "r-services trust .rhosts — check for + + wildcard entries",
            "Scan: nmap -p 512,513,514 --script rexec-brute <host>",
            "Tools: nmap --script rexec*, rsh, netcat"],
    513:   ["rlogin bypasses password if .rhosts or /etc/hosts.equiv allows source IP",
            ".rhosts + + = passwordless login from any host",
            "rlogin -l root <host> (try from trusted IP)",
            "Tools: rlogin, rsh, nmap --script rlogin-brute"],
    623:   ["IPMI Cipher Zero auth bypass: ipmitool -I lanplus -C 0 -H <host> -U admin -P anything chassis status",
            "Dump IPMI hashes: metasploit auxiliary/scanner/ipmi/ipmi_dumphashes",
            "Identify IPMI version: metasploit auxiliary/scanner/ipmi/ipmi_version",
            "Crack hashes offline with hashcat mode 7300",
            "Tools: ipmitool, metasploit ipmi modules, hashcat -m 7300"],
    1099:  ["Java RMI deserialization → RCE via ysoserial payload",
            "List RMI objects: nmap --script rmi-dumpregistry -p 1099 <host>",
            "Exploit: java -jar ysoserial.jar CommonsCollections1 'cmd' | nc <host> 1099",
            "Tools: ysoserial, nmap rmi scripts, rmg (remote-method-guesser), beanshooter"],
    1723:  ["PPTP MS-CHAPv2 is cryptographically broken — capture and crack handshake",
            "Capture: setup PPTP MitM with chapcrack or use asleap",
            "Crack: chapcrack capture.cap → john/hashcat",
            "PPTP provides no forward secrecy — avoid in all modern environments",
            "Tools: asleap, chapcrack, thc-pptp-bruter, pptpcrack"],
    2375:  ["Unauthenticated Docker API = instant RCE",
            "curl http://<host>:2375/v1.41/containers/json",
            "Escape container: mount host filesystem",
            "RCE: docker -H tcp://<host>:2375 run -v /:/mnt alpine chroot /mnt sh",
            "Tools: docker cli, dockerscan, metasploit docker modules"],
    4444:  ["Default Metasploit meterpreter listener port — indicates C2 infrastructure",
            "Check for active sessions: nc -nv <host> 4444",
            "Port scan to confirm Metasploit framework: nmap -sV -p 4444 <host>",
            "If found in your environment: immediate incident response required"],
    5353:  ["mDNS/DNS-SD service enumeration: avahi-browse -a or dns-sd -B _services._dns-sd._udp local",
            "Responder mDNS poisoning: responder -I eth0 (captures NTLMv2 hashes)",
            "MITM via mDNS spoofing: responder poisons A record responses",
            "Enumerate services: nmap -p 5353 --script dns-service-discovery <host>",
            "Tools: Responder, avahi-browse, dns-sd, nmap --script mdns*"],
    5985:  ["WinRM lateral movement: evil-winrm -i <host> -u <user> -p <pass>",
            "Pass-the-hash: evil-winrm -i <host> -u <user> -H <NTLM_hash>",
            "Check if enabled: Test-WSMan -ComputerName <host> (PowerShell)",
            "Brute force: crackmapexec winrm <host> -u users.txt -p passwords.txt",
            "Tools: evil-winrm, crackmapexec, impacket wmiexec, nmap --script winrm*"],
    5986:  ["WinRM over HTTPS — same attacks as 5985 but TLS-wrapped",
            "evil-winrm -i <host> -u <user> -p <pass> -S (SSL mode)",
            "Certificate may leak hostname/org in CN field",
            "Tools: evil-winrm, crackmapexec, curl -k https://<host>:5986/wsman"],
    6000:  ["X11 forwarding abuse: DISPLAY=<host>:0 xterm (open xterm on victim display)",
            "Screenshot capture: xwd -display <host>:0 -root -silent > screen.xwd",
            "Keylogger: xinput on target display",
            "Check for open X11: nmap -p 6000 --script x11-access <host>",
            "Tools: xwd, xdotool, xspy, nmap --script x11*"],
    9418:  ["Anonymous git clone: git clone git://<host>/repo.git",
            "Search commit history for credentials: truffleHog / gitleaks on cloned repo",
            "List repos: git ls-remote git://<host>/",
            "Credentials often accidentally committed in .env, config, or history",
            "Tools: gitleaks, truffleHog, git-dumper"],
    10000: ["Webmin CVE exploitation — check version: curl http://<host>:10000/",
            "CVE-2019-15107: unauthenticated RCE via password reset endpoint",
            "Default creds: admin/admin or as set during install",
            "Brute force login: hydra -l root -P wordlist.txt <host> http-form-post '/session_login.cgi:user=^USER^&pass=^PASS^:Login failed'",
            "Tools: metasploit exploit/linux/http/webmin_backdoor, nmap --script webmin*"],
    44818: ["EtherNet/IP replay attacks: capture Wireshark ENIP frames and replay",
            "Enumerate devices: nmap -p 44818 --script enip-info <host>",
            "Send unauthorized CIP commands via pycomm3 or EtherNet/IP toolkit",
            "ICS devices often lack auth — direct command execution possible",
            "Tools: nmap enip scripts, pycomm3, metasploit auxiliary/scanner/scada/modbusdetect"],
    47808: ["BACnet device enumeration: nmap -sU -p 47808 --script bacnet-info <host>",
            "Read properties: bacpypes BACnet/IP explorer",
            "Unauthorized read/write of BACnet objects = building system manipulation",
            "No native authentication in BACnet — segment from corporate network",
            "Tools: nmap bacnet scripts, bacpypes, BACnet discovery tools"],
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
    # New ports added in expansion
    88:    ["Enforce Kerberos pre-authentication (disable AS-REP roasting surface)",
            "Set strong service account passwords (25+ chars) to defeat Kerberoasting",
            "Monitor for TGS requests to service accounts — high volume = Kerberoasting",
            "Limit Kerberos delegation — avoid unconstrained delegation",
            "Alert on anomalous TGT/TGS requests from non-DCs (Event IDs 4768, 4769, 4771)"],
    500:   ["Use IKEv2 instead of IKEv1 (eliminates aggressive mode risk)",
            "Prefer certificate-based auth over PSK",
            "If PSK required: use long random keys (32+ chars)",
            "Restrict VPN endpoints to known IPs via firewall",
            "Disable weak encryption transforms (DES, 3DES, MD5)"],
    512:   ["Disable r-services (rexec, rlogin, rsh) — use SSH instead",
            "Remove .rhosts and /etc/hosts.equiv files",
            "Block ports 512-514 at the perimeter"],
    513:   ["Disable r-services — use SSH instead",
            "Remove .rhosts and /etc/hosts.equiv files",
            "Block ports 512-514 at the perimeter"],
    623:   ["Isolate IPMI/BMC on a dedicated management VLAN",
            "Patch IPMI firmware to address cipher zero vulnerability",
            "Change default credentials immediately",
            "Restrict IPMI access to known management IPs only",
            "Consider disabling IPMI over network if not needed — use physical console"],
    1099:  ["Firewall Java RMI port — never expose to internet",
            "Enable RMI over SSL (RMISocketFactory)",
            "Use Java security manager to restrict deserialization classes",
            "Patch JDK and all commons-collections/spring/etc dependencies",
            "Filter incoming Java serialized objects at application boundary"],
    1723:  ["Migrate from PPTP to IKEv2 or OpenVPN — PPTP MS-CHAPv2 is broken",
            "Block port 1723 at perimeter if PPTP is not needed",
            "PPTP is deprecated — no remediation can make MS-CHAPv2 secure"],
    2375:  ["NEVER expose Docker API without TLS + mutual auth",
            "Use unix socket only, or bind to 127.0.0.1",
            "Enable TLS: use --tlsverify --tlscacert --tlscert --tlskey flags",
            "Audit running containers regularly for unauthorized images"],
    4444:  ["Block outbound port 4444 at firewall — common Metasploit default",
            "Alert on any inbound connections to port 4444",
            "Use EDR to detect meterpreter payloads regardless of port"],
    5353:  ["Disable mDNS on hosts where it is not needed (disable avahi-daemon)",
            "Block UDP 5353 between network segments",
            "Deploy LLMNR/mDNS poisoning detection (monitor for Responder activity)",
            "Use DNS with DNSSEC instead of mDNS for service discovery"],
    5985:  ["Restrict WinRM access to jump hosts and management subnets only",
            "Require Kerberos or certificate authentication — disable Basic auth",
            "Enable HTTPS (port 5986) instead of HTTP",
            "Log and alert on WinRM sessions (Event ID 91, 168 in WinRM channel)"],
    5986:  ["Prefer 5986 (HTTPS) over 5985 (HTTP) for WinRM",
            "Enforce certificate validation — avoid self-signed certs without pinning",
            "Restrict to management VLAN; require MFA for privileged accounts"],
    6000:  ["Disable X11 TCP listening — use Unix sockets only (add '-nolisten tcp')",
            "Use SSH X11 forwarding (ssh -X) with ForwardX11Trusted no",
            "Block TCP port 6000-6063 at perimeter and between host segments",
            "Never expose X11 to untrusted networks"],
    9418:  ["Use authenticated git transports (SSH or HTTPS) instead of git:// protocol",
            "Disable the git daemon if anonymous clone is not intentional",
            "Scan repositories for hardcoded credentials before pushing",
            "Use gitleaks or truffleHog in CI/CD pipeline"],
    10000: ["Require HTTPS for Webmin (disable HTTP access)",
            "Restrict access to known admin IPs via built-in IP access control",
            "Apply Webmin updates immediately — CVE-2019-15107 was critical RCE",
            "Consider replacing Webmin with purpose-built configuration management"],
    44818: ["Isolate EtherNet/IP devices on dedicated OT/ICS VLAN",
            "Deploy ICS-aware firewall/IDS (Claroty, Dragos, Nozomi)",
            "Block TCP/UDP 44818 from IT networks to OT devices",
            "Implement unidirectional security gateways where possible",
            "Require authentication patches where vendor firmware supports it"],
    47808: ["Isolate BACnet devices on dedicated building automation VLAN",
            "Block UDP 47808 between IT and OT/BAS networks",
            "Deploy BACnet-aware monitoring to detect unauthorized device commands",
            "Work with building system integrators to apply firmware updates",
            "Document all BACnet devices and expected traffic patterns"],
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

        # 6. PoC-in-GitHub availability (top CVEs by CVSS)
        fetch_poc_for_port(port, db)

        # 7. VARIoT IoT-specific CVEs
        fetch_variot_for_port(port, search_terms, db)

        # 8. AttackerKB crowd-sourced exploitation assessments
        fetch_attackerkb_for_port(port, db)

        # 9. Exploit-DB public exploit code (full CSV, cached 24h)
        apply_exploitdb_to_port(port, db)

        # 10. Shadowserver real-time active scanning (no-op without API key)
        fetch_shadowserver_for_port(port, db)

        # 11. Wikipedia — port usage description & historical/malware notes (~30 day cache)
        fetch_wikipedia_history_for_port(port, db)

        # 12. nmap-services — real-world popularity/frequency (~30 day cache)
        fetch_nmap_popularity_for_port(port, db)

        # ── assemble result ────────────────────────────────────────────────────
        profiles      = [dict(r) for r in get_port_profile(db, port)]
        cves_rows     = [dict(r) for r in get_cves(db, port)]
        tech_rows     = [dict(r) for r in get_techniques(db, port)]
        variot_rows   = get_variot_vulns(db, port)
        history_row   = get_port_history(db, port)

        kev_cve_ids      = {c["cve_id"] for c in cves_rows if c.get("exploited_in_wild")}
        top_cves         = sorted(cves_rows, key=lambda c: c.get("cvss_score") or 0, reverse=True)[:10]
        poc_count        = sum(1 for c in cves_rows if (c.get("poc_count") or 0) > 0)
        attackerkb_hits  = sum(1 for c in cves_rows if c.get("attackerkb_score") is not None)
        exploitdb_hits   = sum(1 for c in cves_rows if (c.get("exploitdb_count") or 0) > 0)
        shadowserver_hits = sum(1 for c in cves_rows if (c.get("shadowserver_count") or 0) > 0)

        risk = _risk_level(cves_rows, bool(kev_cve_ids))

        # Determine protocol list
        transports = list({p["transport"] for p in profiles}) if profiles else ["TCP"]

        return {
            "port":            port,
            "service_name":    service_name or f"port-{port}",
            "transport":       transports,
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
            "risk_level":      risk,
            "cve_count":       len(cves_rows),
            "kev_count":       len(kev_cve_ids),
            "poc_count":        poc_count,
            "attackerkb_hits":  attackerkb_hits,
            "exploitdb_hits":   exploitdb_hits,
            "shadowserver_hits": shadowserver_hits,
            "top_cves":        top_cves,
            "all_cves":        cves_rows,
            "techniques":      tech_rows,
            "variot_vulns":    variot_rows,
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

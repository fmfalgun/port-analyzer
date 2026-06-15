"""
IANA Service Name and Port Number Registry.
CSV source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
Fetched once per port; the assignment is effectively immutable.
"""

import csv
import io
import time
import requests
from port_analyzer.cache import get_db, get_port_profile, upsert_port_profile, is_stale, update_fetch_log

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

# ports → search terms for NVD queries (service name may be too generic)
PORT_SEARCH_TERMS: dict[int, list[str]] = {
    21:   ["ftp", "vsftpd", "proftpd", "filezilla"],
    22:   ["ssh", "openssh", "dropbear", "libssh"],
    23:   ["telnet"],
    25:   ["smtp", "postfix", "sendmail", "exim"],
    53:   ["dns", "bind", "named", "dnsmasq", "unbound"],
    67:   ["dhcp", "dhcpd"],
    69:   ["tftp"],
    80:   ["http", "apache", "nginx", "iis"],
    110:  ["pop3", "dovecot"],
    111:  ["rpcbind", "portmap"],
    119:  ["nntp"],
    123:  ["ntp", "ntpd"],
    135:  ["rpc", "dcom", "msrpc"],
    137:  ["netbios", "smb"],
    139:  ["netbios", "smb", "samba"],
    143:  ["imap", "dovecot", "courier"],
    161:  ["snmp"],
    389:  ["ldap", "openldap"],
    443:  ["https", "ssl", "tls", "apache", "nginx", "openssl"],
    445:  ["smb", "samba", "cifs"],
    465:  ["smtps", "smtp"],
    502:  ["modbus"],
    514:  ["syslog"],
    515:  ["lpd", "cups"],
    587:  ["smtp", "submission"],
    631:  ["ipp", "cups"],
    636:  ["ldaps", "ldap"],
    873:  ["rsync"],
    902:  ["vmware"],
    993:  ["imaps", "imap", "dovecot"],
    995:  ["pop3s", "pop3"],
    1080: ["socks", "proxy"],
    1194: ["openvpn"],
    1433: ["mssql", "sql server", "microsoft sql"],
    1521: ["oracle", "oracle database"],
    1883: ["mqtt", "mosquitto"],
    2049: ["nfs"],
    2181: ["zookeeper"],
    2375: ["docker"],
    2376: ["docker"],
    3000: ["grafana", "nodejs", "express"],
    3306: ["mysql", "mariadb"],
    3389: ["rdp", "remote desktop", "mstsc"],
    3690: ["svn", "subversion"],
    4443: ["https", "ssl"],
    4505: ["saltstack", "salt"],
    4848: ["glassfish"],
    5000: ["flask", "upnp"],
    5432: ["postgresql", "postgres"],
    5555: ["android adb", "adb"],
    5601: ["kibana"],
    5672: ["amqp", "rabbitmq"],
    5900: ["vnc", "rfb"],
    6379: ["redis"],
    6443: ["kubernetes", "k8s api"],
    7001: ["weblogic"],
    8009: ["ajp", "apache jserv", "tomcat"],
    8080: ["http", "tomcat", "jetty", "jboss"],
    8443: ["https", "tomcat"],
    8888: ["jupyter", "http"],
    9000: ["php-fpm", "sonarqube"],
    9090: ["prometheus", "cockpit"],
    9200: ["elasticsearch"],
    9300: ["elasticsearch"],
    10250: ["kubelet", "kubernetes"],
    11211: ["memcached"],
    27017: ["mongodb"],
    27018: ["mongodb"],
    50070: ["hadoop", "hdfs"],
    # New ports added in expansion
    8:     ["icmp", "ping", "echo"],
    43:    ["whois"],
    49:    ["tacacs", "tacacs+"],
    70:    ["gopher"],
    79:    ["finger"],
    88:    ["kerberos", "krb5", "kdc"],
    113:   ["ident", "auth", "identd"],
    177:   ["xdmcp", "x display manager"],
    194:   ["irc", "internet relay chat"],
    264:   ["bgmp"],
    500:   ["ike", "ipsec", "isakmp", "vpn"],
    512:   ["rexec", "r-exec"],
    513:   ["rlogin", "r-login", "rsh"],
    520:   ["rip", "routing information protocol"],
    540:   ["uucp"],
    548:   ["afp", "apple filing protocol", "netatalk"],
    554:   ["rtsp", "real time streaming"],
    623:   ["ipmi", "rmcp", "baseboard management"],
    694:   ["ha heartbeat", "cluster heartbeat"],
    749:   ["kerberos admin", "kadmin"],
    853:   ["dns over tls", "dot"],
    989:   ["ftps", "ftp data ssl"],
    990:   ["ftps", "ftp ssl"],
    992:   ["telnet ssl", "telnets"],
    1099:  ["java rmi", "rmi registry", "ysoserial"],
    1434:  ["mssql", "sql server browser", "ms-sql-m"],
    1723:  ["pptp", "vpn", "point-to-point tunneling"],
    2082:  ["cpanel", "whm"],
    2083:  ["cpanel", "cpanel ssl", "whm ssl"],
    2222:  ["ssh", "openssh", "alternate ssh"],
    3268:  ["ldap", "global catalog", "active directory"],
    3269:  ["ldaps", "ldap ssl", "global catalog ssl"],
    4369:  ["erlang", "epmd", "rabbitmq", "beam"],
    4444:  ["metasploit", "meterpreter", "shell listener"],
    5353:  ["mdns", "multicast dns", "bonjour", "avahi"],
    5985:  ["winrm", "windows remote management", "wsman"],
    5986:  ["winrm", "winrm ssl", "wsman ssl"],
    6000:  ["x11", "x windows", "xorg"],
    8000:  ["http", "flask", "django", "python dev server"],
    8001:  ["http", "alternate http"],
    8008:  ["http", "alternate http"],
    8500:  ["consul", "hashicorp consul"],
    8883:  ["mqtt", "mqtt tls", "mosquitto ssl"],
    9418:  ["git", "git protocol", "git daemon"],
    10000: ["webmin", "virtualmin"],
    44818: ["ethernet/ip", "ethernetip", "industrial protocol", "rockwell"],
    47808: ["bacnet", "building automation", "ashrae"],
}

# ATT&CK technique seed mapping (port → [(technique_id, name, tactic)])
PORT_TECHNIQUE_MAP: dict[int, list[tuple[str, str, str]]] = {
    21:    [("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
            ("T1078", "Valid Accounts", "defense-evasion"),
            ("T1190", "Exploit Public-Facing Application", "initial-access")],
    22:    [("T1021.004", "Remote Services: SSH", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
            ("T1098.004", "Account Manipulation: SSH Authorized Keys", "persistence")],
    23:    [("T1021.002", "Remote Services: Telnet", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    25:    [("T1566.001", "Phishing: Spearphishing Attachment", "initial-access"),
            ("T1071.003", "Application Layer Protocol: Mail Protocols", "command-and-control")],
    53:    [("T1071.004", "Application Layer Protocol: DNS", "command-and-control"),
            ("T1568", "Dynamic Resolution", "command-and-control"),
            ("T1048.001", "Exfiltration Over Alternative Protocol: DNS", "exfiltration")],
    80:    [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1059.007", "Command and Scripting Interpreter: JavaScript", "execution"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control")],
    110:   [("T1566.001", "Phishing: Spearphishing Attachment", "initial-access")],
    143:   [("T1566.001", "Phishing: Spearphishing Attachment", "initial-access")],
    161:   [("T1602.001", "Data from Configuration Repository: SNMP MIB Dump", "collection"),
            ("T1040", "Network Sniffing", "credential-access")],
    389:   [("T1087.002", "Account Discovery: Domain Account", "discovery"),
            ("T1482", "Domain Trust Discovery", "discovery")],
    443:   [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
            ("T1573", "Encrypted Channel", "command-and-control")],
    445:   [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
            ("T1110.002", "Brute Force: Password Spraying", "credential-access"),
            ("T1569.002", "System Services: Service Execution", "execution")],
    502:   [("T0853", "Scripting", "execution"),
            ("T0855", "Unauthorized Command Message", "impair-process-control")],
    1433:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion"),
            ("T1505.001", "Server Software Component: SQL Stored Procedures", "persistence")],
    1883:  [("T1040", "Network Sniffing", "credential-access"),
            ("T1557", "Adversary-in-the-Middle", "credential-access")],
    2375:  [("T1610", "Deploy Container", "defense-evasion"),
            ("T1190", "Exploit Public-Facing Application", "initial-access")],
    3306:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    3389:  [("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
            ("T1563.002", "Remote Service Session Hijacking: RDP Hijacking", "lateral-movement")],
    5432:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    5900:  [("T1021.005", "Remote Services: VNC", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    6379:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1059", "Command and Scripting Interpreter", "execution")],
    8080:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control")],
    9200:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1213", "Data from Information Repositories", "collection")],
    27017: [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1213", "Data from Information Repositories", "collection")],
    # New ports added in expansion
    8:     [("T1018", "Remote System Discovery", "discovery"),
            ("T1595.001", "Active Scanning: Scanning IP Blocks", "reconnaissance")],
    43:    [("T1590", "Gather Victim Network Information", "reconnaissance")],
    49:    [("T1078", "Valid Accounts", "defense-evasion"),
            ("T1556", "Modify Authentication Process", "credential-access")],
    70:    [("T1190", "Exploit Public-Facing Application", "initial-access")],
    79:    [("T1592", "Gather Victim Host Information", "reconnaissance"),
            ("T1589", "Gather Victim Identity Information", "reconnaissance")],
    88:    [("T1558", "Steal or Forge Kerberos Tickets", "credential-access"),
            ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "credential-access"),
            ("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "credential-access"),
            ("T1550.003", "Use Alternate Authentication Material: Pass the Ticket", "lateral-movement")],
    113:   [("T1592", "Gather Victim Host Information", "reconnaissance")],
    177:   [("T1021", "Remote Services", "lateral-movement")],
    194:   [("T1071.003", "Application Layer Protocol: Mail Protocols", "command-and-control")],
    500:   [("T1572", "Protocol Tunneling", "command-and-control"),
            ("T1133", "External Remote Services", "initial-access")],
    512:   [("T1021.004", "Remote Services: SSH", "lateral-movement"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    513:   [("T1021.004", "Remote Services: SSH", "lateral-movement"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    520:   [("T1557", "Adversary-in-the-Middle", "credential-access")],
    548:   [("T1039", "Data from Network Shared Drive", "collection"),
            ("T1021", "Remote Services", "lateral-movement")],
    554:   [("T1040", "Network Sniffing", "credential-access")],
    623:   [("T1110", "Brute Force", "credential-access"),
            ("T1552", "Unsecured Credentials", "credential-access")],
    694:   [("T1499", "Endpoint Denial of Service", "impact")],
    749:   [("T1558", "Steal or Forge Kerberos Tickets", "credential-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    853:   [("T1071.004", "Application Layer Protocol: DNS", "command-and-control")],
    989:   [("T1048", "Exfiltration Over Alternative Protocol", "exfiltration")],
    990:   [("T1048", "Exfiltration Over Alternative Protocol", "exfiltration")],
    1099:  [("T1203", "Exploitation for Client Execution", "execution"),
            ("T1190", "Exploit Public-Facing Application", "initial-access")],
    1434:  [("T1046", "Network Service Discovery", "discovery"),
            ("T1190", "Exploit Public-Facing Application", "initial-access")],
    1723:  [("T1572", "Protocol Tunneling", "command-and-control"),
            ("T1133", "External Remote Services", "initial-access")],
    2082:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    2083:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    2222:  [("T1021.004", "Remote Services: SSH", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    3268:  [("T1087.002", "Account Discovery: Domain Account", "discovery"),
            ("T1482", "Domain Trust Discovery", "discovery")],
    3269:  [("T1087.002", "Account Discovery: Domain Account", "discovery"),
            ("T1482", "Domain Trust Discovery", "discovery")],
    4369:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1046", "Network Service Discovery", "discovery")],
    4444:  [("T1219", "Remote Access Software", "command-and-control"),
            ("T1059", "Command and Scripting Interpreter", "execution")],
    5353:  [("T1557", "Adversary-in-the-Middle", "credential-access"),
            ("T1040", "Network Sniffing", "credential-access")],
    5985:  [("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement"),
            ("T1110.001", "Brute Force: Password Guessing", "credential-access")],
    5986:  [("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement"),
            ("T1573", "Encrypted Channel", "command-and-control")],
    6000:  [("T1021.005", "Remote Services: VNC", "lateral-movement"),
            ("T1185", "Browser Session Hijacking", "collection")],
    8000:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control")],
    8001:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control")],
    8008:  [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control")],
    8500:  [("T1046", "Network Service Discovery", "discovery"),
            ("T1190", "Exploit Public-Facing Application", "initial-access")],
    8883:  [("T1040", "Network Sniffing", "credential-access"),
            ("T1557", "Adversary-in-the-Middle", "credential-access")],
    9418:  [("T1213", "Data from Information Repositories", "collection"),
            ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access")],
    10000: [("T1190", "Exploit Public-Facing Application", "initial-access"),
            ("T1078", "Valid Accounts", "defense-evasion")],
    44818: [("T0886", "Remote Services", "lateral-movement"),
            ("T0855", "Unauthorized Command Message", "impair-process-control")],
    47808: [("T0886", "Remote Services", "lateral-movement"),
            ("T0840", "Network Connection Enumeration", "discovery")],
}


def fetch_iana_for_port(port: int, db=None) -> list[dict]:
    """Download IANA CSV and extract all entries for the given port."""
    close = False
    if db is None:
        db = get_db()
        close = True

    try:
        if not is_stale(db, port, "iana", max_age_hours=8760):
            rows = get_port_profile(db, port)
            if rows:
                return [dict(r) for r in rows]

        resp = requests.get(IANA_CSV_URL, timeout=30)
        resp.raise_for_status()

        results = []
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            try:
                p = int(row.get("Port Number", "").strip())
            except (ValueError, TypeError):
                continue
            if p != port:
                continue

            transport = (row.get("Transport Protocol") or "tcp").strip().upper() or "TCP"
            service   = (row.get("Service Name") or "").strip()
            desc      = (row.get("Description") or "").strip()
            status    = (row.get("Assignment Notes") or "Assigned").strip()

            upsert_port_profile(db, port, transport, service, desc, status)
            results.append({
                "port": port,
                "transport": transport,
                "service_name": service,
                "description": desc,
                "iana_status": status,
            })

        if results:
            update_fetch_log(db, port, "iana")
        return results

    finally:
        if close:
            db.close()


def get_search_terms(port: int, service_name: str | None) -> list[str]:
    """Return NVD keyword search terms for this port."""
    terms = PORT_SEARCH_TERMS.get(port, [])
    if not terms and service_name:
        terms = [service_name.lower()]
    return terms or [str(port)]


def get_techniques_seed(port: int) -> list[tuple[str, str, str]]:
    return PORT_TECHNIQUE_MAP.get(port, [])

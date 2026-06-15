# Port Analyzer

Port-level cybersecurity intelligence in three modes — CLI, REST API, and browser UI.

Enter one or more ports and get back: CVEs ranked by CVSS score, CISA KEV exploitation status, EPSS probability scores, public PoC availability per CVE, IoT-specific vulnerabilities from VARIoT, mapped MITRE ATT&CK techniques, pentest commands, and defensive hardening notes. Results are cached locally in SQLite so every repeat query is instant, and only newly published CVEs are fetched on refresh.

---

## Table of Contents

- [What It Is](#what-it-is)
- [Data Sources](#data-sources)
- [Smart Caching](#smart-caching)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI](#cli)
  - [REST API](#rest-api)
  - [Web UI](#web-ui)
- [API Quick Reference](#api-quick-reference)
- [Deployment](#deployment)
- [Port Coverage](#port-coverage)
- [Extending the Tool](#extending-the-tool)

---

## What It Is

Port Analyzer is an offline-first intelligence tool for security engineers, penetration testers, and defenders. Given a port number, it assembles:

| Layer | What you get |
|---|---|
| **Identity** | IANA service name, transport protocol, assignment status |
| **Vulnerabilities** | CVEs from NVD, sorted by CVSS score, with severity and vector string |
| **Exploitation status** | CISA KEV flag — whether the CVE has a confirmed exploit in the wild |
| **Exploitation probability** | EPSS score (0–1) for each CVE |
| **ATT&CK mapping** | MITRE ATT&CK technique IDs, names, and tactics linked to the port |
| **Pentest notes** | Ready-to-run commands for the port (banners, brute force, tool flags) |
| **Defensive notes** | Hardening recommendations for the service |
| **Risk level** | Computed summary: CRITICAL / HIGH / MEDIUM / LOW |
| **Public PoC availability** | PoC count per CVE from nomi-sec PoC-in-GitHub — signals where exploit code is already public |
| **IoT vulnerability intelligence** | VARIoT — IoT-specific CVEs from CIRCL Luxembourg, often missing from NVD |

All data sources are free and open — no commercial feeds required.

---

## Data Sources

| Source | What it provides | Key required? |
|---|---|---|
| [NVD (NIST)](https://nvd.nist.gov/developers/vulnerabilities) | CVE details, CVSS scores, vector strings | No (optional — raises rate limit) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities list | No |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System | No |
| [IANA Registry](https://www.iana.org/assignments/service-names-port-numbers/) | Official service names and port assignments | No |
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique and tactic mappings | No |
| [PoC-in-GitHub (nomi-sec)](https://github.com/nomi-sec/PoC-in-GitHub) | Public PoC repo count per CVE; shows where exploit code is already public | No |
| [VARIoT](https://www.variot.eu/) | IoT-specific vulnerabilities by CIRCL Luxembourg (EU Horizon 2020) | No |

An optional NVD API key raises the NVD rate limit from 5 requests/30 s to 50 requests/30 s, which speeds up first-time queries significantly for large port ranges. Get one free at <https://nvd.nist.gov/developers/request-an-api-key>.

---

## Smart Caching

All fetched data is stored in a local SQLite database (`db/port_analyzer.db` by default).

- **First query** for a port: fetches the full CVE history from NVD, IANA identity, KEV list, EPSS scores, PoC availability from PoC-in-GitHub, and IoT vulns from VARIoT, then stores everything.
- **Subsequent queries**: served from cache. NVD is re-queried only for CVEs published after the last fetch date (cursor-based incremental update). CISA KEV is re-downloaded at most once every 24 hours. PoC-in-GitHub data is refreshed every 24 hours (top 20 CVEs by CVSS). VARIoT data is refreshed every 48 hours. IANA data is re-fetched at most once per year (assignments are nearly immutable).
- **`--no-live` flag**: skip all network calls entirely and serve from whatever is already cached.

This design means the tool is fast and works without a network connection once a port has been queried at least once.

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone https://github.com/your-username/port-analyzer.git
cd port-analyzer
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and fill in the values you want to use:

```ini
# Optional — raises NVD rate limit from 5 req/30s to 50 req/30s
NVD_API_KEY=

# Optional — GreyNoise community feed
GREYNOISE_API_KEY=

# SQLite database path (default shown)
DB_PATH=db/port_analyzer.db

# Backend secret for admin operations
ADMIN_SECRET=change-me-in-production

# CORS origins for the backend (comma-separated)
CORS_ORIGINS=http://localhost:8000,https://yourdomain.github.io
```

---

## Usage

### CLI

The CLI is the primary interface. It writes to the terminal with rich formatting and can also emit structured JSON for scripting.

```bash
# Single port
python -m port_analyzer 22

# Comma-separated list
python -m port_analyzer 22,443,8080

# Range
python -m port_analyzer 8080-8090

# Mixed range and individual ports
python -m port_analyzer 22,80-90,443

# JSON output (pipe-friendly)
python -m port_analyzer 22 --json

# Cache-only — no network calls
python -m port_analyzer 22 --no-live

# Control how many CVEs to display per port (default: 5)
python -m port_analyzer 22 --top 10

# Use a specific SQLite database
python -m port_analyzer 22 --db /path/to/custom.db

# Start the backend server instead of the CLI
python run.py --serve
```

**`run.py`** is a convenience entry point. Without `--serve` it forwards all arguments to the CLI:

```bash
python run.py 22
python run.py 22,443,8080
python run.py --serve        # starts backend on :8000
```

**CLI flags summary:**

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Print raw JSON instead of rich terminal output |
| `--no-live` | off | Skip all API calls; serve from local cache only |
| `--top N` | 5 | Number of top CVEs to display per port |
| `--report PATH` | off | Save a full markdown report to a file |
| `--sync` | off | Push results to GitHub Pages — uploads `web/data/ports/{port}.json` (all CVEs) and updates `web/data/ports.json` summary index (requires `GITHUB_PAT`) |
| `--db PATH` | `$DB_PATH` | Override the SQLite database path |
| `-h / --help` | — | Show help |

**Saving markdown reports:**

The `--report PATH` flag writes a full markdown intelligence report to a file instead of (or in addition to) terminal output. When multiple ports are analyzed, all reports are concatenated in the file with `---` separators. Reports include CVE IDs as clickable links to their NVD detail pages and MITRE technique IDs as links to the ATT&CK technique pages, and each report closes with a `## References` section listing all data sources used (IANA, NVD, CISA KEV if applicable, EPSS, MITRE ATT&CK) along with per-CVE and per-technique links.

```bash
# Save a single-port report
python -m port_analyzer 22 --report /tmp/port22.md

# Save a multi-port report (all ports concatenated into one file)
python -m port_analyzer 22,80,443 --report /tmp/report.md
```

Port ranges are capped at 1000 ports per invocation. All ports must be in the range 0–65535.

**Pushing results to the live GitHub Pages dataset (`--sync`):**

The `--sync` flag pushes the analyzed port data to GitHub Pages so the live site reflects it immediately. It commits two files per port:

| File | Contents |
|---|---|
| `web/data/ports/{port}.json` | **Full data** — all CVEs (e.g. all 1,369 for port 22), every field, PoC URLs, VARIoT entries, techniques, pentest/defensive notes |
| `web/data/ports.json` | **Summary index** — one lean entry per port (counts + top CVEs only); what the homepage loads |

After sync, the port's detail page (`ports.html?p=22`) loads all CVEs from its dedicated file, so the full CVE explorer is available in the browser. Because a Personal Access Token (PAT) — not the automatic `GITHUB_TOKEN` — is used, the push triggers a real push event and `deploy-pages.yml` fires automatically. The site typically updates within ~30 seconds.

**One-time setup — create a GitHub Fine-grained Personal Access Token:**

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Click **Generate new token**.
3. Under **Repository access**, select the `port-analyzer` repository only.
4. Under **Permissions → Repository permissions**, set **Contents** to **Read and write**.
5. Generate the token and copy it immediately (it is shown only once).
6. Set it in your shell:

**fish shell** (persists universally — recommended):
```fish
set -Ux GITHUB_PAT ghp_your_token_here
```

**bash / zsh** (add to `~/.bashrc` or `~/.zshenv` to persist):
```bash
export GITHUB_PAT=ghp_your_token_here
```

> **Note:** `export VAR=value` is bash syntax and does not work in fish. Use `set -Ux` in fish (`-U` = universal/persistent, `-x` = exported to subprocesses).

**Usage:**

```bash
# Analyze and push to the live site
python -m port_analyzer 31337 --sync
python -m port_analyzer 8080,4444 --sync

# Combine with other flags
python -m port_analyzer 22 --sync --report /tmp/port22.md
```

The `--sync` flag is also listed in the flags summary table above; add `GITHUB_PAT` to the table of environment variables in `.env` when you want it persisted across sessions.

---

### REST API

Start the backend:

```bash
python run.py --serve
# or directly:
uvicorn backend.main:app --reload --port 8000
```

The API is then available at `http://localhost:8000`. Interactive docs are at `/docs` (Swagger) and `/redoc`.

**Authentication:**

- Anonymous requests are allowed up to **20 requests per day** per IP.
- Register a free API key at `POST /api/v1/register` to get **1,000 requests per day**.
- Pass the key in the `X-API-Key` request header.

---

### Web UI

When the backend is running, the web UI is served automatically from `/` (the `web/` directory is mounted as static files by `backend/main.py`).

Open `http://localhost:8000` in a browser. Enter a port number, comma-separated list, or range in the search box and click **ANALYZE**. Results render inline without a page reload.

**Available ports panel:** If you search for a port that is not in the pre-built static dataset, the UI shows a helpful message pointing you to the CLI (`python -m port_analyzer.cli <port>`) and displays a collapsible panel listing all pre-built ports.

**Markdown report download:** Each result card includes a **↓ Report** button that generates a markdown intelligence report for that port and downloads it as `port-{N}-report.md` directly in the browser — no server round-trip required.

**CVE Explorer (`ports.html`):** Each port card shows a **Browse CVEs ↗** button (visible in static/GitHub Pages mode after `--sync` has been run for that port). Clicking it opens `ports.html?p=22` — a dedicated full CVE explorer page with:

- **Paginated CVE table** — 25 rows per page across all CVEs (up to 1,369+ for port 22)
- **Filters** — by severity (CRITICAL / HIGH / MEDIUM / LOW), KEV-only, PoC-only
- **Sort** — by CVSS score, EPSS probability, or CVE ID
- **Search** — partial CVE ID search (e.g. type `2024` to filter to CVEs from 2024)
- **Downloads** — export the current filtered view as CSV or JSON
- **VARIoT, ATT&CK, pentest/defensive sections** below the table

The page loads `data/ports/{port}.json` (the full file synced by `--sync`) and falls back to the summary `ports.json` if the per-port file is not yet available.

```
# Direct URL to port 22 CVE explorer (after syncing port 22):
https://fmfalgun.github.io/port-analyzer/ports.html?p=22
```

To use an API key in the web UI, click **Get API Key** in the navigation bar to register, then paste the key into the UI — it is stored in `localStorage` and sent automatically with each request.

---

## API Quick Reference

All endpoints are under `/api/v1`. Full interactive documentation is available at `/docs` after starting the backend.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/port/{port}` | Full analysis for a single port |
| `GET` | `/api/v1/ports?q=22,443,8080-8090` | Batch analysis (max 100 ports per request) |
| `GET` | `/api/v1/search?service=ssh` | Look up ports by service name |
| `GET` | `/api/v1/health` | Health check — returns `{"status": "ok"}` |
| `POST` | `/api/v1/register` | Register email, receive API key |
| `GET` | `/api/v1/key/info` | Check key usage and rate limit status |

**Example request:**

```bash
curl http://localhost:8000/api/v1/port/22 \
  -H "X-API-Key: pa-your-key-here"
```

**Example batch request:**

```bash
curl "http://localhost:8000/api/v1/ports?q=22,443,8080" \
  -H "X-API-Key: pa-your-key-here"
```

**Example service search:**

```bash
curl "http://localhost:8000/api/v1/search?service=redis"
```

---

## Deployment

### Railway or Render (recommended)

1. Push the repository to GitHub.
2. Create a new project on [Railway](https://railway.app) or [Render](https://render.com) and connect the GitHub repo.
3. Set the following environment variables in the platform dashboard:

   | Variable | Value |
   |---|---|
   | `NVD_API_KEY` | Your NVD API key (optional but recommended) |
   | `ADMIN_SECRET` | A strong random secret |
   | `CORS_ORIGINS` | Comma-separated list of allowed origins, e.g. `https://your-frontend.github.io` |
   | `DB_PATH` | `/data/port_analyzer.db` (or any persistent volume path) |

4. Set the start command to:
   ```
   uvicorn backend.main:app --host 0.0.0.0 --port $PORT
   ```

5. Point the web frontend to the deployed backend URL. Edit `web/index.html` and set `window.PA_CONFIG.apiBase`:
   ```js
   window.PA_CONFIG = {
     apiBase: "https://your-backend.railway.app"
   };
   ```
   Then redeploy the frontend (GitHub Pages, Netlify, or serve statically from the same backend).

### CORS configuration

The backend reads `CORS_ORIGINS` from the environment and passes it to FastAPI's `CORSMiddleware`. Set it to the exact origin(s) your frontend is served from to avoid browser CORS errors. Use `*` only for local development.

---

## Port Coverage

Port Analyzer has explicit NVD search terms and ATT&CK technique mappings for over 70 ports, including:

**Well-known and registered services:**
FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), DHCP (67/68), TFTP (69), HTTP (80), POP3 (110), RPCbind (111), NTP (123), MSRPC (135), NetBIOS (137/139), IMAP (143), SNMP (161), LDAP (389), HTTPS (443), SMB (445), rsync (873), MSSQL (1433), Oracle (1521), NFS (2049), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379), Elasticsearch (9200/9300), MongoDB (27017)

**Alternative HTTP and application servers:**
Tomcat/JBoss (8080), AJP (8009), HTTPS-alt (8443), Jupyter (8888), SonarQube (9000), Prometheus (9090), Kibana (5601)

**DevOps and cloud-native:**
Docker API (2375/2376), Kubernetes API (6443), Kubelet (10250), Zookeeper (2181), RabbitMQ/AMQP (5672), Memcached (11211), Hadoop HDFS (50070), Grafana (3000), SaltStack (4505)

**OT and IoT protocols:**
Modbus (502), MQTT/Mosquitto (1883), Android ADB (5555)

For IoT-facing ports, VARIoT supplements NVD with vendor-specific vulnerabilities that are often missing from or poorly enriched in the NVD corpus.

**VPN and tunnelling:**
OpenVPN (1194), SOCKS proxy (1080)

For any port not in the explicit list, Port Analyzer falls back to the IANA service name as the NVD search keyword. Pentest and defensive notes are currently hand-curated for the highest-value ports; all other ports still receive CVE, KEV, EPSS, and IANA data.

---

## Extending the Tool

All port-specific data lives in two files.

### Add NVD search terms — `port_analyzer/sources/iana.py`

`PORT_SEARCH_TERMS` maps a port number to a list of keyword strings that are sent to the NVD API:

```python
PORT_SEARCH_TERMS: dict[int, list[str]] = {
    # ...existing entries...
    9042: ["cassandra", "apache cassandra"],
    27018: ["mongodb"],
}
```

Use specific software names (not just the protocol) to improve CVE hit rate.

### Add ATT&CK technique mappings — `port_analyzer/sources/iana.py`

`PORT_TECHNIQUE_MAP` maps a port number to a list of `(technique_id, name, tactic)` tuples:

```python
PORT_TECHNIQUE_MAP: dict[int, list[tuple[str, str, str]]] = {
    # ...existing entries...
    9042: [
        ("T1190", "Exploit Public-Facing Application", "initial-access"),
        ("T1078", "Valid Accounts", "defense-evasion"),
    ],
}
```

Technique IDs follow the MITRE ATT&CK format (`Txxxx` or `Txxxx.yyy` for sub-techniques).

### Add pentest and defensive notes — `port_analyzer/engine.py`

`PENTEST_NOTES` and `DEFENSIVE_NOTES` are plain dicts mapping port numbers to lists of strings:

```python
PENTEST_NOTES: dict[int, list[str]] = {
    # ...existing entries...
    9042: [
        "Connect: cqlsh <host> 9042",
        "List keyspaces: DESCRIBE keyspaces;",
        "Tools: cqlsh, nmap --script cassandra*",
    ],
}

DEFENSIVE_NOTES: dict[int, list[str]] = {
    # ...existing entries...
    9042: [
        "Bind to 127.0.0.1 or private network only",
        "Enable authenticator: PasswordAuthenticator in cassandra.yaml",
        "Enable authorizer: CassandraAuthorizer",
    ],
}
```

No other changes are needed — the engine picks up new entries automatically.

# Port Analyzer — System Architecture & Microarchitecture

> Reference document for studying the full system design, data flows, and component interactions.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Three Output Surfaces](#2-three-output-surfaces)
3. [Data Source Layer](#3-data-source-layer)
4. [Smart Caching Architecture](#4-smart-caching-architecture)
5. [Static Data Pipeline (GitHub Actions)](#5-static-data-pipeline-github-actions)
   - 5.1 [Why GitHub Actions (not browser JS)](#51-why-github-actions-not-browser-js)
   - 5.2 [End-to-End Data Flow Diagram](#52-end-to-end-data-flow-diagram)
   - 5.3 [The workflow_run Trigger — Why It's Needed](#53-the-workflow_run-trigger--why-its-needed)
   - 5.4 [Key Implementation Fixes](#54-key-implementation-fixes)
   - 5.5 [Current Workflow Files](#55-current-workflow-files)
   - 5.7 [Static JSON Structure](#57-static-json-structure)
   - 5.8 [JS Fallback Decision Tree](#58-js-fallback-decision-tree)
6. [Request Flow — Per Surface](#6-request-flow--per-surface)
7. [SQLite Schema Design](#7-sqlite-schema-design)
8. [Security Architecture](#8-security-architecture)
9. [Deployment Architecture](#9-deployment-architecture)
10. [File Ownership Map](#10-file-ownership-map)
11. [Data Refresh Cycle](#11-data-refresh-cycle)
12. [Extension Points](#12-extension-points)
13. [Known Limitations](#13-known-limitations)

---

## 1. System Overview

Port Analyzer is a three-surface cybersecurity intelligence tool. A user inputs a port number (or range/list) and receives:

- IANA service identity and protocol assignment
- CVEs from NVD with CVSS scores and severity
- CISA KEV status (confirmed exploited in the wild)
- EPSS exploitation probability scores
- MITRE ATT&CK technique mappings
- Pentest notes (tools, checks, commands)
- Defensive recommendations

```
┌─────────────────────────────────────────────────────────────────┐
│                        PORT ANALYZER                            │
│                                                                 │
│  ┌──────────┐    ┌────────────────────┐    ┌─────────────────┐ │
│  │  CLI     │    │   Web UI           │    │   REST API      │ │
│  │ (Python) │    │ (GitHub Pages)     │    │ (FastAPI)       │ │
│  │          │    │                    │    │                 │ │
│  │port-ana- │    │ index.html         │    │ /api/v1/port/22 │ │
│  │lyzer 22  │    │ analyzer.js        │    │ /api/v1/ports   │ │
│  └────┬─────┘    └─────────┬──────────┘    └────────┬────────┘ │
│       │                    │                         │          │
│       └────────────────────┼─────────────────────────┘          │
│                            ▼                                    │
│              ┌─────────────────────────┐                        │
│              │      Query Engine       │                        │
│              │      engine.py          │                        │
│              └─────────────┬───────────┘                        │
│                            │                                    │
│              ┌─────────────▼───────────┐                        │
│              │     Cache Layer         │                        │
│              │     cache.py            │                        │
│              │     SQLite (WAL mode)   │                        │
│              └─────────────┬───────────┘                        │
│                            │                                    │
│    ┌───────────────────────┼───────────────────────────┐        │
│    ▼           ▼           ▼           ▼               ▼        │
│ ┌──────┐  ┌───────┐  ┌─────────┐  ┌──────┐  ┌──────────────┐  │
│ │ IANA │  │  NVD  │  │CISA KEV │  │ EPSS │  │MITRE ATT&CK  │  │
│ │ CSV  │  │API 2.0│  │JSON feed│  │ API  │  │ (seed map)   │  │
│ └──────┘  └───────┘  └─────────┘  └──────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Three Output Surfaces

### Surface A — CLI (Python, offline-first)

```
python -m port_analyzer 22
python -m port_analyzer 22,443,8080
python -m port_analyzer 8080-8090 --json
python -m port_analyzer 22 --no-live
```

- Entry point: `port_analyzer/cli.py` → `port_analyzer/engine.py`
- Output: Rich terminal (web-vapt style — `[i]`, `[>]`, `[+]`, `[!]` prefixes)
- Cache: local `db/port_analyzer.db` (SQLite)
- Offline: `--no-live` skips all API calls, reads only from SQLite

### Surface B — Web UI (GitHub Pages, static)

- URL: `https://YOUR_USERNAME.github.io/port-analyzer/`
- Files: `web/index.html` + `web/assets/js/analyzer.js` + `web/assets/css/style.css`
- **Dual mode** (decided by `window.PA_CONFIG.apiBase`):
  - `apiBase = ""` → **static mode**: reads pre-built `web/data/ports.json`
  - `apiBase = "https://..."` → **live mode**: calls FastAPI backend via REST

### Surface C — REST API (FastAPI backend)

- Entry: `backend/main.py` → `backend/routers/ports.py`
- Auth: `X-API-Key` header (self-registered at `/api/v1/register`)
- Rate limits: 20 req/day anonymous, 1,000 req/day with key
- Internally calls the same `engine.py` as the CLI

---

## 3. Data Source Layer

Each source is a standalone module in `port_analyzer/sources/`. All sources write to the shared SQLite cache. None are called directly by the CLI or API — everything goes through `engine.py`.

### 3.1 IANA (`sources/iana.py`)

```
URL: https://www.iana.org/assignments/service-names-port-numbers/
     service-names-port-numbers.csv

Fetch strategy: Once per port (IANA assignments are permanent)
Cache TTL:      8760 hours (1 year)
Output table:   port_profiles
Key data:       port number, transport (TCP/UDP/SCTP), service_name, description
```

Also contains two static Python dicts (no network call):
- `PORT_SEARCH_TERMS` — `{port: [keyword_list]}` used as NVD keyword search terms
- `PORT_TECHNIQUE_MAP` — `{port: [(technique_id, name, tactic)]}` seeded into `techniques` table

### 3.2 NVD (`sources/nvd.py`)

```
URL: https://services.nvd.nist.gov/rest/json/cves/2.0
Auth: Optional API key (NVD_API_KEY env var)
Rate: 5 req/30s without key (6.5s sleep), 50 req/30s with key (0.6s sleep)

Fetch strategy: CURSOR-BASED INCREMENTAL
  - First call:  no pubStartDate → fetches ALL historical CVEs
  - Repeat call: pubStartDate = cursor (last fetch's pubEndDate) → only NEW CVEs
  - Cursor stored in: fetch_log table, column 'cursor'

Pagination: resultsPerPage=100, loops until startIndex >= totalResults
Search:     keywordSearch = PORT_SEARCH_TERMS[port] (e.g. ["ssh", "openssh", "dropbear"])
Output:     cves table (cve_id, port, cvss_score, cvss_vector, cvss_severity, description, published_at)
```

The cursor mechanism is the core of the "smart cache" design:

```
First query for port 22:
  fetch_log has no entry → pubStartDate omitted → NVD returns ALL CVEs
  stores cursor = "2026-06-15T12:00:00.000" in fetch_log

Second query (next day):
  fetch_log.cursor = "2026-06-15T12:00:00.000"
  NVD called with pubStartDate="2026-06-15T12:00:00.000"
  Only returns CVEs published AFTER that date (usually 0-5 new ones)
  Cost: 1-2 API calls instead of 10-20
```

### 3.3 CISA KEV (`sources/cisa_kev.py`)

```
URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Auth: None
Fetch strategy: BLOB CACHE
  - Downloads full JSON blob (~300KB, ~1,500 entries)
  - Caches in cisa_kev_cache table with fetched_at timestamp
  - Cache TTL: 24 hours
  - Per-port filtering done locally (no per-port API call)

Per-port logic:
  1. Load blob from cache (or fetch if stale)
  2. Extract all cveID values into a Python set
  3. Read port's CVEs from SQLite
  4. Intersect → mark matching CVEs as exploited_in_wild=1
```

This is more efficient than querying per CVE — one blob download covers all 65535 ports.

### 3.4 EPSS (`sources/epss.py`)

```
URL: https://api.first.org/data/v1/epss?cve=CVE-XXXX,CVE-YYYY,...
Auth: None
Fetch strategy: BATCH SCORING
  - Groups all CVEs for a port into batches of 100
  - Single API call per batch
  - Updates epss_score + epss_percentile + epss_updated_at in cves table
  - Cache TTL: 24 hours (scores change daily)

Score meaning:
  epss_score      = probability (0.0–1.0) this CVE will be exploited in next 30 days
  epss_percentile = rank among all CVEs (0.97 = more likely than 97% of all CVEs)
```

### 3.5 MITRE ATT&CK (`sources/mitre_attack.py`)

```
Source: Static seed map PORT_TECHNIQUE_MAP in sources/iana.py
Fetch strategy: SEED (no network call)
  - On first query for a port, writes seed entries to techniques table
  - Cache TTL: 8760 hours (1 year)
  - Covers ~30 most-queried ports with T-code, name, tactic, ATT&CK URL

Future: full STIX bundle from GitHub (60MB) can be parsed offline and added
        as an optional --update-attack flag in the CLI
```

---

## 4. Smart Caching Architecture

The cache layer (`cache.py`) is the single source of truth for all persistent data. The core principle: **never re-fetch what you already have.**

### 4.1 Staleness Check

```python
def is_stale(db, port, source, max_age_hours) -> bool:
    row = fetch_log WHERE port=? AND source=?
    if no row: return True          # never fetched
    age = now - row.last_fetched
    return age > max_age_hours
```

Each source has its own TTL:

| Source | TTL | Reason |
|--------|-----|--------|
| IANA | 8760h (1yr) | Port assignments never change |
| NVD | 24h | New CVEs published daily |
| CISA KEV | 24h | New exploits confirmed daily |
| EPSS | 24h | Scores recalculated daily |
| MITRE ATT&CK | 8760h (1yr) | Seed map is static |

### 4.2 Fetch Log Table

```sql
fetch_log (
    port         INTEGER,
    source       TEXT,      -- 'iana', 'nvd', 'cisa_kev', 'epss', 'mitre'
    last_fetched TEXT,      -- ISO 8601 UTC timestamp
    cursor       TEXT,      -- NVD only: pubEndDate of last successful fetch
    PRIMARY KEY (port, source)
)
```

### 4.3 Query Engine Sequence (engine.py)

For every `analyze_port(port)` call:

```
1. fetch_iana_for_port(port)        → is_stale(port, 'iana', 8760h)?
   YES → download IANA CSV, parse, upsert port_profiles, update fetch_log
   NO  → skip

2. seed_techniques_for_port(port)   → is_stale(port, 'mitre', 8760h)?
   YES → write PORT_TECHNIQUE_MAP[port] to techniques table
   NO  → skip

3. fetch_nvd_for_port(port, terms)  → is_stale(port, 'nvd', 24h)?
   YES → get cursor from fetch_log, call NVD with pubStartDate=cursor,
         upsert new CVEs, update fetch_log with new cursor
   NO  → skip

4. apply_kev_to_port(port)          → get_cisa_kev_cache() stale?
   YES → download full CISA KEV blob, cache it, mark port's CVEs
   NO  → use cached blob, mark port's CVEs

5. fetch_epss_for_port(port)        → is_stale(port, 'epss', 24h)?
   YES → batch-fetch EPSS for all port's CVE IDs, update scores
   NO  → skip

6. read everything from SQLite → assemble result dict → return
```

---

## 5. Static Data Pipeline (GitHub Actions)

This is the "no-backend" mode — a GitHub Actions workflow runs on a cron schedule, fetches data server-side (bypassing browser CORS restrictions), and commits a pre-built JSON file that GitHub Pages serves statically.

### 5.1 Why GitHub Actions (not browser JS)

Browser JS cannot call NVD/CISA/EPSS directly:

```
Browser → fetch("https://services.nvd.nist.gov/...") → CORS blocked
Browser → fetch("https://www.cisa.gov/feeds/...")    → CORS blocked
Browser → fetch("https://api.first.org/...")         → CORS blocked
```

These APIs are designed for server-to-server calls and don't send `Access-Control-Allow-Origin` headers. GitHub Actions runs Python server-side — no CORS restriction.

### 5.2 End-to-End Data Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                    STATIC DATA PIPELINE                                │
│                                                                        │
│  ┌──────────────────────────────────┐                                  │
│  │  Cron trigger (0 2 * * *)        │                                  │
│  │  or workflow_dispatch (manual)   │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  build-data.yml                  │                                  │
│  │  (GitHub Actions runner)         │                                  │
│  │                                  │                                  │
│  │  env: PYTHONPATH=$workspace      │  ← required: runner doesn't     │
│  │  env: NVD_API_KEY=<secret>       │    add repo root automatically  │
│  │                                  │                                  │
│  │  python scripts/build_data.py    │                                  │
│  │    for each port in PORT_LIST    │                                  │
│  │    (~115 ports):                 │                                  │
│  │      engine.analyze_port(port)   │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  Sources (server-side, no CORS)  │                                  │
│  │  ┌──────┐ ┌─────┐ ┌──────────┐  │                                  │
│  │  │ IANA │ │ NVD │ │CISA KEV  │  │                                  │
│  │  └──────┘ └─────┘ └──────────┘  │                                  │
│  │  ┌──────┐ ┌──────────────────┐  │                                  │
│  │  │ EPSS │ │  MITRE ATT&CK    │  │                                  │
│  │  └──────┘ └──────────────────┘  │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  SQLite cache                    │                                  │
│  │  db/port_analyzer.db             │                                  │
│  │  (WAL mode, per-run ephemeral)   │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  web/data/ports.json             │                                  │
│  │  (written by build_data.py)      │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  git status --porcelain          │  ← detects new + modified files  │
│  │  if changed:                     │    (git diff misses new files)   │
│  │    git commit + git push         │                                  │
│  │    (permissions: contents:write) │  ← explicit permission required  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  GITHUB_TOKEN push               │                                  │
│  │  (does NOT fire push event)      │  ← GitHub security restriction:  │
│  │                                  │    token pushes don't trigger    │
│  │                                  │    on: push workflows            │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  workflow_run trigger            │  ← deploy-pages.yml watches for  │
│  │  (deploy-pages.yml fires when    │    "Build Port Data" completion  │
│  │   build-data.yml completes)      │    instead of the push event     │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  deploy-pages.yml                │                                  │
│  │  uploads web/ → Pages artifact  │                                  │
│  │  (only runs if build succeeded)  │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  GitHub Pages CDN                │                                  │
│  │  serves web/ including           │                                  │
│  │  web/data/ports.json             │                                  │
│  └──────────────┬───────────────────┘                                  │
│                 │                                                       │
│                 ▼                                                       │
│  ┌──────────────────────────────────┐                                  │
│  │  Browser                         │                                  │
│  │  fetch("data/ports.json")        │                                  │
│  │  same-origin → no CORS           │                                  │
│  └──────────────────────────────────┘                                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.3 The workflow_run Trigger — Why It's Needed

GitHub blocks workflows triggered by `GITHUB_TOKEN` pushes from firing `on: push` events in other workflows. This is a deliberate security restriction to prevent infinite trigger loops.

Without `workflow_run`:

```
build-data.yml pushes ports.json
  → GITHUB_TOKEN push does NOT fire push event
  → deploy-pages.yml never runs
  → Pages still serves the OLD ports.json
```

With `workflow_run` (current implementation):

```
build-data.yml completes
  → GitHub fires "workflow_run completed" event
  → deploy-pages.yml's workflow_run trigger fires
  → Pages is redeployed with the new ports.json
```

The `deploy-pages.yml` guard ensures it only deploys on a successful build:

```yaml
if: ${{ github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success' }}
```

### 5.4 Key Implementation Fixes

Three subtle bugs were resolved to make the pipeline reliable:

**PYTHONPATH fix**

The GitHub Actions runner does not add the repo root to `PYTHONPATH`. Without this, `import port_analyzer` fails with `ModuleNotFoundError`. Fixed by setting:

```yaml
env:
  PYTHONPATH: ${{ github.workspace }}
```

**git status --porcelain for change detection**

`git diff` only detects modified tracked files — it misses untracked new files. On the first run, `web/data/ports.json` doesn't exist yet, so `git diff` reports no changes and the commit is skipped. Fixed by using:

```bash
git status --porcelain web/data/ports.json
```

**contents: write permission**

`GITHUB_TOKEN` has read-only permissions by default in modern GitHub Actions. To commit and push the updated `ports.json`, the workflow job must declare:

```yaml
permissions:
  contents: write
```

### 5.5 Current Workflow Files

**`.github/workflows/build-data.yml`** (data fetch + commit):

```yaml
name: Build Port Data

on:
  schedule:
    - cron: '0 2 * * *'   # 2 AM UTC daily
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Build port data
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          PYTHONPATH: ${{ github.workspace }}
        run: python scripts/build_data.py

      - name: Check for changes
        id: diff
        run: |
          if [[ -n "$(git status --porcelain web/data/ports.json)" ]]; then
            echo "changed=true" >> $GITHUB_OUTPUT
          fi

      - name: Commit and push updated data
        if: steps.diff.outputs.changed == 'true'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add web/data/ports.json
          git commit -m "data: refresh port intelligence"
          git push origin master
```

**`.github/workflows/deploy-pages.yml`** (deploy web/ to Pages):

```yaml
name: Deploy Web to GitHub Pages

on:
  push:
    branches: [master]
    paths:
      - "web/**"
      - ".github/workflows/deploy-pages.yml"
  workflow_dispatch:
  workflow_run:
    workflows: ["Build Port Data"]
    types: [completed]
    branches: [master]

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  deploy:
    if: ${{ github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success' }}
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: web
      - id: deployment
        uses: actions/deploy-pages@v4
```

### 5.7 Static JSON Structure

```json
{
  "_meta": {
    "generated_at": "2026-06-15T02:00:00Z",
    "port_count": 115,
    "sources": ["IANA", "NVD", "CISA KEV", "EPSS", "MITRE ATT&CK"]
  },
  "22": {
    "port": 22,
    "service_name": "ssh",
    "transport": ["TCP", "UDP", "SCTP"],
    "iana_status": "...",
    "risk_level": "HIGH",
    "cve_count": 45,
    "kev_count": 3,
    "top_cves": [
      {
        "cve_id": "CVE-2023-38408",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "epss_score": 0.94,
        "epss_percentile": 0.99,
        "exploited_in_wild": 1,
        "description": "..."
      }
    ],
    "techniques": [
      { "technique_id": "T1021.004", "name": "Remote Services: SSH", "tactic": "lateral-movement" }
    ],
    "pentest_notes": ["Banner grab: nc -nv <host> 22", "..."],
    "defensive_notes": ["Disable PasswordAuthentication", "..."]
  }
}
```

### 5.8 JS Fallback Decision Tree

```
User enters "22" in web UI
         │
         ▼
  API_BASE empty?
    /        \
  YES         NO
   │           │
   ▼           ▼
fetch(          call API_BASE
 "data/         + /api/v1/port/22
  ports.json")   (live FastAPI)
   │
   ▼
data["22"] exists?
  /        \
YES         NO
 │           │
 ▼           ▼
render      show message:
result      "port not in static
            dataset — deploy
            backend for live"
```

---

## 6. Request Flow — Per Surface

### 6.1 CLI Request Flow

```
$ python -m port_analyzer 22

cli.py: parse_port_input("22") → [22]
         │
         ▼
cli.py: analyze_port(22, db)  ← db = get_db() from cache.py
         │
         ▼
engine.py: analyze_port(22, db)
  │
  ├── sources/iana.py:         fetch_iana_for_port(22, db)
  ├── sources/mitre_attack.py: seed_techniques_for_port(22, db)
  ├── sources/nvd.py:          fetch_nvd_for_port(22, ["ssh","openssh",...], db)
  ├── sources/cisa_kev.py:     apply_kev_to_port(22, db)
  └── sources/epss.py:         fetch_epss_for_port(22, db)
         │
         ▼
     read from SQLite → assemble result dict
         │
         ▼
renderer.py: render_port(result)
  → Rich terminal output with [i]/[>]/[+]/[!] prefixes
```

### 6.2 Web UI Live Mode Request Flow

```
User: types "22" → clicks ANALYZE

analyzer.js: query("22")
  → API_BASE is set ("https://backend.railway.app")
  → apiFetch("/api/v1/port/22")
      → fetch(API_BASE + "/api/v1/port/22", {
          headers: {"X-API-Key": localStorage.pa_api_key}
        })

backend/routers/ports.py: GET /api/v1/port/22
  → _auth(request):
      key present? → check rate limit in SQLite → increment usage
      no key?      → check IP rate limit (20/day) in SQLite
  → analyze_port(22, db)   ← same engine.py as CLI
  → return JSON

analyzer.js: renderResults([result])
  → buildCard(result) → innerHTML with esc() XSS protection
```

### 6.3 Web UI Static Mode Request Flow

```
User: types "22" → clicks ANALYZE

analyzer.js: query("22")
  → API_BASE is "" (empty)
  → loadStaticData()
      → _staticCache exists? return it
      → fetch("data/ports.json")   ← same-origin GitHub Pages, no CORS
      → cache in _staticCache
  → data["22"] exists? → push to results
  → renderResults([data["22"]])    ← same render path as live mode
```

### 6.4 GitHub Pages Data Serving

```
Browser → GET https://fmfalgun.github.io/port-analyzer/data/ports.json

GitHub Pages:
  reads from repo: web/data/ports.json
  serves with:     Content-Type: application/json
                   Cache-Control: max-age=600 (10 min browser cache)

No server-side code runs. Pure static file serving.
File is updated by: GitHub Actions build-data.yml (commits daily)
```

---

## 7. SQLite Schema Design

Database: `db/port_analyzer.db` (WAL mode for concurrent reads)

```sql
-- Port identity (from IANA, permanent)
port_profiles (
    port        INTEGER,
    transport   TEXT,        -- TCP / UDP / SCTP
    service_name TEXT,
    description  TEXT,
    iana_status  TEXT,
    fetched_at   TEXT,
    PRIMARY KEY (port, transport)
)

-- CVEs linked to a port's service (append-only via ON CONFLICT DO UPDATE)
cves (
    cve_id           TEXT PRIMARY KEY,
    port             INTEGER,
    cvss_score       REAL,
    cvss_vector      TEXT,
    cvss_severity    TEXT,     -- CRITICAL / HIGH / MEDIUM / LOW
    epss_score       REAL,     -- 0.0–1.0
    epss_percentile  REAL,     -- 0.0–1.0
    exploit_type     TEXT,     -- RCE / LPE / DoS / InfoDisc / AuthBypass
    exploited_in_wild INTEGER DEFAULT 0,  -- 1 if in CISA KEV
    description      TEXT,
    published_at     TEXT,
    fetched_at       TEXT,
    epss_updated_at  TEXT
)

-- ATT&CK techniques per port (from seed map, one-time write)
techniques (
    technique_id TEXT,
    port         INTEGER,
    name         TEXT,
    tactic       TEXT,
    url          TEXT,
    fetched_at   TEXT,
    PRIMARY KEY (technique_id, port)
)

-- Per-(port, source) fetch tracking — the smart cache control table
fetch_log (
    port         INTEGER,
    source       TEXT,     -- 'iana' / 'nvd' / 'cisa_kev' / 'epss' / 'mitre'
    last_fetched TEXT,
    cursor       TEXT,     -- NVD only: ISO datetime for next pubStartDate
    PRIMARY KEY (port, source)
)

-- CISA KEV blob (one row, replaced every 24h)
cisa_kev_cache (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    fetched_at TEXT,
    data       TEXT     -- full JSON blob
)

-- API key registry (self-registered)
api_keys (
    key              TEXT PRIMARY KEY,
    email            TEXT UNIQUE,
    created_at       TEXT,
    last_used        TEXT,
    requests_today   INTEGER DEFAULT 0,
    rate_limit       INTEGER DEFAULT 1000,
    reset_date       TEXT
)

-- IP-based rate limiting for anonymous requests
rate_limit_ip (
    ip       TEXT,
    date     TEXT,
    requests INTEGER DEFAULT 0,
    PRIMARY KEY (ip, date)
)
```

---

## 8. Security Architecture

### 8.1 API Authentication Flow

```
Client request → backend/routers/ports.py: _auth(request)
                    │
                    ├── X-API-Key present?
                    │   YES → get_api_key(db, key)
                    │         → not found: 401 Unauthorized
                    │         → found: check_key_rate_limit(db, key)
                    │           → over limit: 429 Too Many Requests
                    │           → ok: increment_key_usage(db, key) → proceed
                    │
                    └── no key → check_ip_rate_limit(db, ip, limit=20)
                                  → over limit: 429 (suggest registration)
                                  → ok: proceed (anonymous tier)
```

### 8.2 API Key Generation

```
POST /api/v1/register {"email": "user@example.com"}
  → validate email format (regex)
  → email_exists(db, email)? → 409 Conflict
  → key = "pa-" + secrets.token_urlsafe(32)
    (cryptographically secure, 43-char random suffix, 256-bit entropy)
  → create_api_key(db, email, key, rate_limit=1000)
  → return {api_key, email, rate_limit, message}
```

### 8.3 XSS Mitigation (Web UI)

All API-sourced strings go through `esc()` before innerHTML injection:

```javascript
function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}
```

MITRE ATT&CK URLs validated before use as `href` (must start with `https://attack.mitre.org/`).

### 8.4 CORS Guard

`backend/main.py` refuses to start if `CORS_ORIGINS` is unset or `*`:

```python
if not _cors_env or _cors_env.strip() == "*":
    if os.getenv("CORS_ALLOW_WILDCARD", "0") != "1":
        print("ERROR: CORS_ORIGINS is unset or '*'...")
        sys.exit(1)
```

Production must set `CORS_ORIGINS=https://YOUR_USERNAME.github.io`.

### 8.5 SQL Injection Prevention

All SQLite queries use parameterized statements:

```python
# Always like this — never string concatenation
db.execute("SELECT * FROM cves WHERE port=?", (port,))
db.execute("INSERT INTO api_keys ... VALUES (?, ?, ?, ...)", (key, email, ...))
```

---

## 9. Deployment Architecture

### 9.1 Production Layout

```
GitHub Repository (fmfalgun/port-analyzer)
│
├── master branch
│   ├── port_analyzer/    ← Python package (CLI + engine + sources)
│   ├── backend/          ← FastAPI (deployed to Railway/Render)
│   ├── web/              ← Static frontend (deployed to GitHub Pages)
│   │   └── data/ports.json  ← pre-built by GitHub Actions daily
│   ├── scripts/          ← build_data.py (runs in GitHub Actions)
│   └── .github/workflows/
│       ├── deploy-pages.yml   ← deploys web/ to Pages on push
│       └── build-data.yml     ← cron: fetches data, updates ports.json
│
├── GitHub Pages
│   └── https://YOUR_USERNAME.github.io/port-analyzer/
│       serves: web/ directory
│
└── Railway/Render (separate service)
    └── https://your-backend.railway.app
        runs: uvicorn backend.main:app
        env:  NVD_API_KEY, CORS_ORIGINS, DB_PATH, ADMIN_SECRET
```

### 9.2 Data Flow in Production (Live Mode)

```
User browser (GitHub Pages)
  │
  │  1. GET /port-analyzer/  → GitHub Pages serves index.html
  │  2. GET /port-analyzer/assets/js/analyzer.js → Pages serves JS
  │  3. User types "22", clicks Analyze
  │  4. JS: fetch("https://backend.railway.app/api/v1/port/22",
  │              {headers: {"X-API-Key": "pa-..."}})
  │
  ▼
Railway (FastAPI backend)
  │
  │  5. _auth() validates API key from SQLite
  │  6. analyze_port(22, db) runs full pipeline
  │     → IANA (cached), NVD (incremental), CISA KEV (24h blob),
  │       EPSS (24h batch), ATT&CK (seeded)
  │  7. Returns JSON
  │
  ▼
User browser
  8. renderResults() → buildCard() → displays port intelligence
```

### 9.3 Data Flow in Static Mode (GitHub Pages Only)

```
User browser (GitHub Pages)
  │
  │  1. GET /port-analyzer/ → index.html
  │  2. User types "22", clicks Analyze
  │  3. JS: API_BASE empty → loadStaticData()
  │  4. fetch("data/ports.json")  ← same-origin, no CORS
  │
  ▼
GitHub Pages
  5. serves web/data/ports.json (committed to repo)
  │
  ▼
User browser
  6. data["22"] found → renderResults() → same UI as live mode
```

### 9.4 GitHub Actions Triggers

```
Push to master (web/** changed)
  → deploy-pages.yml triggers (on: push paths: web/**)
  → uploads web/ to GitHub Pages environment
  → Pages live in ~30s

Cron 0 2 * * * (daily 2AM UTC)
  → build-data.yml triggers
  → runs build_data.py → NVD_API_KEY from GitHub Secrets
  → if ports.json changed: commits + pushes via GITHUB_TOKEN
  → GITHUB_TOKEN push does NOT fire on: push event (GitHub restriction)
  → build-data.yml completion fires workflow_run event
  → deploy-pages.yml workflow_run trigger picks it up
  → Pages redeployed with new ports.json in ~1-2 min

Manual redeploy
  → workflow_dispatch on either workflow
  → build-data: refetches and commits data
  → deploy-pages: redeploys current web/ to Pages
```

---

## 10. File Ownership Map

| File | Layer | Responsibility |
|------|-------|----------------|
| `port_analyzer/cache.py` | Data | SQLite schema, all CRUD, staleness checks |
| `port_analyzer/sources/iana.py` | Data | IANA fetch + PORT_SEARCH_TERMS + PORT_TECHNIQUE_MAP |
| `port_analyzer/sources/nvd.py` | Data | NVD API 2.0, cursor pagination, CVSS parse |
| `port_analyzer/sources/cisa_kev.py` | Data | CISA KEV blob, 24h cache, per-port filter |
| `port_analyzer/sources/epss.py` | Data | EPSS batch scoring, daily refresh |
| `port_analyzer/sources/mitre_attack.py` | Data | ATT&CK seed writer |
| `port_analyzer/engine.py` | Logic | Orchestration + PENTEST_NOTES + DEFENSIVE_NOTES |
| `port_analyzer/renderer.py` | CLI UI | Rich terminal output, web-vapt style |
| `port_analyzer/cli.py` | CLI UI | Click CLI, flag parsing, --no-live mode |
| `backend/main.py` | API | FastAPI app, CORS guard, docs toggle, static mount |
| `backend/routers/ports.py` | API | Route handlers, auth/rate-limit check |
| `backend/routers/auth.py` | API | API key registration, key info |
| `web/index.html` | Web UI | Main page, PA_CONFIG (apiBase + staticDataUrl) |
| `web/register.html` | Web UI | API key self-registration page |
| `web/assets/js/analyzer.js` | Web UI | Fetch, static fallback, render, XSS protection |
| `web/assets/css/style.css` | Web UI | Dark cyber theme (portfolio palette) |
| `web/data/ports.json` | Web Data | Pre-built static port intelligence (generated) |
| `scripts/build_data.py` | Pipeline | Fetches all sources for PORT_LIST → ports.json |
| `.github/workflows/deploy-pages.yml` | CI/CD | Deploys web/ to GitHub Pages on push |
| `.github/workflows/build-data.yml` | CI/CD | Cron: fetches data, commits ports.json |

---

## 11. Data Refresh Cycle

```
Timeline:

Day 0  │  First build_data.py run
       │  → fetches IANA (all), NVD (all historical), CISA KEV, EPSS
       │  → stores in SQLite, writes ports.json
       │  → commits to repo, Pages serves immediately

Day 1  │  build-data.yml cron triggers (2AM UTC)
       │  → for each port:
       │     NVD: pubStartDate = yesterday's cursor → only ~0-5 new CVEs per port
       │     CISA KEV: blob re-downloaded (24h TTL expired) → re-filtered
       │     EPSS: scores re-fetched (values drift daily)
       │     IANA: skipped (8760h TTL)
       │     ATT&CK: skipped (8760h TTL)
       │  → ports.json updated with deltas
       │  → commit + push → workflow_run fires deploy-pages.yml
       │  → Pages redeployed and live in ~1-2 min

Day 365│  IANA TTL expires → re-fetches CSV (usually identical)
       │  ATT&CK seed TTL expires → re-seeds from static map (identical)
```

### Cost analysis (with NVD API key):

```
Per-port per day (after initial build):
  NVD incremental: ~1-2 API calls × 0.6s = ~1.2s per port
  EPSS batch:      1 call per 100 CVEs → negligible
  CISA KEV:        1 blob download shared across ALL ports = ~0.3s total

~115 ports × 1.5s average = ~175s ≈ 3 minutes per daily run
GitHub Actions free tier: 2000 min/month → using ~90 min/month (~5% of free tier)
```

---

## 12. Extension Points

### Add a new port to the static dataset

In `port_analyzer/sources/iana.py`:

```python
PORT_SEARCH_TERMS[8888] = ["jupyter", "jupyter notebook", "jupyterhub"]
PORT_TECHNIQUE_MAP[8888] = [
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", "execution"),
]
```

In `port_analyzer/engine.py`:

```python
PENTEST_NOTES[8888] = [
    "Default Jupyter has no auth — direct code execution",
    "curl http://<host>:8888/api/kernels → check if open",
    "Tools: jupyter-client, curl, metasploit jupyter_open_socket",
]
DEFENSIVE_NOTES[8888] = [
    "Always set a password or token: jupyter notebook --NotebookApp.token=''",
    "Never expose to internet — bind to 127.0.0.1 only",
    "Use JupyterHub with OAuth for multi-user setups",
]
```

Then add `8888` to `PORT_LIST` in `scripts/build_data.py`.

### Add a new data source

1. Create `port_analyzer/sources/new_source.py`
2. Follow the pattern: check `is_stale()`, fetch, call `update_fetch_log()`
3. Call it in `engine.py: analyze_port()` after existing source calls
4. Add new tables to `cache.py: SCHEMA` if needed

### Switch from static JSON to live API on the web

Update `web/index.html`:

```javascript
window.PA_CONFIG = {
  apiBase: "https://your-backend.railway.app",  // set this
  staticDataUrl: "data/ports.json"              // kept as fallback
};
```

The JS automatically uses live mode when `apiBase` is non-empty.

---

## 13. Known Limitations

### Static mode: pre-built port set only

The GitHub Pages static mode serves `web/data/ports.json` which is built from `PORT_LIST` in `scripts/build_data.py`. This list currently contains **~115 ports** (54 well-known, 61 registered). Ports outside this list return a "port not in static dataset" message. Live FastAPI mode has no such restriction — it queries any port 0–65535 on demand.

`PORT_LIST` is split into two groups:

- **WELL_KNOWN** — ports 0–1023 commonly exploited during pentests (22, 23, 25, 53, 80, 443, 445, etc.)
- **REGISTERED** — ports 1024–49151 for common services (databases, message queues, web frameworks, k8s, industrial protocols, etc.)

To add a port, see [Section 12](#12-extension-points).

### workflow_run: no artifact sharing

`deploy-pages.yml` triggered by `workflow_run` re-checks out the repo and re-uploads `web/` as a Pages artifact. It does not consume build artifacts from `build-data.yml`. This is by design — the committed `ports.json` is the canonical output.

### NVD rate limiting without API key

Without `NVD_API_KEY` set in GitHub Secrets, NVD allows 5 requests per 30 seconds with a 6-second sleep between calls. For ~115 ports, the initial full historical fetch can take 30–60 minutes. Subsequent incremental runs are fast regardless (1–2 calls per port). Set `NVD_API_KEY` for production to use the 50 req/30s tier.

### Live API backend: not deployed by default

The FastAPI backend (`backend/main.py`) must be deployed separately (Railway, Render, Fly.io, etc.). The default GitHub Pages deployment uses static mode only. Set `window.PA_CONFIG.apiBase` in `web/index.html` to enable live mode.

### Interactive API docs disabled in production

Swagger UI (`/docs`) and ReDoc (`/redoc`) are disabled by default. Set `ENABLE_DOCS=1` in the backend environment to enable them.

---

*Document version: 1.1 — Updated 2026-06-15*

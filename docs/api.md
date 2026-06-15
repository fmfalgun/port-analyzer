# Port Analyzer — API Reference & Integration Guide

> Cybersecurity intelligence for any port: CVEs, MITRE ATT&CK techniques, CISA KEV, EPSS exploitation scores, and pentest/defensive notes.

---

## Table of Contents

**Part 1 — API Reference**

1. [Authentication](#1-authentication)
2. [Rate Limits](#2-rate-limits)
3. [Base URL](#3-base-url)
4. [Endpoints](#4-endpoints)
   - [GET /api/v1/port/{port}](#get-apiv1portport)
   - [GET /api/v1/ports](#get-apiv1ports)
   - [GET /api/v1/search](#get-apiv1search)
   - [POST /api/v1/register](#post-apiv1register)
   - [GET /api/v1/key/info](#get-apiv1keyinfo)
   - [GET /api/v1/health](#get-apiv1health)
5. [Port Result Object Schema](#5-port-result-object-schema)
6. [Error Codes](#6-error-codes)

**Part 2 — Integrating from a Static Website**

7. [Configuring the Backend URL (PA_CONFIG)](#7-configuring-the-backend-url-pa_config)
8. [CORS Configuration](#8-cors-configuration)
9. [API Key Storage in the Browser](#9-api-key-storage-in-the-browser)
10. [URL Parameter Deep-Linking](#10-url-parameter-deep-linking)
11. [Vanilla JS Fetch Example](#11-vanilla-js-fetch-example)
12. [Rate Limit Recommendations for Embedded Use](#12-rate-limit-recommendations-for-embedded-use)

**Part 3 — Portfolio Integration**

13. [Static Data URL (No Backend Required)](#13-static-data-url-no-backend-required)
14. [Embed via iframe](#14-embed-via-iframe)
15. [Query the API Directly from a Portfolio Site](#15-query-the-api-directly-from-a-portfolio-site)
16. [Web UI Features — Pre-Built Ports and Markdown Download](#16-web-ui-features----pre-built-ports-and-markdown-download)

**Part 4 — CLI Reference**

17. [`--sync`: Push Analysis Results to GitHub Pages](#17---sync-push-analysis-results-to-github-pages)
18. [Markdown Reports — Clickable Links and References Section](#18-markdown-reports----clickable-links-and-references-section)

---

## Part 1 — API Reference

### 1. Authentication

All endpoints accept an optional `X-API-Key` header. Requests without this header are served anonymously at a reduced rate limit.

**Obtaining a key:** send a `POST /api/v1/register` request with your email address (see [below](#post-apiv1register)). The response contains your key immediately — save it, it is not stored in a retrievable form after the response.

**Key format:** keys are prefixed with `pa-` followed by a 32-byte URL-safe random token, e.g.:

```
pa-Xk9mR2vTqL8nJwPzYcAoD5sBuFhNiE3eGlV0tCx1Wy
```

**Using the key in requests:**

```bash
curl -H "X-API-Key: pa-your-key-here" \
     https://your-backend-url.com/api/v1/port/22
```

If the key is absent, the API falls back to anonymous rate limits. If the key is present but not recognised, the API returns `401`.

---

### 2. Rate Limits

| Tier | Limit | Scope |
|---|---|---|
| Anonymous (no key) | 20 requests / day | Per IP address |
| Authenticated (with key) | 1,000 requests / day | Per API key |

When a limit is exceeded the API returns `429` with a `detail` field describing the current usage, e.g.:

```json
{ "detail": "Rate limit exceeded (1000/1000 requests today)" }
```

Anonymous users who hit their limit are directed to register at `POST /api/v1/register`.

---

### 3. Base URL

All paths below are relative to your deployed backend, e.g.:

```
https://your-backend-url.com
```

Interactive docs (Swagger UI) are available at `/docs` and ReDoc at `/redoc` when `ENABLE_DOCS=1` is set in the backend environment (disabled by default).

---

### 4. Endpoints

---

#### GET /api/v1/port/{port}

Retrieve full cybersecurity intelligence for a single port number.

**Path parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `port` | integer | yes | Port number, 0–65535 |

**Example request**

```bash
curl -H "X-API-Key: pa-your-key-here" \
     https://your-backend-url.com/api/v1/port/22
```

**Example response** — `200 OK`

```json
{
  "port": 22,
  "service_name": "ssh",
  "transport": ["TCP"],
  "iana_status": "Assigned",
  "risk_level": "HIGH",
  "cve_count": 47,
  "kev_count": 3,
  "top_cves": [
    {
      "cve_id": "CVE-2023-38408",
      "cvss_score": 9.8,
      "cvss_severity": "CRITICAL",
      "epss_score": 0.9341,
      "exploited_in_wild": true,
      "description": "Remote code execution in OpenSSH's ssh-agent forwarding via a malicious PKCS#11 provider."
    },
    {
      "cve_id": "CVE-2024-6387",
      "cvss_score": 8.1,
      "cvss_severity": "HIGH",
      "epss_score": 0.8812,
      "exploited_in_wild": true,
      "description": "regreSSHion: race condition in OpenSSH sshd signal handler leading to unauthenticated RCE."
    }
  ],
  "techniques": [
    {
      "technique_id": "T1021.004",
      "name": "Remote Services: SSH",
      "tactic": "lateral-movement",
      "url": "https://attack.mitre.org/techniques/T1021/004/"
    },
    {
      "technique_id": "T1563.001",
      "name": "Remote Service Session Hijacking: SSH Hijacking",
      "tactic": "lateral-movement",
      "url": "https://attack.mitre.org/techniques/T1563/001/"
    }
  ],
  "pentest_notes": [
    "Attempt authentication with default or weak credentials using Hydra or Medusa.",
    "Check OpenSSH version banner against known CVE list; regreSSHion (CVE-2024-6387) affects versions < 9.8p1.",
    "Test for SSH agent forwarding abuse on compromised intermediate hosts.",
    "Enumerate valid users via timing differences (older OpenSSH versions)."
  ],
  "defensive_notes": [
    "Disable password authentication; enforce public-key only.",
    "Restrict source IPs via firewall rules or /etc/hosts.allow.",
    "Upgrade OpenSSH to >= 9.8p1 to mitigate regreSSHion.",
    "Enable fail2ban or equivalent to block brute-force attempts.",
    "Disable SSH agent forwarding unless explicitly required."
  ]
}
```

**Error responses:** `400` if the port is outside 0–65535; `429` on rate limit; `500` on internal error.

---

#### GET /api/v1/ports

Retrieve intelligence for multiple ports in a single request. Accepts a comma-separated list of ports and/or port ranges.

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `q` | string | yes | Comma-separated ports and/or ranges, e.g. `22,443,8080-8090` |

**Constraints:** maximum 100 ports per request (after range expansion).

**Example requests**

```bash
# Comma list
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend-url.com/api/v1/ports?q=22,80,443"

# Range
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend-url.com/api/v1/ports?q=8080-8090"

# Mixed
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend-url.com/api/v1/ports?q=22,80-90,443"
```

**Example response** — `200 OK`

```json
{
  "ports": [
    {
      "port": 22,
      "service_name": "ssh",
      "transport": ["TCP"],
      "iana_status": "Assigned",
      "risk_level": "HIGH",
      "cve_count": 47,
      "kev_count": 3,
      "top_cves": [ "..." ],
      "techniques": [ "..." ],
      "pentest_notes": [ "..." ],
      "defensive_notes": [ "..." ]
    },
    {
      "port": 80,
      "service_name": "http",
      "transport": ["TCP"],
      "iana_status": "Assigned",
      "risk_level": "MEDIUM",
      "cve_count": 312,
      "kev_count": 18,
      "top_cves": [ "..." ],
      "techniques": [ "..." ],
      "pentest_notes": [ "..." ],
      "defensive_notes": [ "..." ]
    }
  ]
}
```

The `ports` array contains one [Port Result Object](#5-port-result-object-schema) per resolved port.

**Error responses:** `400` if the `q` parameter is missing, unparseable, or resolves to more than 100 ports; `429` on rate limit; `500` on internal error.

---

#### GET /api/v1/search

Look up ports by service name. Returns up to 10 matching ports.

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `service` | string | yes | Service name keyword, case-insensitive (e.g. `ssh`, `http`, `mysql`, `ftp`) |

**Example request**

```bash
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend-url.com/api/v1/search?service=ssh"
```

**Example response — match found** — `200 OK`

```json
{
  "service": "ssh",
  "ports": [
    {
      "port": 22,
      "service_name": "ssh",
      "transport": ["TCP"],
      "iana_status": "Assigned",
      "risk_level": "HIGH",
      "cve_count": 47,
      "kev_count": 3,
      "top_cves": [ "..." ],
      "techniques": [ "..." ],
      "pentest_notes": [ "..." ],
      "defensive_notes": [ "..." ]
    }
  ]
}
```

**Example response — no match** — `200 OK`

```json
{
  "service": "unknownservice",
  "ports": [],
  "message": "No known ports found for this service"
}
```

**Error responses:** `429` on rate limit; `500` on internal error.

---

#### POST /api/v1/register

Register an email address and receive a free API key. Each email address may only be registered once. This endpoint does **not** require an existing API key.

**Request body** — `application/json`

**Registration flow:**

```
POST /api/v1/register {"email": "<your-email>"}
  → validate email format (regex: ^[^@\s]+@[^@\s]+\.[^@\s]+$)
  → email already registered? → 409 Conflict
  → key = "pa-" + secrets.token_urlsafe(32)
    (cryptographically secure, 43-char random suffix, 256-bit entropy)
  → stored in api_keys table with rate_limit=1000
  → return {api_key, email, rate_limit, message}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | string | yes | Valid email address |

**Example request**

```bash
curl -X POST https://your-backend-url.com/api/v1/register \
     -H "Content-Type: application/json" \
     -d '{"email": "<your-email>"}'
```

**Example response** — `200 OK`

```json
{
  "api_key": "pa-Xk9mR2vTqL8nJwPzYcAoD5sBuFhNiE3eGlV0tCx1Wy",
  "email": "<your-email>",
  "rate_limit": 1000,
  "message": "Key generated. Include it as X-API-Key header in requests."
}
```

> **Important:** the `api_key` value is returned exactly once. Store it immediately — it cannot be retrieved again through the API.

**Error responses:**

- `400` — email address failed format validation
- `409` — this email is already registered

---

#### GET /api/v1/key/info

Inspect usage statistics and metadata for the authenticated key. Requires the `X-API-Key` header.

**Example request**

```bash
curl -H "X-API-Key: pa-your-key-here" \
     https://your-backend-url.com/api/v1/key/info
```

**Example response** — `200 OK`

```json
{
  "email": "<your-email>",
  "created_at": "2025-09-01T14:22:05.123456",
  "last_used": "2026-06-15T09:44:12.789012",
  "requests_today": 42,
  "rate_limit": 1000
}
```

**Error responses:** `401` if the `X-API-Key` header is absent or the key is not recognised.

---

#### GET /api/v1/health

Liveness check. Returns the API version. No authentication required.

**Example request**

```bash
curl https://your-backend-url.com/api/v1/health
```

**Example response** — `200 OK`

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

### 5. Port Result Object Schema

Every endpoint that returns port data uses the same object shape. All fields are always present; fields with no data return `null`, `0`, or an empty array as appropriate.

| Field | Type | Description |
|---|---|---|
| `port` | integer | Port number (0–65535) |
| `service_name` | string \| null | IANA-registered service name, e.g. `"ssh"`, `"http"` |
| `transport` | string[] | Transport protocols, e.g. `["TCP"]`, `["TCP", "UDP"]` |
| `iana_status` | string \| null | IANA assignment status, e.g. `"Assigned"`, `"Unassigned"` |
| `risk_level` | string | Aggregated risk classification: `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"` |
| `cve_count` | integer | Total number of CVEs associated with this port's service |
| `kev_count` | integer | Number of CVEs on the CISA Known Exploited Vulnerabilities (KEV) catalogue |
| `top_cves` | CVE[] | Up to 8 highest-severity CVEs (see CVE object below) |
| `techniques` | Technique[] | Associated MITRE ATT&CK techniques (see Technique object below) |
| `pentest_notes` | string[] | Actionable notes for penetration testers and red teamers |
| `defensive_notes` | string[] | Actionable hardening and detection recommendations |

**CVE object**

| Field | Type | Description |
|---|---|---|
| `cve_id` | string | CVE identifier, e.g. `"CVE-2024-6387"` |
| `cvss_score` | number \| null | CVSS base score (0.0–10.0) |
| `cvss_severity` | string \| null | `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"` |
| `epss_score` | number \| null | EPSS probability of exploitation (0.0–1.0) |
| `exploited_in_wild` | boolean | `true` if listed in the CISA KEV catalogue |
| `description` | string \| null | Brief CVE description |

**Technique object**

| Field | Type | Description |
|---|---|---|
| `technique_id` | string | ATT&CK technique or sub-technique ID, e.g. `"T1021.004"` |
| `name` | string | Technique name |
| `tactic` | string | Parent tactic (kebab-case), e.g. `"lateral-movement"` |
| `url` | string | Direct link to the ATT&CK entry |

---

### 6. Error Codes

All error responses share the same envelope:

```json
{ "detail": "Human-readable explanation of the error." }
```

| Status | Meaning | Common causes |
|---|---|---|
| `400` | Bad Request | Port out of range (0–65535); invalid `q` parameter format; more than 100 ports requested after range expansion; malformed email on registration |
| `401` | Unauthorized | `X-API-Key` header is present but the key is not recognised; `X-API-Key` header is absent from an endpoint that requires it (`/key/info`) |
| `409` | Conflict | The supplied email address is already registered |
| `429` | Too Many Requests | Anonymous IP has exceeded 20 requests/day; authenticated key has exceeded 1,000 requests/day |
| `500` | Internal Server Error | Unexpected backend failure; `detail` contains the underlying exception message |

---

## Part 2 — Integrating from a Static Website

This section explains how a static website hosted on GitHub Pages, Netlify, Cloudflare Pages, or any CDN can embed the Port Analyzer and call its API.

---

### 7. Configuring the Backend URL (PA\_CONFIG)

The frontend JavaScript reads the backend URL from `window.PA_CONFIG.apiBase` before making any API calls:

```js
// From analyzer.js
const API_BASE = (window.PA_CONFIG && window.PA_CONFIG.apiBase) || "";
```

If `apiBase` is empty or `PA_CONFIG` is not defined, the JS falls back to reading `staticDataUrl` (pre-built `ports.json`). For a static site on a separate domain you must set `apiBase` to the full backend URL.

**Dual-mode behaviour:**

| `apiBase` value | Mode | Data source |
|---|---|---|
| `""` (empty, default) | Static | `data/ports.json` from GitHub Pages CDN (same-origin fetch) |
| `"https://..."` (non-empty) | Live | FastAPI backend via REST (`/api/v1/port/{port}`) |

Both modes use the same `renderResults()` path — the UI output is identical.

**How to set it:** declare `window.PA_CONFIG` in an inline `<script>` tag in your HTML **before** loading `analyzer.js`:

```html
<!-- Set this to your deployed backend URL -->
<script>
  window.PA_CONFIG = {
    apiBase: "https://your-backend-url.com",
    staticDataUrl: "data/ports.json"
  };
</script>

<!-- Load the analyzer script after the config -->
<script src="assets/js/analyzer.js"></script>
```

All `fetch` calls in `analyzer.js` will then be prefixed with that URL, e.g.:

```
https://your-backend-url.com/api/v1/port/22
```

---

### 8. CORS Configuration

Browsers enforce the Same-Origin Policy, so a static site at `https://yourusername.github.io` will be blocked from calling `https://your-backend-url.com` unless the backend explicitly allows it.

The backend reads its allowed origins from the `CORS_ORIGINS` environment variable:

```python
# From backend/main.py
CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]
```

The backend **refuses to start** if `CORS_ORIGINS` is unset or set to `*`, unless `CORS_ALLOW_WILDCARD=1` is also set:

```python
if not _cors_env or _cors_env.strip() == "*":
    if os.getenv("CORS_ALLOW_WILDCARD", "0") != "1":
        print("ERROR: CORS_ORIGINS is unset or '*'...")
        sys.exit(1)
```

**For production:** set `CORS_ORIGINS` to a comma-separated list of the exact origins that should be permitted:

```
CORS_ORIGINS=https://yourusername.github.io,https://www.yourdomain.com
```

**For development/open access:** set `CORS_ALLOW_WILDCARD=1` to skip the guard and allow all origins.

Origins must include the scheme and host exactly as the browser sends in the `Origin` header — no trailing slash, no path.

---

### 9. API Key Storage in the Browser

The frontend stores the API key in `localStorage` under the key `pa_api_key`:

```js
// Constants from analyzer.js
const KEY_STORAGE = "pa_api_key";

function getKey() { return localStorage.getItem(KEY_STORAGE) || ""; }
function setKey(k) {
  if (k) localStorage.setItem(KEY_STORAGE, k);
  else    localStorage.removeItem(KEY_STORAGE);
}
```

Every `apiFetch` call automatically reads this value and attaches it as the `X-API-Key` header if present.

**Seamless key injection from your static site**

If you want visitors to your static site to use a pre-issued key without having to register themselves, you have two options:

**Option A — Pre-set on page load (recommended for controlled embeds):**

```html
<script>
  window.PA_CONFIG = { apiBase: "https://your-backend-url.com" };

  // Pre-load a shared or visitor-specific key before the analyzer script runs
  if (!localStorage.getItem("pa_api_key")) {
    localStorage.setItem("pa_api_key", "pa-your-shared-key-here");
  }
</script>
<script src="assets/js/analyzer.js"></script>
```

**Option B — Pass via URL parameter and read in JavaScript:**

```html
<!-- In your analyzer HTML, before analyzer.js -->
<script>
  window.PA_CONFIG = { apiBase: "https://your-backend-url.com" };

  const params = new URLSearchParams(window.location.search);
  const keyParam = params.get("key");
  if (keyParam) {
    localStorage.setItem("pa_api_key", keyParam);
  }
</script>
<script src="assets/js/analyzer.js"></script>
```

> **Security note:** embedding a key in a URL makes it visible in browser history and server logs. Use this only with a read-only shared key. For sensitive use cases, use the localStorage pre-set approach or prompt users to register their own key.

---

### 10. URL Parameter Deep-Linking

The analyzer frontend reads `?port=` and `?q=` query parameters on page load and runs the analysis automatically:

```js
// From analyzer.js DOMContentLoaded handler
const params = new URLSearchParams(window.location.search);
const portParam = params.get("port") || params.get("q");
if (portParam && input) {
  input.value = portParam;
  query(portParam);
}
```

Your static site can deep-link directly to a pre-loaded analysis:

```
# Analyze a single port
https://your-backend-url.com/?port=22

# Analyze multiple ports (comma list)
https://your-backend-url.com/?q=22,443,8080

# Analyze a range
https://your-backend-url.com/?q=8080-8090
```

Both `?port=` and `?q=` are equivalent.

---

### 11. Vanilla JS Fetch Example

A self-contained snippet for calling the API from any static page without depending on `analyzer.js`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Port Intelligence Widget</title>
</head>
<body>
  <div id="port-result">Loading port 22 intelligence...</div>

  <script>
    const API_BASE = "https://your-backend-url.com";
    const API_KEY  = localStorage.getItem("pa_api_key") || "";

    async function fetchPort(port) {
      const headers = { "Content-Type": "application/json" };
      if (API_KEY) headers["X-API-Key"] = API_KEY;

      const resp = await fetch(`${API_BASE}/api/v1/port/${port}`, { headers });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }
      return resp.json();
    }

    function renderPort(data, container) {
      const kevBadge = data.kev_count
        ? `<strong style="color:red">${data.kev_count} in CISA KEV</strong>`
        : "0 in CISA KEV";

      container.innerHTML = `
        <h3>Port ${data.port} — ${(data.service_name || "unknown").toUpperCase()}</h3>
        <p>Transport: ${(data.transport || ["TCP"]).join(", ")}</p>
        <p>IANA Status: ${data.iana_status || "—"}</p>
        <p>Risk Level: <strong>${data.risk_level || "UNKNOWN"}</strong></p>
        <p>CVEs: ${data.cve_count} total &nbsp;|&nbsp; ${kevBadge}</p>
        <h4>Top CVEs</h4>
        <ul>
          ${(data.top_cves || []).slice(0, 5).map(c =>
            `<li>${c.cve_id} — CVSS ${c.cvss_score ?? "N/A"} (${c.cvss_severity ?? "?"})
             ${c.exploited_in_wild ? " [KEV]" : ""}
             <br><small>${c.description || ""}</small></li>`
          ).join("")}
        </ul>
        <h4>Pentest Notes</h4>
        <ul>
          ${(data.pentest_notes || []).map(n => `<li>${n}</li>`).join("")}
        </ul>
      `;
    }

    (async () => {
      const container = document.getElementById("port-result");
      try {
        const data = await fetchPort(22);
        renderPort(data, container);
      } catch (err) {
        container.textContent = `Error: ${err.message}`;
      }
    })();
  </script>
</body>
</html>
```

Key points:
- `API_BASE` is the full backend URL.
- The key is read from `localStorage` — if absent, the request is anonymous.
- The `X-API-Key` header is only attached when a key is present, matching the behavior of `analyzer.js`.
- Error messages come from the `detail` field of the JSON error body.

---

### 12. Rate Limit Recommendations for Embedded Use

The anonymous tier allows **20 requests per day per IP address**. For a static site embedded on a public page, every visitor gets their own 20-request daily allowance. However, if the embedded widget fires multiple queries on page load, a single visitor can exhaust their allowance quickly.

**Recommendations:**

- **Use a dedicated API key for your embedded widget.** Register a key at `POST /api/v1/register` and pre-load it as described in [section 9](#9-api-key-storage-in-the-browser). This gives the key a 1,000 requests/day budget.

- **Prefer deep-linked single-port queries over bulk analysis.** Linking to `?port=22` loads one request; avoid pre-loading a list of ports unless the visitor explicitly triggered it.

- **Cache results client-side when appropriate.** If your static site repeatedly displays the same port (e.g. a fixed widget for port 443), cache the API response in `sessionStorage` for the duration of the visit.

- **Do not embed your personal API key in public source code.** If your static site's HTML is public (as it is on GitHub Pages), any key in the source is visible to anyone. Treat embedded keys as shared read-only credentials. Rotate the key if it is abused.

- **Monitor usage with `GET /api/v1/key/info`.** Check `requests_today` and `rate_limit` to understand your current daily consumption.

---

## Part 3 — Portfolio Integration

This section covers two ways to feature Port Analyzer on a portfolio website without running a backend.

---

### 13. Static Data URL (No Backend Required)

Port Analyzer's GitHub Pages deployment includes a pre-built JSON file with intelligence for ~115 high-value ports. This file is refreshed daily by GitHub Actions and can be fetched directly from any page:

```
https://fmfalgun.github.io/port-analyzer/data/ports.json
```

The file structure:

```json
{
  "_meta": {
    "generated_at": "2026-06-15T02:00:00Z",
    "port_count": 115,
    "sources": ["IANA", "NVD", "CISA KEV", "EPSS", "MITRE ATT&CK"]
  },
  "22": { ... port result object ... },
  "443": { ... port result object ... }
}
```

**Fetching from a portfolio site:**

```javascript
const STATIC_URL = "https://fmfalgun.github.io/port-analyzer/data/ports.json";

async function getPortData(port) {
  const resp = await fetch(STATIC_URL);
  const data = await resp.json();
  return data[String(port)] || null;
}
```

**Notes:**
- This is a same-origin fetch from GitHub Pages — no CORS issues when the portfolio site fetches it with `fetch()` (cross-origin fetches to GitHub Pages are permitted).
- The file is ~500KB+ uncompressed; cache it after the first fetch rather than refetching on every port query.
- Only ports in `PORT_LIST` are present. Querying a port not in the list returns `null`.
- For arbitrary port queries, deploy the FastAPI backend and use live mode.

---

### 14. Embed via iframe

The simplest portfolio integration is an `<iframe>` pointing at the GitHub Pages deployment:

```html
<!-- Embed the full Port Analyzer UI -->
<iframe
  src="https://fmfalgun.github.io/port-analyzer/"
  width="100%"
  height="800"
  style="border: none; border-radius: 8px;"
  title="Port Analyzer — Cybersecurity Intelligence"
></iframe>
```

**Deep-link to a pre-loaded analysis** (the UI auto-runs on page load when `?port=` is set):

```html
<!-- Pre-load port 22 analysis in the iframe -->
<iframe
  src="https://fmfalgun.github.io/port-analyzer/?port=22"
  width="100%"
  height="800"
  style="border: none;"
  title="Port 22 (SSH) Security Analysis"
></iframe>
```

**Limitations of the iframe approach:**
- The embedded UI is in static mode (no live backend) — only ports in `PORT_LIST` are available.
- The iframe's `localStorage` is scoped to the `fmfalgun.github.io` origin, not your portfolio site's origin.
- If you want the live FastAPI backend, deploy the backend and set `apiBase` in the embedded page's `index.html`.

---

### 15. Query the API Directly from a Portfolio Site

If the FastAPI backend is deployed, a portfolio site can query it directly with plain `fetch()`. This requires:

1. `CORS_ORIGINS` on the backend must include your portfolio site's origin.
2. A shared API key pre-loaded or prompted on the portfolio page.

**Minimal portfolio widget:**

```html
<div id="pa-widget"></div>
<script>
  const API = "https://your-backend-url.com";
  const KEY = "pa-your-shared-key-here";

  fetch(`${API}/api/v1/port/443`, {
    headers: { "X-API-Key": KEY }
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById("pa-widget").innerHTML = `
      <strong>Port ${d.port} (${d.service_name})</strong>:
      ${d.cve_count} CVEs, ${d.kev_count} in CISA KEV,
      Risk: ${d.risk_level}
    `;
  });
</script>
```

**CORS setup for the backend:**

```bash
# Set this environment variable on your backend deployment
CORS_ORIGINS=https://your-portfolio-domain.com,https://fmfalgun.github.io
```

**Alternative — use the static data URL** (no backend needed, no CORS config required):

```javascript
// No API key, no backend, no CORS — works from any static site
fetch("https://fmfalgun.github.io/port-analyzer/data/ports.json")
  .then(r => r.json())
  .then(data => {
    const port443 = data["443"];
    // use port443.cve_count, port443.risk_level, etc.
  });
```

---

### 16. Web UI Features — Pre-Built Ports and Markdown Download

#### Available-ports panel

The web UI operates in static mode by default (no backend required). When a queried port is not present in the pre-built dataset, the UI shows a descriptive message rather than a bare error, pointing the user to the CLI for live queries:

```
python -m port_analyzer.cli <port>
```

It also displays a collapsible panel listing every port that is available in the current static dataset (~118 ports). The list is derived at runtime from the loaded `ports.json` keys — no separate configuration is needed.

#### Per-port markdown download

Each result card in the web UI includes a **↓ Report** button. Clicking it generates a complete markdown intelligence report for that port and downloads it as `port-{N}-report.md`. The generation is entirely client-side — no additional API request is made.

Reports include:
- CVE IDs as clickable markdown links to the NVD detail page (`https://nvd.nist.gov/vuln/detail/{CVE-ID}`)
- MITRE technique IDs as clickable links to the ATT&CK entry (dot → slash in the URL path, e.g. `T1021.004` → `https://attack.mitre.org/techniques/T1021/004/`)
- A `## References` section at the end listing IANA, NVD port search, CISA KEV (when `kev_count > 0`), EPSS, MITRE ATT&CK, and per-CVE and per-technique bullet links

#### CLI equivalent — `--report PATH`

For scripted or offline use, the CLI `--report PATH` flag produces the same markdown content and writes it to a file:

```bash
# Single port
python -m port_analyzer.cli 22 --report /tmp/port22.md

# Multiple ports — all reports concatenated with --- separators
python -m port_analyzer.cli 22,80,443 --report /tmp/report.md
```

The `--report` flag can be combined with `--no-live` (reads from local cache), `--json` (JSON goes to stdout; markdown goes to the file path), or `--sync` (see [section 17](#17---sync-push-analysis-results-to-github-pages)).

---

## Part 4 — CLI Reference

### 17. `--sync`: Push Analysis Results to GitHub Pages

The `--sync` flag uploads the analysis result for each queried port to the live GitHub Pages dataset using the GitHub Contents API. A Personal Access Token (PAT) authenticates the push. Because a PAT push fires a real `push` event on the repository, it automatically triggers `deploy-pages.yml` — the live site updates in roughly 30 seconds.

#### Why PAT and not GITHUB_TOKEN

GitHub Actions' built-in `GITHUB_TOKEN` cannot trigger other workflows. A PAT push fires an authentic `push` event that `deploy-pages.yml` is able to listen on. This is the same architectural reason that `build-data.yml` uses a `workflow_run` trigger.

#### One-time setup

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Click **Generate new token**.
3. Under **Repository access**, select only the `port-analyzer` repository.
4. Under **Permissions**, set **Contents → Read and write**.
5. Generate and copy the token.
6. Export it in your shell (add to `~/.bashrc` or `~/.zshenv` to persist):

```bash
export GITHUB_PAT=ghp_your_token_here
```

The `GITHUB_REPO` variable defaults to `fmfalgun/port-analyzer`. Set it only if you are working with a fork:

```bash
export GITHUB_REPO=yourusername/port-analyzer   # optional
```

#### Usage

```bash
# Analyze port 31337 and push the result to the live dataset
python -m port_analyzer 31337 --sync

# Multiple ports — each port is pushed individually
python -m port_analyzer 22,443 --sync

# Combine with --report to write a local markdown file at the same time
python -m port_analyzer 22 --sync --report /tmp/port22.md
```

#### Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GITHUB_PAT` | Yes (for `--sync`) | — | Personal Access Token for GitHub Contents API push |
| `GITHUB_REPO` | No | `fmfalgun/port-analyzer` | Target repository for the sync (owner/repo) |
| `NVD_API_KEY` | No | — | NVD API key — raises the NVD rate limit 10x |

---

### 18. Markdown Reports — Clickable Links and References Section

Both the CLI `--report PATH` output and the web UI **↓ Report** download button produce fully linked markdown reports.

#### Inline hyperlinks

- **CVE IDs** are rendered as clickable links to the NVD detail page:
  `[CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)`
- **MITRE technique IDs** are rendered as clickable links to the ATT&CK entry. The dot in the technique ID is converted to a slash in the URL path:
  `[T1021.004](https://attack.mitre.org/techniques/T1021/004/)`

#### `## References` section

Every port report ends with a `## References` section listing the canonical sources consulted. The section always includes:

- IANA service name registry
- NVD port-keyword search URL for the service
- EPSS score API
- MITRE ATT&CK (general)

When `kev_count > 0`, a CISA KEV link is also included. Per-CVE and per-technique bullet links are appended after the general references:

```markdown
## References

- [IANA Service Name Registry](https://www.iana.org/assignments/service-names-port-numbers/)
- [NVD — ssh vulnerability search](https://nvd.nist.gov/vuln/search/results?keyword=ssh)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS — Exploit Prediction Scoring System](https://www.first.org/epss/)
- [MITRE ATT&CK](https://attack.mitre.org/)

**CVEs referenced:**
- [CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- [CVE-2023-38408](https://nvd.nist.gov/vuln/detail/CVE-2023-38408)

**ATT&CK techniques referenced:**
- [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [T1563.001 — Remote Service Session Hijacking: SSH Hijacking](https://attack.mitre.org/techniques/T1563/001/)
```

---

*Document version: 1.2 — Updated 2026-06-15*

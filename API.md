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
     https://your-backend.railway.app/api/v1/port/22
```

If the key is absent or invalid, the API either falls back to anonymous rate limits (absent) or returns `401` (present but not recognised).

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
https://your-backend.railway.app
```

Interactive docs (Swagger UI) are available at `/docs`; ReDoc is at `/redoc`.

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
     https://your-backend.railway.app/api/v1/port/22
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
     "https://your-backend.railway.app/api/v1/ports?q=22,80,443"

# Range
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend.railway.app/api/v1/ports?q=8080-8090"

# Mixed
curl -H "X-API-Key: pa-your-key-here" \
     "https://your-backend.railway.app/api/v1/ports?q=22,80-90,443"
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
     "https://your-backend.railway.app/api/v1/search?service=ssh"
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

Register an email address and receive a free API key. Each email address may only be registered once.

This endpoint does **not** require an existing API key.

**Request body** — `application/json`

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | string | yes | Valid email address |

**Example request**

```bash
curl -X POST https://your-backend.railway.app/api/v1/register \
     -H "Content-Type: application/json" \
     -d '{"email": "analyst@example.com"}'
```

**Example response** — `200 OK`

```json
{
  "api_key": "pa-Xk9mR2vTqL8nJwPzYcAoD5sBuFhNiE3eGlV0tCx1Wy",
  "email": "analyst@example.com",
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
     https://your-backend.railway.app/api/v1/key/info
```

**Example response** — `200 OK`

```json
{
  "email": "analyst@example.com",
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
curl https://your-backend.railway.app/api/v1/health
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

If `apiBase` is empty or `PA_CONFIG` is not defined, the JS calls paths relative to the current origin — which works when the frontend and backend are served from the same domain. For a static site on a separate domain you must set `apiBase` to the full backend URL.

**How to set it:** declare `window.PA_CONFIG` in an inline `<script>` tag in your HTML **before** loading `analyzer.js`:

```html
<!-- Set this to your deployed backend URL -->
<script>
  window.PA_CONFIG = {
    apiBase: "https://your-backend.railway.app"
  };
</script>

<!-- Load the analyzer script after the config -->
<script src="assets/js/analyzer.js"></script>
```

All `fetch` calls in `analyzer.js` will then be prefixed with that URL, e.g.:

```
https://your-backend.railway.app/api/v1/port/22
```

To repoint the static site at a different backend (staging vs. production), update only this one value.

---

### 8. CORS Configuration

Browsers enforce the Same-Origin Policy, so a static site at `https://yourusername.github.io` will be blocked from calling `https://your-backend.railway.app` unless the backend explicitly allows it.

The backend reads its allowed origins from the `CORS_ORIGINS` environment variable:

```python
# From main.py
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]
```

**Default:** when `CORS_ORIGINS` is unset, it defaults to `"*"` (all origins allowed). This is fine for development but you should restrict it in production.

**For production:** set `CORS_ORIGINS` to a comma-separated list of the exact origins that should be permitted:

```
CORS_ORIGINS=https://yourusername.github.io,https://www.yourdomain.com
```

Origins must include the scheme and host exactly as the browser sends in the `Origin` header — no trailing slash, no path.

If your static site starts receiving `CORS error` or `Access-Control-Allow-Origin` errors in the browser console, verify that:

1. The `CORS_ORIGINS` env var on the backend contains your site's exact origin.
2. The backend has been restarted after changing the env var.
3. The `apiBase` in `PA_CONFIG` matches the backend URL exactly (no trailing slash).

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
  window.PA_CONFIG = { apiBase: "https://your-backend.railway.app" };

  // Pre-load a shared or visitor-specific key before the analyzer script runs
  if (!localStorage.getItem("pa_api_key")) {
    localStorage.setItem("pa_api_key", "pa-your-shared-key-here");
  }
</script>
<script src="assets/js/analyzer.js"></script>
```

**Option B — Pass via URL parameter and read in JavaScript:**

You can append the key as a URL parameter from your static site, then read and store it on the analyzer page before the main script runs:

```html
<!-- In your analyzer HTML, before analyzer.js -->
<script>
  window.PA_CONFIG = { apiBase: "https://your-backend.railway.app" };

  const params = new URLSearchParams(window.location.search);
  const keyParam = params.get("key");
  if (keyParam) {
    localStorage.setItem("pa_api_key", keyParam);
  }
</script>
<script src="assets/js/analyzer.js"></script>
```

Then link to the analyzer from your static site like:

```
https://your-backend.railway.app/?key=pa-your-key-here&port=22
```

> **Security note:** embedding a key in a URL makes it visible in browser history and server logs. Use this only with a read-only shared key and not a personal key with write access. For sensitive use cases, consider the localStorage pre-set approach instead, or prompt users to register their own key.

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
https://your-backend.railway.app/?port=22

# Analyze multiple ports (comma list)
https://your-backend.railway.app/?q=22,443,8080

# Analyze a range
https://your-backend.railway.app/?q=8080-8090

# Mixed — also works
https://your-backend.railway.app/?q=22,80-90,443
```

Both `?port=` and `?q=` are equivalent; the JS merges them into the same variable.

**Practical use:** from a static blog post or project page, link directly to a port analysis rather than sending visitors to a blank analyzer:

```html
<!-- A link on your static site that opens port 443 analysis immediately -->
<a href="https://your-backend.railway.app/?port=443">
  Analyze port 443 (HTTPS)
</a>
```

---

### 11. Vanilla JS Fetch Example

Below is a self-contained snippet showing how to call the API from any static page and render a result. It does not depend on `analyzer.js` and can be dropped into any HTML file.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Port Intelligence Widget</title>
</head>
<body>
  <div id="port-result">Loading port 22 intelligence…</div>

  <script>
    const API_BASE = "https://your-backend.railway.app";
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

The anonymous tier allows **20 requests per day per IP address**. For a static site embedded on a public page, every visitor shares no pooled budget — each unique IP gets its own 20-request allowance. However, if the embedded widget fires multiple queries on page load, a single visitor can exhaust their daily allowance quickly.

**Recommendations:**

- **Use a dedicated API key for your embedded widget.** Register a key at `POST /api/v1/register` and pre-load it as described in [section 9](#9-api-key-storage-in-the-browser). This gives the key a 1,000 requests/day budget, shared across all visitors who load the key from your site — more than enough for most personal or project sites.

- **Prefer deep-linked single-port queries over bulk analysis.** Linking to `?port=22` loads one request; avoid pre-loading a list of ports unless the visitor explicitly triggered it.

- **Cache results client-side when appropriate.** If your static site repeatedly displays the same port (e.g. a fixed widget for port 443), consider caching the API response in `sessionStorage` for the duration of the visit to avoid redundant requests.

- **Do not embed your personal API key in public source code.** If your static site's HTML is public (as it is on GitHub Pages), any key in the source is visible to anyone. Treat embedded keys as shared read-only credentials with no sensitive access — exactly what Port Analyzer keys are. Still, rotate the key if it is abused.

- **Monitor usage with `GET /api/v1/key/info`.** Check `requests_today` and `rate_limit` to understand your current daily consumption before approaching the limit.

// Port Analyzer — frontend JS
// Reads API_BASE from window.PA_CONFIG (set in HTML) or falls back to same origin.

const API_BASE = (window.PA_CONFIG && window.PA_CONFIG.apiBase) || "";
const KEY_STORAGE = "pa_api_key";

// Static data fallback — used when API_BASE is empty (GitHub Pages without backend)
const STATIC_DATA_URL = (window.PA_CONFIG && window.PA_CONFIG.staticDataUrl) || "data/ports.json";
let _staticCache = null;

async function loadStaticData() {
  if (_staticCache) return _staticCache;
  const resp = await fetch(STATIC_DATA_URL);
  if (!resp.ok) throw new Error(`Static data not available (${resp.status})`);
  _staticCache = await resp.json();
  renderPortsInfoPanel();
  return _staticCache;
}

// ── available-ports info panel ────────────────────────────────────

function getStaticPortKeys() {
  if (!_staticCache) return [];
  return Object.keys(_staticCache)
    .filter(k => k !== "_meta")
    .sort((a, b) => Number(a) - Number(b));
}

function renderPortsInfoPanel() {
  const panel = $("ports-info-panel");
  if (!panel) return;
  const keys = getStaticPortKeys();
  const count = keys.length;
  if (count === 0) { panel.innerHTML = ""; return; }
  const portList = keys.map(esc).join(", ");
  panel.innerHTML = `
    <div class="ports-info-card">
      <div class="ports-info-heading">
        <span class="ports-info-label">STATIC DATASET</span>
        <span class="ports-info-count">${esc(String(count))} ports pre-built</span>
      </div>
      <details class="ports-info-details">
        <summary>Browse all ${esc(String(count))} available ports</summary>
        <p class="ports-info-list">${portList}</p>
      </details>
    </div>`;
}

function hidePortsInfoPanel() {
  const panel = $("ports-info-panel");
  if (panel) panel.style.display = "none";
}

function showPortsInfoPanel() {
  const panel = $("ports-info-panel");
  if (panel) panel.style.display = "";
}

// ── XSS mitigation ───────────────────────────────────────────────
// Escape API-sourced strings before injecting into innerHTML.
function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

const $ = id => document.getElementById(id);

// ── API key management ────────────────────────────────────────────

function getKey() { return localStorage.getItem(KEY_STORAGE) || ""; }

function setKey(k) {
  if (k) localStorage.setItem(KEY_STORAGE, k);
  else    localStorage.removeItem(KEY_STORAGE);
  renderKeyBanner();
}

function renderKeyBanner() {
  const banner = $("key-banner");
  const key = getKey();
  if (!banner) return;
  if (key) {
    banner.classList.add("active");
    banner.querySelector("span").textContent = key.slice(0, 12) + "…";
  } else {
    banner.classList.remove("active");
  }
}

// ── status ────────────────────────────────────────────────────────

function setStatus(msg, type = "info") {
  const el = $("status");
  if (!el) return;
  el.textContent = msg;
  el.className = type;
}

function clearStatus() {
  const el = $("status");
  if (!el) return;
  el.textContent = "";
  el.className = "";
}

// ── fetch wrapper ─────────────────────────────────────────────────

async function apiFetch(path) {
  const headers = { "Content-Type": "application/json" };
  const key = getKey();
  if (key) headers["X-API-Key"] = key;

  const resp = await fetch(API_BASE + path, { headers });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

// ── not-in-dataset helper ─────────────────────────────────────────

function renderNotInDataset(searchedPorts) {
  const keys = getStaticPortKeys();
  const count = keys.length;
  const portList = keys.map(esc).join(", ");

  const countLine = count
    ? `<p class="nid-meta"><span class="nid-highlight">${esc(String(count))}</span> ports are pre-built and searchable here.</p>`
    : "";

  const browseSection = count
    ? `<details class="nid-details">
        <summary>Browse all ${esc(String(count))} available ports</summary>
        <p class="nid-port-list">${portList}</p>
      </details>`
    : "";

  const container = $("results");
  container.innerHTML = `
    <div class="nid-card">
      <div class="section-title">Port not in static dataset</div>
      <p class="nid-reason">This tool pre-builds data for a curated set of ports.
        Arbitrary ports require the live backend — not available on this static deployment.</p>
      ${countLine}
      <div class="nid-cli-block">
        <span class="nid-cli-label">Use the CLI instead:</span>
        <code>python -m port_analyzer.cli ${esc(searchedPorts)}</code><br/>
        <code>python -m port_analyzer.cli --help</code>
      </div>
      ${browseSection}
    </div>`;
  showPortsInfoPanel();
}

// ── main query ────────────────────────────────────────────────────

async function query(input) {
  input = input.trim();
  if (!input) return;

  clearStatus();
  $("results").innerHTML = "";
  setStatus(`[>] querying port(s): ${input} …`, "loading");

  try {
    // NEW: static fallback when no backend is configured
    if (!API_BASE) {
      const data = await loadStaticData();
      const ports = input.split(",").map(p => p.trim()).filter(Boolean);
      const results = [];
      for (const p of ports) {
        const entry = data[p] || data[p.replace(/\s/g, "")];
        if (entry) results.push(entry);
        else results.push({ port: parseInt(p) || p, service_name: "unknown", risk_level: "LOW", cve_count: 0, kev_count: 0, top_cves: [], techniques: [], pentest_notes: [], defensive_notes: [], _not_in_dataset: true });
      }
      clearStatus();
      if (results.every(r => r._not_in_dataset)) {
        renderNotInDataset(input);
        return;
      }
      hidePortsInfoPanel();
      renderResults(results.filter(r => !r._not_in_dataset));
      return;
    }
    // EXISTING live-API code below — untouched
    // Decide endpoint: single port or multi
    let data;
    if (/^[0-9]+$/.test(input)) {
      data = await apiFetch(`/api/v1/port/${input}`);
      data = [data];
    } else {
      const res = await apiFetch(`/api/v1/ports?q=${encodeURIComponent(input)}`);
      data = res.ports || [];
    }

    clearStatus();
    renderResults(data);
  } catch (e) {
    setStatus(`[!] ${e.message}`, "error");
  }
}

// ── render ────────────────────────────────────────────────────────

function renderResults(results) {
  const container = $("results");
  if (!results.length) {
    container.innerHTML = `<p class="no-data">[i] No results returned.</p>`;
    return;
  }
  results.forEach(r => container.appendChild(buildCard(r)));
}

function buildCard(r) {
  const card = document.createElement("div");
  card.className = "port-card";

  const transport = (r.transport || ["TCP"]).map(esc).join(" / ");
  const riskLevel = esc(r.risk_level || "LOW");
  const riskClass = `risk-${riskLevel}`;

  card.innerHTML = `
    <div class="port-card-header" onclick="toggleCard(this)">
      <div>
        <span class="port-number">${esc(String(r.port))}</span>
        <span class="port-service">${esc((r.service_name || "unknown").toUpperCase())}</span>
        <span class="port-transport">[${transport}]</span>
      </div>
      <div style="display:flex;align-items:center;gap:0.75rem">
        <button class="dl-report-btn" title="Download markdown report">&#8595; Report</button>
        <span class="risk-badge ${riskClass}">${riskLevel}</span>
        <span class="collapse-icon">▾</span>
      </div>
    </div>
    <div class="port-card-body">
      ${metaGrid(r)}
      ${statsStrip(r)}
      ${cveSection(r)}
      ${techniqueSection(r)}
      ${noteSection("PENTEST NOTES", r.pentest_notes)}
      ${noteSection("DEFENSIVE RECOMMENDATIONS", r.defensive_notes)}
    </div>
  `;

  // Wire download button without inline onclick (keeps r in closure, avoids JSON injection)
  card.querySelector(".dl-report-btn").addEventListener("click", e => {
    e.stopPropagation(); // prevent card collapse toggle
    downloadReport(r);
  });

  return card;
}

function metaGrid(r) {
  const items = [
    ["Transport",   esc((r.transport || ["TCP"]).join(" / "))],
    ["IANA Status", esc(r.iana_status || "—")],
    ["CVE Count",   esc(String(r.cve_count ?? "—"))],
    ["CISA KEV",    r.kev_count ? `<span style="color:var(--critical)">${esc(String(r.kev_count))} confirmed</span>` : "0"],
  ];
  if (r.description) items.push(["Description", esc(r.description.slice(0, 100))]);

  return `<div class="meta-grid">${items.map(([l, v]) =>
    `<div class="meta-item">
      <span class="meta-label">${esc(l)}</span>
      <span class="meta-value">${v}</span>
    </div>`
  ).join("")}</div>`;
}

function statsStrip(r) {
  const topEpss = (r.top_cves || [])
    .filter(c => c.epss_score != null)
    .sort((a, b) => b.epss_score - a.epss_score)[0];

  const epssStr = topEpss
    ? `<span class="stat-val">${esc((topEpss.epss_score * 100).toFixed(0))}%</span> exploitation prob (EPSS top — ${esc(topEpss.cve_id)})`
    : null;

  const parts = [
    epssStr,
    r.kev_count ? `<span class="stat-kev">${esc(String(r.kev_count))}</span> exploited in wild (CISA KEV)` : null,
  ].filter(Boolean);

  if (!parts.length) return "";
  return `<div class="stats-strip">${parts.map(p => `<span>${p}</span>`).join("")}</div>`;
}

function cveSection(r) {
  const cves = (r.top_cves || []).slice(0, 8);
  if (!cves.length) return `
    <div class="section-block">
      <div class="section-title">CVEs</div>
      <p class="no-data">No CVEs found in cache yet — run a live query to populate.</p>
    </div>`;

  const rows = cves.map(c => {
    const sev   = esc(c.cvss_severity || "?");
    const score = c.cvss_score != null ? esc(c.cvss_score.toFixed(1)) : "—";
    const epss  = c.epss_score  != null ? esc((c.epss_score * 100).toFixed(0)) + "%" : "—";
    const kev   = c.exploited_in_wild ? `<span class="cve-kev">KEV</span>` : "";
    const desc  = esc((c.description || "").slice(0, 90));
    return `<tr>
      <td><span class="cve-id">${esc(c.cve_id)}</span> ${kev}</td>
      <td class="sev-${sev}">${score} ${sev}</td>
      <td>${epss}</td>
      <td style="color:var(--dim);font-size:0.78rem">${desc}</td>
    </tr>`;
  }).join("");

  return `<div class="section-block">
    <div class="section-title">CVEs (top ${cves.length})</div>
    <table class="cve-table">
      <thead><tr>
        <th>CVE ID</th><th>CVSS / Severity</th><th>EPSS</th><th>Description</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function techniqueSection(r) {
  const techs = r.techniques || [];
  if (!techs.length) return "";

  const items = techs.map(t => {
    const tactic = esc((t.tactic || "").replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase()));
    // Only allow HTTPS URLs pointing to attack.mitre.org to prevent URL injection.
    const rawUrl = t.url || `https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}/`;
    const url    = /^https:\/\/attack\.mitre\.org\//.test(rawUrl) ? esc(rawUrl) : "#";
    return `<div class="technique-item">
      <a href="${url}" target="_blank" rel="noopener noreferrer">
        <span class="technique-id">${esc(t.technique_id)}</span>
        <span class="technique-tactic">${tactic}</span>
        <span class="technique-name">${esc(t.name)}</span>
      </a>
    </div>`;
  }).join("");

  return `<div class="section-block">
    <div class="section-title">MITRE ATT&CK</div>
    <div class="technique-list">${items}</div>
  </div>`;
}

function noteSection(title, notes) {
  if (!notes || !notes.length) return "";
  const items = notes.map(n =>
    `<div class="note-item"><span class="note-bullet">·</span><span>${esc(n)}</span></div>`
  ).join("");
  return `<div class="section-block">
    <div class="section-title">${title}</div>
    <div class="note-list">${items}</div>
  </div>`;
}

function toggleCard(header) {
  header.closest(".port-card").classList.toggle("collapsed");
}

// ── markdown export ───────────────────────────────────────────────

function generateMarkdown(r) {
  const port       = r.port;
  const svc        = (r.service_name || `port-${port}`).toLowerCase();
  const risk       = r.risk_level || "LOW";
  const transports = (r.transport || ["TCP"]).join(", ");
  const iana       = r.iana_status || "—";
  const cveCount   = r.cve_count ?? 0;
  const kevCount   = r.kev_count ?? 0;
  const desc       = r.description || "";

  const lines = [];

  // Title
  lines.push(`# Port ${port} — ${svc} (${risk} RISK)`);
  lines.push("");

  // Overview table
  lines.push("## Overview");
  lines.push("| Field | Value |");
  lines.push("|---|---|");
  lines.push(`| Port | ${port} |`);
  lines.push(`| Service | ${svc} |`);
  lines.push(`| Transport | ${transports} |`);
  lines.push(`| IANA Status | ${iana} |`);
  lines.push(`| Risk Level | ${risk} |`);
  lines.push(`| CVE Count | ${cveCount} |`);
  lines.push(`| KEV Count | ${kevCount} |`);
  lines.push("");

  // Description
  if (desc) {
    lines.push("## Description");
    lines.push(desc);
    lines.push("");
  }

  // Top CVEs
  const topCves = r.top_cves || [];
  if (topCves.length) {
    lines.push("## Top CVEs");
    lines.push("| CVE ID | CVSS | EPSS | KEV |");
    lines.push("|---|---|---|---|");
    for (const c of topCves) {
      const score = c.cvss_score != null ? `${c.cvss_score.toFixed(1)} ${c.cvss_severity || "?"}` : "N/A";
      const epss  = c.epss_score  != null ? c.epss_score.toFixed(2) : "—";
      const kev   = c.exploited_in_wild ? "Yes" : "No";
      lines.push(`| ${c.cve_id || "—"} | ${score} | ${epss} | ${kev} |`);
    }
    lines.push("");
  }

  // MITRE ATT&CK techniques
  const techs = r.techniques || [];
  if (techs.length) {
    lines.push("## MITRE ATT&CK Techniques");
    lines.push("| Technique | Name | Tactic |");
    lines.push("|---|---|---|");
    for (const t of techs) {
      lines.push(`| ${t.technique_id || "—"} | ${t.name || "—"} | ${t.tactic || "—"} |`);
    }
    lines.push("");
  }

  // Pentest notes
  const pentest = r.pentest_notes || [];
  if (pentest.length) {
    lines.push("## Pentest Notes");
    for (const n of pentest) lines.push(`- ${n}`);
    lines.push("");
  }

  // Defensive notes
  const defensive = r.defensive_notes || [];
  if (defensive.length) {
    lines.push("## Defensive Notes");
    for (const n of defensive) lines.push(`- ${n}`);
    lines.push("");
  }

  lines.push("---");
  lines.push("*Generated by Port Analyzer — https://github.com/fmfalgun/port-analyzer*");

  return lines.join("\n");
}

function downloadReport(r) {
  const md   = generateMarkdown(r);
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `port-${r.port}-report.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── event wiring ──────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  renderKeyBanner();

  const input = $("port-input");
  const btn   = $("search-btn");

  if (btn)   btn.addEventListener("click", () => query(input?.value || ""));
  if (input) input.addEventListener("keydown", e => { if (e.key === "Enter") query(input.value); });

  const clearBtn = $("clear-key");
  if (clearBtn) clearBtn.addEventListener("click", () => { setKey(""); });

  // Pre-load static data so the info panel is ready immediately (no-backend mode)
  if (!API_BASE) {
    loadStaticData().catch(() => {});
  }

  // Support ?port= in URL for portfolio embedding
  const params = new URLSearchParams(window.location.search);
  const portParam = params.get("port") || params.get("q");
  if (portParam && input) {
    input.value = portParam;
    query(portParam);
  }
});

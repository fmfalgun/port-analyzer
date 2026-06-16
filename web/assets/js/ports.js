// Port CVE Explorer — ports.html companion script
// Reads ?p=<port> from URL, fetches data/ports/{port}.json (full) or
// data/ports.json (summary fallback), renders full CVE table with
// filtering, sorting, pagination, and downloads.

"use strict";

// ── XSS mitigation ────────────────────────────────────────────────
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

// ── constants ──────────────────────────────────────────────────────
const PAGE_SIZE = 25;

// ── state ──────────────────────────────────────────────────────────
let portData    = null;   // full port entry
let allCves     = [];     // raw CVE array
let filteredCves = [];    // after filters+sort applied
let currentPage = 1;

// ── boot ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(location.search);
  const port   = params.get("p") || params.get("port");

  if (!port) {
    showError(
      "No port specified.",
      `No port number was provided in the URL. <a href="index.html" style="color:var(--amber)">← Return to Port Analyzer</a>`
    );
    return;
  }

  // Update title immediately with port number
  document.title = `Port ${esc(port)} — CVE Explorer | Port Analyzer`;

  setStatus(`[>] Loading port ${esc(port)} data…`, "loading");

  try {
    // Fetch the per-port full file (has all_cves); fall back to summary if missing
    const perPortUrl = `data/ports/${encodeURIComponent(port)}.json`;
    let resp = await fetch(perPortUrl);
    let entry;

    if (resp.ok) {
      entry = await resp.json();
    } else {
      // Fall back to summary ports.json (only top_cves available)
      resp = await fetch("data/ports.json");
      if (!resp.ok) throw new Error(`Data fetch failed (HTTP ${resp.status})`);
      const summary = await resp.json();
      entry = summary[port] || summary[String(parseInt(port, 10))];
    }

    if (!entry) {
      showError(
        `Port ${esc(port)} not in dataset.`,
        `Port <strong>${esc(port)}</strong> has not been pre-built yet.<br>
         Run the CLI to populate it:<br>
         <code style="color:var(--amber);display:block;margin-top:0.5rem">python -m port_analyzer.cli ${esc(port)} --sync</code>`
      );
      return;
    }

    portData = entry;
    allCves  = entry.all_cves || entry.top_cves || [];

    // Update document title with service name
    const svc = (entry.service_name || `port-${port}`).toUpperCase();
    document.title = `Port ${esc(port)} — ${svc} CVE Explorer | Port Analyzer`;

    clearStatus();
    renderPortHeader(entry);
    renderUsageHistory(entry);
    wireFilterBar();
    applyFiltersAndRender();
    renderVariotSection(entry);
    renderExtraSections(entry);

  } catch (err) {
    showError("Failed to load data.", esc(err.message));
  }
});

// ── status helpers ─────────────────────────────────────────────────
function setStatus(msg, type = "info") {
  const el = $("explorer-status");
  if (!el) return;
  el.innerHTML = msg;
  el.className = `explorer-status ${type}`;
}

function clearStatus() {
  const el = $("explorer-status");
  if (el) { el.innerHTML = ""; el.className = "explorer-status"; }
}

function showError(title, detail) {
  clearStatus();
  const wrap = $("explorer-wrap");
  if (!wrap) return;
  wrap.innerHTML = `
    <div class="error-card">
      <div class="section-title">${esc(title)}</div>
      <p class="error-detail">${detail}</p>
      <a href="index.html" class="back-link">← Return to Port Analyzer</a>
    </div>`;
}

// ── port header ────────────────────────────────────────────────────
function renderPortHeader(r) {
  const el = $("port-header");
  if (!el) return;

  const port       = esc(String(r.port));
  const svc        = esc((r.service_name || "unknown").toUpperCase());
  const risk       = esc(r.risk_level || "LOW");
  const transport  = (r.transport || ["TCP"]).map(esc).join(" / ");
  const cveCount   = Number(r.cve_count   ?? allCves.length);
  const kevCount   = Number(r.kev_count   ?? 0);
  const pocCount   = Number(r.poc_count   ?? 0);
  const edbCount   = Number(r.exploitdb_hits ?? 0);
  const dataCount  = allCves.length;

  const kevBadge = kevCount
    ? `<span class="hdr-badge kev-badge">${kevCount} KEV</span>`
    : "";
  const pocBadge = pocCount
    ? `<span class="hdr-badge poc-badge">${pocCount} PoC</span>`
    : "";
  const edbBadge = edbCount
    ? `<span class="hdr-badge edb-badge">${edbCount} EDB</span>`
    : "";

  const dataNote = dataCount < cveCount
    ? `<span class="hdr-data-note">(showing top ${dataCount.toLocaleString()} — run CLI for full dataset)</span>`
    : "";

  el.innerHTML = `
    <div class="port-hdr">
      <div class="port-hdr-left">
        <span class="port-hdr-num">PORT ${port}</span>
        <span class="port-hdr-dash">—</span>
        <span class="port-hdr-svc">${svc}</span>
        <span class="port-hdr-transport">[${transport}]</span>
      </div>
      <span class="risk-badge risk-${risk}">${risk}</span>
    </div>
    <div class="port-hdr-meta">
      <span class="hdr-count">${cveCount.toLocaleString()} CVEs</span>
      ${kevBadge}
      ${pocBadge}
      ${edbBadge}
      ${dataNote}
    </div>`;
}

// ── usage & history ────────────────────────────────────────────────
function renderUsageHistory(r) {
  const el = $("usage-history-section");
  if (!el) return;

  const wiki = r.wiki_description;
  const freqParts = [];
  if (r.nmap_tcp_freq  != null) freqParts.push(`TCP ${(r.nmap_tcp_freq  * 100).toFixed(1)}%`);
  if (r.nmap_udp_freq  != null) freqParts.push(`UDP ${(r.nmap_udp_freq  * 100).toFixed(1)}%`);
  if (r.nmap_sctp_freq != null) freqParts.push(`SCTP ${(r.nmap_sctp_freq * 100).toFixed(1)}%`);
  const hasNmap = freqParts.length > 0 || r.popularity_freq != null;

  if (!wiki && !hasNmap) { el.innerHTML = ""; return; }

  const wikiBlock = wiki
    ? `<p class="usage-text">${esc(wiki)}</p>
       ${r.wiki_url ? `<p class="usage-link"><a href="${esc(r.wiki_url)}" target="_blank" rel="noopener noreferrer">View full Wikipedia article ↗</a></p>` : ""}`
    : "";

  let freqText;
  if (freqParts.length > 0) {
    freqText = freqParts.map(p => `<span style="color:var(--warn)">${p}</span>`).join(" · ");
  } else if (r.popularity_freq != null) {
    freqText = `<span style="color:var(--warn)">${esc((r.popularity_freq * 100).toFixed(1))}%</span>`;
  } else {
    freqText = null;
  }

  const svcNote = (r.nmap_service_name && r.nmap_service_name !== r.service_name)
    ? ` <span style="color:var(--dim);font-size:0.78rem">(nmap service: "${esc(r.nmap_service_name)}")</span>`
    : "";
  const commentNote = r.nmap_comment
    ? ` <span style="color:var(--dim);font-size:0.78rem">— ${esc(r.nmap_comment)}</span>`
    : "";

  const freqBlock = freqText
    ? `<p class="usage-freq">${freqText} of internet-wide scans see this port open <span style="color:var(--dim);font-size:0.78rem">(nmap-services)</span>${svcNote}${commentNote}
       <br><a href="https://github.com/nmap/nmap/blob/master/nmap-services" target="_blank" rel="noopener noreferrer" style="font-size:0.78rem">View source ↗</a></p>`
    : "";

  el.innerHTML = `
    <div class="section-block" style="margin-bottom:1rem">
      <div class="section-title">Usage &amp; History</div>
      ${wikiBlock}
      ${freqBlock}
    </div>`;
}

// ── filter bar wiring ──────────────────────────────────────────────
function wireFilterBar() {
  const ids = ["cve-search", "filter-sev", "filter-kev", "filter-poc", "sort-by"];
  ids.forEach(id => {
    const el = $(id);
    if (el) el.addEventListener("input", () => { currentPage = 1; applyFiltersAndRender(); });
  });

  const dlCsv  = $("dl-csv");
  const dlJson = $("dl-json");
  if (dlCsv)  dlCsv.addEventListener("click",  downloadCsv);
  if (dlJson) dlJson.addEventListener("click", downloadJson);
}

// ── filters + sort ─────────────────────────────────────────────────
function applyFiltersAndRender() {
  const search   = ($("cve-search")?.value  || "").toLowerCase().trim();
  const sev      = $("filter-sev")?.value   || "";
  const kevOnly  = $("filter-kev")?.checked  || false;
  const pocOnly  = $("filter-poc")?.checked  || false;
  const sortBy   = $("sort-by")?.value       || "cvss";

  filteredCves = allCves.filter(c => {
    if (search  && !c.cve_id.toLowerCase().includes(search)) return false;
    if (sev     && c.cvss_severity !== sev)                  return false;
    if (kevOnly && !c.exploited_in_wild)                     return false;
    if (pocOnly && !(c.poc_count > 0))                       return false;
    return true;
  });

  // Sort
  filteredCves = [...filteredCves].sort((a, b) => {
    switch (sortBy) {
      case "cvss":
        return (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
      case "epss":
        return (b.epss_score ?? -1) - (a.epss_score ?? -1);
      case "published":
        return (b.published_at || "").localeCompare(a.published_at || "");
      case "cve_id":
        return (a.cve_id || "").localeCompare(b.cve_id || "");
      default:
        return (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
    }
  });

  updateCountLabel();
  renderTable();
  renderPagination();
}

function updateCountLabel() {
  const el = $("cve-count-label");
  if (!el) return;
  const total    = allCves.length;
  const filtered = filteredCves.length;
  el.textContent = filtered === total
    ? `${total.toLocaleString()} CVEs`
    : `${filtered.toLocaleString()} / ${total.toLocaleString()} CVEs`;
}

// ── table render ───────────────────────────────────────────────────
function renderTable() {
  const wrap = $("cve-table-wrap");
  if (!wrap) return;

  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = filteredCves.slice(start, start + PAGE_SIZE);

  if (!slice.length) {
    wrap.innerHTML = `<p class="no-data" style="padding:1.5rem 0">[i] No CVEs match the current filters.</p>`;
    return;
  }

  const rows = slice.map(c => {
    const cveId   = esc(c.cve_id || "—");
    const score   = c.cvss_score  != null ? esc(c.cvss_score.toFixed(1))             : "—";
    const sev     = esc(c.cvss_severity || "?");
    const epss    = c.epss_score  != null ? esc((c.epss_score * 100).toFixed(1)) + "%" : "—";
    const desc    = esc((c.description || "").slice(0, 100));
    const pocN    = c.poc_count        || 0;
    const edbN    = c.exploitdb_count  || 0;

    const kevCell = c.exploited_in_wild
      ? `<span class="badge-kev">KEV</span>`
      : `<span class="cell-dim">—</span>`;

    const pocCell = pocN
      ? `<span class="badge-poc">[PoC:${esc(String(pocN))}]</span>`
      : `<span class="cell-dim">—</span>`;

    const edbCell = edbN
      ? `<span class="badge-edb">[EDB:${esc(String(edbN))}]</span>`
      : `<span class="cell-dim">—</span>`;

    const nvdUrl = c.cve_id
      ? `https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}`
      : "#";

    return `<tr>
      <td class="col-cve"><a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="cve-link">${cveId}</a></td>
      <td class="col-cvss">${score}</td>
      <td class="col-sev sev-${sev}">${sev}</td>
      <td class="col-epss">${epss}</td>
      <td class="col-kev">${kevCell}</td>
      <td class="col-poc">${pocCell}</td>
      <td class="col-edb">${edbCell}</td>
      <td class="col-desc hide-mobile">${desc}</td>
    </tr>`;
  }).join("");

  wrap.innerHTML = `
    <table class="cve-table explorer-table">
      <thead>
        <tr>
          <th class="col-cve">CVE ID</th>
          <th class="col-cvss">CVSS</th>
          <th class="col-sev">Severity</th>
          <th class="col-epss">EPSS</th>
          <th class="col-kev">KEV</th>
          <th class="col-poc">PoC</th>
          <th class="col-edb">EDB</th>
          <th class="col-desc hide-mobile">Description</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── pagination ─────────────────────────────────────────────────────
function renderPagination() {
  const el = $("pagination");
  if (!el) return;

  const total = filteredCves.length;
  const pages = Math.ceil(total / PAGE_SIZE);

  if (pages <= 1) { el.innerHTML = ""; return; }

  const hasPrev = currentPage > 1;
  const hasNext = currentPage < pages;

  el.innerHTML = `
    <button class="pg-btn" id="pg-first" ${hasPrev ? "" : "disabled"} title="First page">«</button>
    <button class="pg-btn" id="pg-prev"  ${hasPrev ? "" : "disabled"}>← Prev</button>
    <span class="pg-label">Page ${currentPage} of ${pages} (${total.toLocaleString()} CVEs)</span>
    <button class="pg-btn" id="pg-next"  ${hasNext ? "" : "disabled"}>Next →</button>
    <button class="pg-btn" id="pg-last"  ${hasNext ? "" : "disabled"} title="Last page">»</button>`;

  if (hasPrev) {
    $("pg-first").addEventListener("click", () => gotoPage(1));
    $("pg-prev").addEventListener("click",  () => gotoPage(currentPage - 1));
  }
  if (hasNext) {
    $("pg-next").addEventListener("click", () => gotoPage(currentPage + 1));
    $("pg-last").addEventListener("click", () => gotoPage(pages));
  }
}

function gotoPage(n) {
  currentPage = n;
  renderTable();
  renderPagination();
  // Scroll table into view
  const wrap = $("cve-table-wrap");
  if (wrap) wrap.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── VARIoT section ─────────────────────────────────────────────────
function renderVariotSection(r) {
  const el    = $("variot-section");
  if (!el) return;
  const vulns = r.variot_vulns || [];
  if (!vulns.length) { el.innerHTML = ""; return; }

  const rows = vulns.map(v => {
    const cveId = esc(v.cve_id || "—");
    const score = v.cvss_score != null ? esc(v.cvss_score.toFixed(1)) : "—";
    const title = esc((v.title || v.description || "").slice(0, 80));
    const cveCell = v.cve_id && v.cve_id.startsWith("CVE-")
      ? `<a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" rel="noopener noreferrer" class="cve-link">${cveId}</a>`
      : cveId;
    return `<tr>
      <td>${cveCell}</td>
      <td style="color:var(--warn)">${score}</td>
      <td style="color:var(--dim);font-size:0.78rem">${title}</td>
    </tr>`;
  }).join("");

  el.innerHTML = `
    <div class="section-block" style="margin-top:2rem">
      <div class="section-title">VARIoT — IoT Vulnerabilities (${esc(String(vulns.length))} found)</div>
      <table class="cve-table">
        <thead><tr><th>CVE ID</th><th>CVSS</th><th>Title</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ── extra sections (techniques, pentest, defensive) ────────────────
function renderExtraSections(r) {
  const el = $("extra-sections");
  if (!el) return;

  let html = "";

  // MITRE ATT&CK techniques
  const techs = r.techniques || [];
  if (techs.length) {
    const items = techs.map(t => {
      const tactic = esc((t.tactic || "").replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase()));
      const rawUrl = t.url || `https://attack.mitre.org/techniques/${(t.technique_id || "").replace(".", "/")}/`;
      const url    = /^https:\/\/attack\.mitre\.org\//.test(rawUrl) ? esc(rawUrl) : "#";
      return `<div class="technique-item">
        <a href="${url}" target="_blank" rel="noopener noreferrer">
          <span class="technique-id">${esc(t.technique_id || "")}</span>
          <span class="technique-tactic">${tactic}</span>
          <span class="technique-name">${esc(t.name || "")}</span>
        </a>
      </div>`;
    }).join("");

    html += `<div class="section-block">
      <div class="section-title">MITRE ATT&amp;CK Techniques</div>
      <div class="technique-list">${items}</div>
    </div>`;
  }

  // Pentest notes
  const pentest = r.pentest_notes || [];
  if (pentest.length) {
    const items = pentest.map(n =>
      `<div class="note-item"><span class="note-bullet">·</span><span>${esc(n)}</span></div>`
    ).join("");
    html += `<div class="section-block">
      <div class="section-title">Pentest Notes</div>
      <div class="note-list">${items}</div>
    </div>`;
  }

  // Defensive notes
  const defensive = r.defensive_notes || [];
  if (defensive.length) {
    const items = defensive.map(n =>
      `<div class="note-item"><span class="note-bullet">·</span><span>${esc(n)}</span></div>`
    ).join("");
    html += `<div class="section-block">
      <div class="section-title">Defensive Recommendations</div>
      <div class="note-list">${items}</div>
    </div>`;
  }

  el.innerHTML = html ? `<div class="extra-sections">${html}</div>` : "";
}

// ── downloads ──────────────────────────────────────────────────────
function downloadCsv() {
  const port = portData ? portData.port : "unknown";
  const headers = ["cve_id","cvss_score","cvss_severity","epss_score","exploited_in_wild","poc_count","exploitdb_count","published_at","description"];
  const rows = filteredCves.map(c =>
    headers.map(h => {
      const v = c[h];
      if (v == null) return "";
      const s = String(v).replace(/"/g, '""');
      return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
    }).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  triggerDownload(csv, `port-${port}-cves.csv`, "text/csv;charset=utf-8");
}

function downloadJson() {
  const port = portData ? portData.port : "unknown";
  const json = JSON.stringify(filteredCves, null, 2);
  triggerDownload(json, `port-${port}-cves.json`, "application/json;charset=utf-8");
}

function triggerDownload(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

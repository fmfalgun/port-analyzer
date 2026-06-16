"""
sync.py — push analyzed port data to the GitHub Pages dataset via GitHub Contents API.

Requires GITHUB_PAT (Personal Access Token with `contents: write` scope) and
GITHUB_REPO (default: fmfalgun/port-analyzer) to be set in the environment or .env.

A PAT-authenticated push fires a real `push` event on GitHub, which triggers
deploy-pages.yml automatically — the site updates in ~30 seconds.

Two files are written per sync:
  - web/data/ports/{port}.json  — full data including all_cves (one file per port)
  - web/data/ports.json         — summary index (all_cves stripped, top_cves kept)
"""

import base64
import json
import os
from datetime import datetime, timezone


_GITHUB_API = "https://api.github.com"
_DEFAULT_REPO = "fmfalgun/port-analyzer"
_DATA_PATH = "web/data/ports.json"
_SOURCES = ["IANA", "NVD", "CISA KEV", "EPSS", "MITRE ATT&CK", "PoC-in-GitHub",
            "VARIoT", "AttackerKB", "Exploit-DB", "Wikipedia", "nmap-services"]


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _build_summary(result: dict) -> dict:
    """Strip all_cves from result for the lean ports.json index."""
    s = dict(result)
    s.pop("all_cves", None)
    return s


def _get_file(url: str, hdrs: dict) -> tuple:
    """
    Fetch a file from GitHub Contents API.

    Returns (content_dict_or_None, sha_or_None).
    404 is treated as a new file — returns (None, None).
    Raises RuntimeError for other non-OK responses.

    Only use this when the decoded content is actually needed (e.g. merging
    into the summary ports.json). The Contents API omits `content` (returns
    "") for files over ~1MB, which would make json.loads() blow up here —
    use _get_sha() instead when only the sha is needed.
    """
    import requests

    resp = requests.get(url, headers=hdrs, timeout=15)
    if resp.status_code == 404:
        return None, None
    if not resp.ok:
        raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
    info = resp.json()
    sha = info["sha"]
    raw = base64.b64decode(info["content"].replace("\n", ""))
    content = json.loads(raw.decode("utf-8"))
    return content, sha


def _get_sha(url: str, hdrs: dict) -> str | None:
    """
    Fetch only the sha of a file from GitHub Contents API, without decoding
    content. Safe for files over the Contents API's ~1MB inline-content
    limit (per-port full datasets can be several MB once a port has
    thousands of CVEs — e.g. port 443/22).

    Returns None if the file doesn't exist yet (404).
    Raises RuntimeError for other non-OK responses.
    """
    import requests

    resp = requests.get(url, headers=hdrs, timeout=15)
    if resp.status_code == 404:
        return None
    if not resp.ok:
        raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()["sha"]


def _put_file(url: str, hdrs: dict, content_bytes: bytes, sha, commit_message: str) -> dict:
    """
    PUT a file to GitHub Contents API.

    sha=None for new files (omits the sha key from the payload).
    Returns the parsed response JSON.
    Raises RuntimeError on failure.
    """
    import requests

    encoded = base64.b64encode(content_bytes).decode()
    payload: dict = {"message": commit_message, "content": encoded}
    if sha is not None:
        payload["sha"] = sha

    resp = requests.put(url, headers=hdrs, json=payload, timeout=30)
    if not resp.ok:
        raise RuntimeError(f"Push failed {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def sync_ports(results: list[dict], token: str = None, repo: str = None) -> tuple[bool, str]:
    """
    Push `results` (list of analyze_port() dicts) to GitHub:

      1. Each port's full data (including all_cves) → web/data/ports/{port}.json
      2. Summary-only data (all_cves stripped) merged into web/data/ports.json

    Returns (success: bool, message: str).
    """
    token = token or os.environ.get("GITHUB_PAT") or os.environ.get("GITHUB_TOKEN")
    repo = repo or os.environ.get("GITHUB_REPO", _DEFAULT_REPO)

    if not token:
        return False, "GITHUB_PAT not set — skipping sync (export GITHUB_PAT=ghp_...)"

    hdrs = _headers(token)
    valid_results = [r for r in results if "error" not in r]

    if not valid_results:
        return False, "No valid results to sync."

    port_labels = ", ".join(str(r["port"]) for r in valid_results)
    commit_urls: list[str] = []

    # ------------------------------------------------------------------ #
    # 1. Push each port's full data to web/data/ports/{port}.json         #
    # ------------------------------------------------------------------ #
    for r in valid_results:
        port = r["port"]
        per_port_path = f"web/data/ports/{port}.json"
        per_port_url = f"{_GITHUB_API}/repos/{repo}/contents/{per_port_path}"

        try:
            sha = _get_sha(per_port_url, hdrs)
        except RuntimeError as exc:
            return False, str(exc)

        content_bytes = json.dumps(r, indent=2).encode("utf-8")
        try:
            resp_json = _put_file(
                per_port_url,
                hdrs,
                content_bytes,
                sha,
                f"data: sync port {port} full dataset",
            )
        except RuntimeError as exc:
            return False, str(exc)

        commit_url = resp_json.get("commit", {}).get("html_url", "")
        if commit_url:
            commit_urls.append(commit_url)

    # ------------------------------------------------------------------ #
    # 2. Fetch current ports.json, merge summary-only data, push back     #
    # ------------------------------------------------------------------ #
    summary_url = f"{_GITHUB_API}/repos/{repo}/contents/{_DATA_PATH}"

    try:
        current_data, sha = _get_file(summary_url, hdrs)
    except RuntimeError as exc:
        return False, str(exc)

    if current_data is None:
        current_data = {
            "_meta": {"generated_at": "", "port_count": 0, "sources": _SOURCES}
        }

    for r in valid_results:
        current_data[str(r["port"])] = _build_summary(r)

    # Refresh _meta
    port_keys = [k for k in current_data if k != "_meta"]
    current_data["_meta"]["generated_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    current_data["_meta"]["port_count"] = len(port_keys)
    current_data["_meta"]["sources"] = _SOURCES

    content_bytes = json.dumps(current_data, indent=2).encode("utf-8")
    try:
        resp_json = _put_file(
            summary_url,
            hdrs,
            content_bytes,
            sha,
            f"data: update ports.json summary — port(s) {port_labels}",
        )
    except RuntimeError as exc:
        return False, str(exc)

    commit_url = resp_json.get("commit", {}).get("html_url", "")
    if commit_url:
        commit_urls.append(commit_url)

    summary_line = "\n    ".join(commit_urls)
    return (
        True,
        f"Synced port(s) {port_labels} → {repo} | deploy in ~30s\n    {summary_line}",
    )

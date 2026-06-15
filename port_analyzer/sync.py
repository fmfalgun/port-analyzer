"""
sync.py — push analyzed port data to the GitHub Pages dataset via GitHub Contents API.

Requires GITHUB_PAT (Personal Access Token with `contents: write` scope) and
GITHUB_REPO (default: fmfalgun/port-analyzer) to be set in the environment or .env.

A PAT-authenticated push fires a real `push` event on GitHub, which triggers
deploy-pages.yml automatically — the site updates in ~30 seconds.
"""

import base64
import json
import os
from datetime import datetime, timezone


_GITHUB_API = "https://api.github.com"
_DEFAULT_REPO = "fmfalgun/port-analyzer"
_DATA_PATH = "web/data/ports.json"
_SOURCES = ["IANA", "NVD", "CISA KEV", "EPSS", "MITRE ATT&CK"]


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def sync_ports(results: list[dict], token: str = None, repo: str = None) -> tuple[bool, str]:
    """
    Merge `results` (list of analyze_port() dicts) into the live ports.json on GitHub.

    Returns (success: bool, message: str).
    """
    import requests  # already in requirements.txt

    token = token or os.environ.get("GITHUB_PAT") or os.environ.get("GITHUB_TOKEN")
    repo = repo or os.environ.get("GITHUB_REPO", _DEFAULT_REPO)

    if not token:
        return False, "GITHUB_PAT not set — skipping sync (export GITHUB_PAT=ghp_...)"

    url = f"{_GITHUB_API}/repos/{repo}/contents/{_DATA_PATH}"
    hdrs = _headers(token)

    # Fetch current ports.json
    resp = requests.get(url, headers=hdrs, timeout=15)
    if resp.status_code == 404:
        current_data: dict = {"_meta": {"generated_at": "", "port_count": 0, "sources": _SOURCES}}
        sha = None
    elif not resp.ok:
        return False, f"GitHub API error {resp.status_code}: {resp.text[:200]}"
    else:
        info = resp.json()
        sha = info["sha"]
        raw = base64.b64decode(info["content"].replace("\n", ""))
        current_data = json.loads(raw.decode("utf-8"))

    # Merge new results
    for r in results:
        if "error" in r:
            continue
        current_data[str(r["port"])] = r

    # Refresh _meta
    port_keys = [k for k in current_data if k != "_meta"]
    current_data["_meta"]["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    current_data["_meta"]["port_count"] = len(port_keys)
    current_data["_meta"]["sources"] = _SOURCES

    # Encode and push
    encoded = base64.b64encode(json.dumps(current_data, indent=2).encode("utf-8")).decode()
    port_labels = ", ".join(str(r["port"]) for r in results if "error" not in r)
    payload = {
        "message": f"data: add port(s) {port_labels} via CLI sync",
        "content": encoded,
    }
    if sha:
        payload["sha"] = sha

    resp = requests.put(url, headers=hdrs, json=payload, timeout=30)
    if not resp.ok:
        return False, f"Push failed {resp.status_code}: {resp.text[:200]}"

    commit_url = resp.json().get("commit", {}).get("html_url", "")
    return True, f"Synced port(s) {port_labels} → {repo} | deploy in ~30s\n    {commit_url}"

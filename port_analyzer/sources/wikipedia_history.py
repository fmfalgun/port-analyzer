"""
Wikipedia — "List of TCP and UDP port numbers" article.
Free public MediaWiki API, no key required. The whole article is parsed
once and cached for ~30 days (port assignments/history change extremely
rarely); each port query just looks up its row from the cached parse.
"""

import re
import requests
from bs4 import BeautifulSoup
from port_analyzer.cache import get_wikipedia_ports_cache, set_wikipedia_ports_cache, upsert_port_history

WIKI_API_URL = "https://en.wikipedia.org/w/api.php"
WIKI_PAGE = "List_of_TCP_and_UDP_port_numbers"


def _fetch_and_parse() -> dict:
    """Fetch the article HTML and parse every wikitable into {port_str: description}."""
    resp = requests.get(WIKI_API_URL, params={
        "action": "parse",
        "page": WIKI_PAGE,
        "format": "json",
        "prop": "text",
        "formatversion": "2",
    }, timeout=20, headers={"User-Agent": "port-analyzer/1.0 (https://github.com/fmfalgun/port-analyzer)"})
    resp.raise_for_status()
    html = resp.json()["parse"]["text"]

    soup = BeautifulSoup(html, "html.parser")
    parsed: dict[str, str] = {}

    for table in soup.find_all("table", class_=lambda c: c and "wikitable" in c):
        rows = table.find_all("tr")
        if not rows:
            continue
        header_cells = [c.get_text(strip=True).lower() for c in rows[0].find_all(["th", "td"])]
        has_port = any("port" in h for h in header_cells)
        has_desc = any("description" in h or "use" in h for h in header_cells)
        if not (has_port and has_desc):
            continue

        # Don't trust header-matched column *indices* for cell access: rows
        # often merge blank TCP/UDP/SCTP/DCCP cells via colspan, so the cell
        # count varies per row and a fixed index can land short or on the
        # wrong cell. Port is reliably the first <td>; Description is
        # reliably the last <td>, regardless of how many columns collapsed
        # in between — index from the ends instead.
        for row in rows[1:]:
            cells = row.find_all("td")
            if len(cells) < 2:
                continue
            # Strip Wikipedia footnote/reference superscripts (e.g. [477]) before
            # extracting text — they render as "[ 477 ]" noise in get_text().
            for sup in cells[-1].find_all("sup", class_="reference"):
                sup.decompose()
            port_text = cells[0].get_text(" ", strip=True)
            desc_text = cells[-1].get_text(" ", strip=True)
            desc_text = re.sub(r"\s*\[\s*\d+\s*\]", "", desc_text).strip()
            if not desc_text:
                continue
            for num_str in re.findall(r"\d+", port_text):
                try:
                    num = int(num_str)
                except ValueError:
                    continue
                if 0 <= num <= 65535 and str(num) not in parsed:
                    parsed[str(num)] = desc_text[:1500]  # cap length

    return parsed


def fetch_wikipedia_history_for_port(port: int, db=None) -> None:
    """
    Idempotent, never raises. Ensures the Wikipedia ports table is cached
    (refetching if stale/missing), then upserts this port's description
    into port_history if found.
    """
    if db is None:
        return
    try:
        cached = get_wikipedia_ports_cache(db)
        if cached is None:
            cached = _fetch_and_parse()
            if cached:
                set_wikipedia_ports_cache(db, cached)

        if not cached:
            return

        desc = cached.get(str(port))
        if desc:
            upsert_port_history(db, port, wiki_description=desc)

    except Exception as exc:
        print(f"[!] wikipedia_history: failed for port {port}: {exc}")

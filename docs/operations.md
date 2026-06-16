# Operations & Performance Notes

Practical guidance for running large batch analyses/syncs, and an honest
assessment of what would (and wouldn't) speed the pipeline up. This is a
working-notes doc, not formal architecture documentation — see
`docs/architecture.md` for system design and `README.md` for user-facing docs.

---

## 1. How `--sync` actually sequences work

For a multi-port CLI invocation (`python -m port_analyzer.cli 22,443,... --sync`):

```
for each port in the list:
    analyze_port(port)        # live fetch + cache write, one port at a time
    collect result

# only after EVERY port above has finished:
sync_ports(all_results)       # push to GitHub, port by port, in one batch
```

**Analysis completes for all ports first, then sync runs once at the end** —
not "analyze port → push port → next port." Within `sync_ports()` itself, the
GitHub push *does* loop port-by-port (with skip-and-continue resilience, see
§3), but that loop only starts once every port has been analyzed.

### Why this is safe to interrupt

- **Interrupted during analysis** (the slow phase): nothing has been pushed
  to GitHub yet, but nothing is lost — every port already analyzed is cached
  in SQLite (`db/port_analyzer.db`). Re-running the same command skips the
  slow live fetch for already-cached ports and only does live work for the
  ones not yet reached.
- **Interrupted during sync**: whatever already pushed stays pushed (real
  commits on GitHub). Re-running is safe and idempotent — already-pushed
  ports just get redundantly re-pushed with identical content.

### Why we kept batch-at-the-end over per-port incremental sync

Considered switching to push-immediately-after-each-port. Decided against it:
a 124-port run would trigger ~124 separate pushes (each a `git push`-equivalent
via the GitHub Contents API), each of which fires a real `push` event and
triggers `deploy-pages.yml` — up to 124 separate Pages deployments queued
instead of one. The current batch model gives one deploy wave per CLI run,
and the resilience fix in §3 already covers the main risk (one bad port
killing the rest) without that downside.

---

## 2. Rate limits — what's actually at risk during a large batch

Checked every source module's actual throttling code (not assumptions) before
running a 124-port batch. Only two sources use a real, finite-quota
credential; everything else is keyless.

| Source | Credential | Limit | Self-throttle in code | Risk at 124 ports |
|---|---|---|---|---|
| **NVD** | `NVD_API_KEY` | 50 req/30s (5 req/30s without key) | `RATE_SLEEP = 0.6s` (paced to the limit exactly) | None from a single sequential run — **but see warning below** |
| **GitHub sync** | `GITHUB_PAT` | 5,000 req/hr | N/A (well under limit by volume alone) | None — ~124×2 + 2 ≈ 250 calls total, ~5% of hourly quota |
| PoC-in-GitHub | none | — | `REQ_SLEEP=0.5s`, capped 20 CVEs/port | None — hits `raw.githubusercontent.com` (CDN), not GitHub's rate-limited REST/Search API |
| AttackerKB | none | unknown (public API) | `REQ_SLEEP=0.5s`, capped 20 CVEs/port | Low |
| EPSS | none | — | batches 100 CVEs/request, 1s sleep between batches | Low |
| CISA KEV | none | — | one shared blob fetch, cached 24h | None — first port in the run primes the cache, rest reuse it |
| Wikipedia | none | — | one shared blob fetch, cached 30 days | None — same caching behavior |
| nmap-services | none | — | one shared blob fetch, cached 30 days | None — same |
| Exploit-DB | none | — | one shared CSV fetch, cached 24h | None — same |
| Shadowserver | `SHADOWSERVER_API_KEY` (unset by default) | — | no-op without key | Zero calls |
| VARIoT | none | — | per-term sleep, fails fast on error | Currently near-zero — see §4 |

**The one real warning**: NVD's limit is *per API key*, not per-process. The
code's `RATE_SLEEP` correctly paces a single sequential CLI run to exactly the
allowed rate — but running a **second** CLI/`build_data.py` process in
parallel against the same key doubles the effective request rate and risks
`429`s. Don't run two instances concurrently against the same `NVD_API_KEY`.

---

## 3. Resilience fixes made for large batches

Two bugs were found and fixed specifically because of running larger batches
than the project had previously tested:

1. **GitHub Contents API's ~1MB inline-content limit.** Per-port files for
   high-CVE-count ports (e.g. port 443 at 11.7MB) caused a crash: the sync
   step fetched the *existing* file just to read its `sha` (discarding the
   content), but GitHub returns an empty `content` field for files over
   ~1MB, and `json.loads("")` blew up. Fixed with a dedicated `_get_sha()`
   that never attempts to decode content — only `_get_file()` (used for the
   small summary `ports.json`) still decodes.

2. **Abort-all → skip-and-continue.** Originally, `sync_ports()` returned
   immediately on the first port's push failure, leaving every subsequent
   port in the batch unattempted. Now a failed port is logged and skipped;
   the loop continues; the final message reports both successes and
   failures, and re-running `--sync` safely retries whatever didn't make it.

3. **PUT timeout scaling.** A fixed 30s timeout was too short for multi-MB
   uploads on real connections. Timeout now scales ~15s per MB of the
   base64-encoded payload (minimum 30s).

See `docs/architecture.md` §7.3 for the full technical writeup of these.

---

## 4. Known external issue: VARIoT

Investigated why the VARIoT section never appears in any output. Root cause,
confirmed via an independent DNS-over-HTTPS lookup (Cloudflare's resolver,
bypassing any local resolver): `variot.eu` returns `SERVFAIL` — "No Reachable
Authority at delegation variot.eu." This is an **upstream outage**, not a bug
in this project. `fetch_variot_for_port()`'s existing graceful degradation
(catch the connection failure per search term, store 0 results, no crash) is
working exactly as designed. No code changes needed; if/when VARIoT's DNS is
restored, the feature resumes working with zero changes on our end.

---

## 5. Can a GPU speed this up?

**No.** A GPU accelerates workloads with massive *numerical* parallelism —
matrix multiplication, tensor ops, SIMD over large arrays (ML
training/inference, image/video processing, hashing at scale). This
pipeline's wall-clock time is dominated by `time.sleep()` calls waiting on
external rate limits:

```
port_analyzer/sources/nvd.py:        RATE_SLEEP = 0.6s   (per request)
port_analyzer/sources/epss.py:       time.sleep(1)       (per 100-CVE batch)
port_analyzer/sources/poc_github.py: REQ_SLEEP = 0.5s    (per CVE, capped at 20)
port_analyzer/sources/attackerkb.py: REQ_SLEEP = 0.5s    (per CVE, capped at 20)
port_analyzer/sources/variot.py:     REQ_SLEEP = 1.0s    (per search term)
```

A GPU sits idle during a `time.sleep()` — there's no tensor op to hand it.
The only CPU-bound work in the whole pipeline (JSON parsing, the one-time
Wikipedia HTML table parse, regex matching, SQLite I/O) is already fast and
dwarfed by the sleep calls above; none of it is GPU-shaped work either.

### What would actually help — and why it's not implemented

The real lever is **concurrency**: overlapping the *waiting* time of
multiple ports instead of waiting sequentially. While port A sleeps 0.6s for
its next NVD page, port B's request could be in flight. This is a
CPU/network-I/O optimization (threads or `asyncio`), not a GPU one — Python's
`requests` releases the GIL during network waits, so even simple threading
helps here, no specialized hardware required.

**The catch, and why this isn't a quick win**: NVD's 50 req/30s budget is
shared across the whole API key, not per-thread. Naively running N ports in
parallel — each independently sleeping 0.6s — would let N requests fire
almost simultaneously, blowing through the shared budget and risking `429`s.
A real implementation needs a **shared rate limiter** (token bucket) per
external source, used by every concurrent port-worker, not just deleting the
sleep calls. That means touching every module under `port_analyzer/sources/`
to route through a shared limiter instead of an independent local sleep —
a genuine refactor, weighed against the actual time saved, and not undertaken
without that trade-off being deliberately decided.

**Status: not implemented.** Current architecture processes ports strictly
sequentially. If batch wall-clock time becomes a real pain point, the next
step would be a `ThreadPoolExecutor` (or `asyncio` rewrite) with a shared
per-source rate limiter — not a GPU.

---

*Document version: 1.0 — created 2026-06-16, covering the 124-port batch
sync planning conversation.*

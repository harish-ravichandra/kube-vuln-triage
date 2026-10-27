"""Exploit-likelihood enrichment: CISA KEV membership and FIRST EPSS scores."""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_AGE_SECONDS = 24 * 3600
EPSS_BATCH = 100
USER_AGENT = "cva/0.1 (+container-vuln-attribution)"


@dataclass
class EnrichInfo:
    kev_catalog_version: str = ""
    kev_count: int = 0
    epss_requested: int = 0
    epss_fetched_batches: int = 0
    offline: bool = False


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _fresh(path: Path) -> bool:
    return path.exists() and time.time() - path.stat().st_mtime < MAX_AGE_SECONDS


def load_kev(cache_dir: Path, offline: bool, info: EnrichInfo) -> set[str]:
    """CVE IDs in the CISA KEV catalog, refreshed at most once a day."""
    path = cache_dir / "kev.json"
    if not offline and not _fresh(path):
        try:
            data = _get_json(KEV_URL)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        except OSError as exc:
            print(f"warning: KEV download failed ({exc}); using cache if present", file=sys.stderr)
    if not path.exists():
        print("warning: no KEV data available; KEV treated as false for all findings", file=sys.stderr)
        return set()
    data = json.loads(path.read_text())
    info.kev_catalog_version = data.get("catalogVersion", "")
    kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
    info.kev_count = len(kev)
    return kev


def load_epss(cve_ids: set[str], cache_dir: Path, offline: bool, info: EnrichInfo) -> dict[str, float]:
    """EPSS probability per CVE, queried in batches; unknown CVEs score 0.0.

    The cache stores every CVE asked for (null when FIRST has no score) with the
    fetch time, so repeat runs within a day make no requests at all.
    """
    path = cache_dir / "epss.json"
    cache: dict[str, dict] = json.loads(path.read_text()) if path.exists() else {}
    wanted = sorted(c for c in cve_ids if c.startswith("CVE-"))
    info.epss_requested = len(wanted)
    now = time.time()
    stale = [c for c in wanted if now - cache.get(c, {}).get("fetched", 0) >= MAX_AGE_SECONDS]

    if stale and not offline:
        for i in range(0, len(stale), EPSS_BATCH):
            batch = stale[i : i + EPSS_BATCH]
            query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": EPSS_BATCH})
            try:
                data = _get_json(f"{EPSS_URL}?{query}")
            except OSError as exc:
                print(f"warning: EPSS batch failed ({exc}); keeping cached values", file=sys.stderr)
                continue
            info.epss_fetched_batches += 1
            scores = {row["cve"]: float(row["epss"]) for row in data.get("data", [])}
            for cve in batch:
                cache[cve] = {"epss": scores.get(cve), "fetched": now}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, sort_keys=True))

    return {c: (cache.get(c, {}).get("epss") or 0.0) for c in wanted}

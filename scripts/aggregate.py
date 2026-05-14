#!/usr/bin/env python3
"""
CTI Daily Brief - Aggregator
Pulls open-source threat intel feeds, normalizes, deduplicates, enriches,
and writes a single JSON file consumed by the static dashboard.

Run locally:  python scripts/aggregate.py
Run in CI:    handled by .github/workflows/build.yml
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import feedparser
import requests
import yaml
from dateutil import parser as dateparser

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "scripts" / "sources.yaml"
OUTPUT_FILE = ROOT / "docs" / "data.json"
HISTORY_DIR = ROOT / "data"

USER_AGENT = "CTI-Daily-Brief/1.0 (+https://github.com/) feedparser"
HTTP_TIMEOUT = 30
LOOKBACK_HOURS = 72            # items older than this are dropped
PRIORITY_FLOOR_FOR_HEADLINE = 0  # show everything in headlines, sort by score

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HTML_TAG_RE = re.compile(r"<[^>]+>")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("aggregate")


# ----------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------

@dataclass
class Item:
    id: str
    title: str
    summary: str
    url: str
    source: str
    source_trust: int
    category: str              # threat | vuln | advisory | breach | mixed
    published: str             # ISO8601
    published_ts: float        # epoch for sort
    cves: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    actively_exploited: bool = False
    cvss: float | None = None
    priority_score: int = 0
    priority_label: str = "Low"
    related_sources: list[dict] = field(default_factory=list)  # for correlated dupes


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def load_config() -> dict:
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def clean_html(text: str | None) -> str:
    if not text:
        return ""
    text = HTML_TAG_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_date(value: Any) -> tuple[str, float]:
    """Return (iso_string, epoch_seconds). Falls back to now() on failure."""
    if not value:
        return datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).timestamp()
    try:
        if isinstance(value, (list, tuple)):
            value = value[0]
        if isinstance(value, str):
            dt = dateparser.parse(value)
        else:
            # feedparser struct_time
            dt = datetime(*value[:6], tzinfo=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(), dt.timestamp()
    except Exception:
        now = datetime.now(timezone.utc)
        return now.isoformat(), now.timestamp()


def hash_id(*parts: str) -> str:
    h = hashlib.sha1("||".join(parts).encode("utf-8")).hexdigest()
    return h[:16]


def extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(text or "")})


def detect_sectors(text: str, sector_map: dict) -> list[str]:
    text_l = (text or "").lower()
    hits = []
    for sector, keywords in sector_map.items():
        for kw in keywords:
            if kw.lower() in text_l:
                hits.append(sector)
                break
    return hits


def detect_regions(text: str, region_map: dict) -> list[str]:
    text_l = (text or "").lower()
    hits = []
    for region, keywords in region_map.items():
        for kw in keywords:
            if kw.lower() in text_l:
                hits.append(region)
                break
    return hits or ["Unspecified"]


def detect_active_exploitation(text: str, keywords: list[str]) -> bool:
    text_l = (text or "").lower()
    return any(kw.lower() in text_l for kw in keywords)


def detect_products(text: str) -> list[str]:
    """Lightweight product extraction. Extend as needed."""
    products = []
    catalog = [
        "Windows", "Linux", "macOS", "Android", "iOS", "Chrome", "Firefox", "Edge",
        "Safari", "Outlook", "Exchange", "Office", "SharePoint", "Active Directory",
        "VMware ESXi", "VMware vCenter", "Citrix", "Fortinet", "FortiOS", "Cisco IOS",
        "Cisco ASA", "Palo Alto PAN-OS", "Ivanti", "MOVEit", "SolarWinds", "Zimbra",
        "Confluence", "Jira", "WordPress", "Apache", "Nginx", "OpenSSL", "Log4j",
        "Kubernetes", "Docker", "Jenkins", "GitLab", "GitHub", "Slack", "Zoom",
        "Salesforce", "ServiceNow", "Oracle WebLogic", "SAP", "MySQL", "PostgreSQL",
        "MongoDB", "Redis",
    ]
    text_l = (text or "").lower()
    for p in catalog:
        if p.lower() in text_l:
            products.append(p)
    return sorted(set(products))


def fingerprint(title: str, cves: list[str]) -> str:
    """Stable key for grouping near-duplicate stories across feeds."""
    if cves:
        return "cve::" + "|".join(sorted(cves))
    # normalize title: lowercase, strip punctuation, keep significant tokens
    norm = re.sub(r"[^a-z0-9 ]", " ", title.lower())
    tokens = [t for t in norm.split() if len(t) > 3]
    # use top 6 tokens to be loose enough to merge but not too loose
    key_tokens = sorted(tokens)[:6]
    return "title::" + "|".join(key_tokens)


# ----------------------------------------------------------------------
# Fetchers
# ----------------------------------------------------------------------

def fetch_rss(feed: dict) -> list[Item]:
    log.info("Fetching RSS: %s", feed["name"])
    try:
        resp = requests.get(
            feed["url"],
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except Exception as e:
        log.warning("Failed %s: %s", feed["name"], e)
        return []

    items: list[Item] = []
    for entry in parsed.entries[:50]:
        title = clean_html(entry.get("title", "")).strip()
        if not title:
            continue
        link = entry.get("link", "")
        summary = clean_html(
            entry.get("summary") or entry.get("description") or ""
        )[:1500]
        published_raw = (
            entry.get("published")
            or entry.get("updated")
            or entry.get("published_parsed")
        )
        published_iso, published_ts = parse_date(published_raw)
        full_text = f"{title} {summary}"
        items.append(Item(
            id=hash_id(feed["name"], link or title),
            title=title,
            summary=summary,
            url=link,
            source=feed["name"],
            source_trust=feed.get("trust", 3),
            category=feed.get("category", "mixed"),
            published=published_iso,
            published_ts=published_ts,
            cves=extract_cves(full_text),
        ))
    log.info("  → %d items", len(items))
    return items


def fetch_nvd(feed: dict) -> list[Item]:
    """NVD CVE API 2.0 — newest first."""
    log.info("Fetching NVD: %s", feed["name"])
    # restrict to last 7 days to keep things relevant
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    url = (
        feed["url"]
        + f"&pubStartDate={start.strftime('%Y-%m-%dT00:00:00.000')}"
        + f"&pubEndDate={end.strftime('%Y-%m-%dT23:59:59.999')}"
    )
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("NVD fetch failed: %s", e)
        return []

    items: list[Item] = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        published_iso, published_ts = parse_date(cve.get("published"))
        # CVSS - try v3.1 then v3.0 then v2
        cvss = None
        metrics = cve.get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                try:
                    cvss = float(metrics[k][0]["cvssData"]["baseScore"])
                    break
                except Exception:
                    pass
        url_cve = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        items.append(Item(
            id=hash_id("NVD", cve_id),
            title=f"{cve_id}: {desc[:140]}",
            summary=desc[:1500],
            url=url_cve,
            source="NVD",
            source_trust=5,
            category="vuln",
            published=published_iso,
            published_ts=published_ts,
            cves=[cve_id],
            cvss=cvss,
        ))
    log.info("  → %d items", len(items))
    return items


def fetch_cisa_kev(feed: dict) -> list[Item]:
    log.info("Fetching CISA KEV catalog")
    try:
        resp = requests.get(feed["url"], headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("KEV fetch failed: %s", e)
        return []

    items: list[Item] = []
    # only show recently added KEV entries
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    for v in data.get("vulnerabilities", []):
        try:
            added = dateparser.parse(v["dateAdded"]).replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if added < cutoff:
            continue
        cve_id = v.get("cveID", "")
        title = f"{cve_id}: {v.get('vulnerabilityName','')} ({v.get('vendorProject','')} {v.get('product','')})"
        summary = (
            f"CISA KEV — actively exploited. "
            f"{v.get('shortDescription','')} "
            f"Required action: {v.get('requiredAction','N/A')} "
            f"(due {v.get('dueDate','N/A')})."
        )
        items.append(Item(
            id=hash_id("KEV", cve_id),
            title=title,
            summary=summary,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            source="CISA KEV",
            source_trust=5,
            category="vuln",
            published=added.isoformat(),
            published_ts=added.timestamp(),
            cves=[cve_id],
            actively_exploited=True,
        ))
    log.info("  → %d items", len(items))
    return items


FETCHERS = {
    "rss": fetch_rss,
    "atom": fetch_rss,
    "nvd": fetch_nvd,
    "cisa_kev": fetch_cisa_kev,
}


# ----------------------------------------------------------------------
# Enrichment, dedup, scoring
# ----------------------------------------------------------------------

def enrich(items: list[Item], cfg: dict) -> None:
    sectors_map = cfg.get("sectors", {})
    regions_map = cfg.get("regions", {})
    exploit_kws = cfg.get("exploitation_keywords", [])
    for it in items:
        text = f"{it.title} {it.summary}"
        it.sectors = it.sectors or detect_sectors(text, sectors_map)
        it.regions = it.regions or detect_regions(text, regions_map)
        it.products = it.products or detect_products(text)
        if not it.actively_exploited:
            it.actively_exploited = detect_active_exploitation(text, exploit_kws)


def deduplicate(items: list[Item]) -> list[Item]:
    """Group items by fingerprint, keep the most trusted, attach related sources."""
    buckets: dict[str, list[Item]] = {}
    for it in items:
        fp = fingerprint(it.title, it.cves)
        buckets.setdefault(fp, []).append(it)

    deduped: list[Item] = []
    for group in buckets.values():
        group.sort(key=lambda x: (x.source_trust, x.published_ts), reverse=True)
        primary = group[0]
        # merge metadata across the group
        merged_cves = set(primary.cves)
        merged_sectors = set(primary.sectors)
        merged_regions = set(primary.regions)
        merged_products = set(primary.products)
        related = []
        for dup in group[1:]:
            merged_cves.update(dup.cves)
            merged_sectors.update(dup.sectors)
            merged_regions.update(dup.regions)
            merged_products.update(dup.products)
            if dup.actively_exploited:
                primary.actively_exploited = True
            if dup.cvss and (primary.cvss is None or dup.cvss > primary.cvss):
                primary.cvss = dup.cvss
            related.append({
                "source": dup.source,
                "url": dup.url,
                "title": dup.title,
                "published": dup.published,
            })
        primary.cves = sorted(merged_cves)
        primary.sectors = sorted(merged_sectors)
        # remove "Unspecified" if a real region was found via duplicates
        regions_clean = {r for r in merged_regions if r != "Unspecified"} or {"Unspecified"}
        primary.regions = sorted(regions_clean)
        primary.products = sorted(merged_products)
        primary.related_sources = related
        deduped.append(primary)
    return deduped


def score(items: list[Item]) -> None:
    """
    Priority scoring (0-100). Rough weights:
      - Active exploitation:      +35
      - CISA KEV listing:         +20
      - CVSS >= 9.0 (Critical):   +20  (>=7.0 Critical+High: +10)
      - Sector breadth:           +5 per impacted sector (cap 25)
      - Global region tag:        +10
      - High-trust vendor source: +5
      - Mentions "ransomware" / APT: +5
      - Recency (within 24h):     +5
    Then labelled: Critical/High/Medium/Low.
    """
    now_ts = datetime.now(timezone.utc).timestamp()
    for it in items:
        s = 0
        text_l = f"{it.title} {it.summary}".lower()

        if it.actively_exploited:
            s += 35
        if it.source == "CISA KEV":
            s += 20
        if it.cvss is not None:
            if it.cvss >= 9.0:
                s += 20
            elif it.cvss >= 7.0:
                s += 10
        s += min(25, 5 * len(it.sectors))
        if "Global" in it.regions:
            s += 10
        if it.source_trust >= 5:
            s += 5
        if "ransomware" in text_l or "apt" in text_l or "nation-state" in text_l:
            s += 5
        if now_ts - it.published_ts <= 86400:
            s += 5

        s = max(0, min(100, s))
        it.priority_score = s
        if s >= 75:
            it.priority_label = "Critical"
        elif s >= 50:
            it.priority_label = "High"
        elif s >= 25:
            it.priority_label = "Medium"
        else:
            it.priority_label = "Low"


def filter_recent(items: list[Item], hours: int) -> list[Item]:
    cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
    return [it for it in items if it.published_ts >= cutoff]


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> int:
    cfg = load_config()
    all_items: list[Item] = []

    for feed in cfg["feeds"]:
        fetcher = FETCHERS.get(feed["type"])
        if not fetcher:
            log.warning("No fetcher for type=%s", feed["type"])
            continue
        try:
            all_items.extend(fetcher(feed))
        except Exception as e:
            log.exception("Fetcher crashed for %s: %s", feed["name"], e)

    log.info("Total raw items: %d", len(all_items))

    all_items = filter_recent(all_items, LOOKBACK_HOURS)
    log.info("After %dh lookback: %d", LOOKBACK_HOURS, len(all_items))

    enrich(all_items, cfg)
    deduped = deduplicate(all_items)
    log.info("After dedup: %d", len(deduped))

    score(deduped)
    deduped.sort(key=lambda x: (x.priority_score, x.published_ts), reverse=True)

    # Build output
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_hours": LOOKBACK_HOURS,
        "totals": {
            "all": len(deduped),
            "critical": sum(1 for x in deduped if x.priority_label == "Critical"),
            "high": sum(1 for x in deduped if x.priority_label == "High"),
            "medium": sum(1 for x in deduped if x.priority_label == "Medium"),
            "low": sum(1 for x in deduped if x.priority_label == "Low"),
            "actively_exploited": sum(1 for x in deduped if x.actively_exploited),
            "with_cves": sum(1 for x in deduped if x.cves),
        },
        "sources_used": sorted({x.source for x in deduped}),
        "items": [asdict(x) for x in deduped],
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    log.info("Wrote %s", OUTPUT_FILE)

    # Daily snapshot for history
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    snap = HISTORY_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
    with open(snap, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    log.info("Wrote snapshot %s", snap)

    return 0


if __name__ == "__main__":
    sys.exit(main())

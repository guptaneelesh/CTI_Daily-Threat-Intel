# CTI Daily Brief

A self-updating, open-source **Cyber Threat Intelligence dashboard** hosted on GitHub Pages.
Pulls from 20+ open feeds (CISA, NVD, MSRC, Unit 42, Cisco Talos, Microsoft, Google TAG,
CrowdStrike, SentinelOne, Trend Micro, BleepingComputer, The Hacker News, GBHackers,
Krebs, Securelist, Check Point, and more), deduplicates, scores by priority, and renders
a static dashboard with headlines + drill-down detail.

## Architecture

```
┌────────────────────┐    cron 6h    ┌──────────────────────┐    commits    ┌──────────────┐
│  GitHub Actions    │ ───────────▶  │  scripts/aggregate.py │ ────────────▶ │  docs/data.json │
│  (.github/wf)      │               │  (Python: feedparser, │               │  + data/YYYY-MM-DD.json │
└────────────────────┘               │   requests, yaml)     │               └──────┬───────┘
                                     └──────────────────────┘                       │
                                                                                    ▼
                                                                          ┌─────────────────┐
                                                                          │ GitHub Pages    │
                                                                          │ docs/index.html │
                                                                          │ + style.css     │
                                                                          │ + app.js        │
                                                                          └─────────────────┘
```

- **No backend.** Aggregator runs in CI, commits a JSON file, static page reads it.
- **No LLM cost.** Dedup is fingerprint-based (CVE id or normalized title tokens).
- **No secrets.** Only public feeds; no API keys required.

## What you get

- **Headlines view** — top 15 items from the last 24h, numbered ticker style, click → primary source.
- **Full feed** — every item in the last 72h, with priority pill, CVSS, exploitation badge, CVE/product/sector/region tags, and corroborating sources collapsed under a "+ N corroborating" link.
- **Priority scoring** (0–100) considering: active exploitation, CISA KEV listing, CVSS, sector breadth, global impact, vendor-source trust, ransomware/APT keywords, recency.
- **Filters** — text search, category (threat/vuln/advisory/breach), sector, priority, "actively exploited only".
- **Click-through stats** — every tile at the top is a clickable shortcut filter.
- **Daily snapshots** committed to `data/YYYY-MM-DD.json` so you have a history.

## Sector mapping

Items are auto-tagged into the six sectors you specified:

- Consumer
- Financial Services
- Energy Resources & Industrials
- Life Sciences & Health Care
- Government & Public Services
- Technology, Media & Telecom

Mapping is keyword-based and editable in `scripts/sources.yaml` → `sectors:`.

---

## Step-by-step deployment

### 1. Create the repo

```bash
gh repo create cti-daily-brief --public --clone
cd cti-daily-brief
```

Or use the GitHub UI. Then copy every file from this template into the repo.

### 2. Push the code

```bash
git add .
git commit -m "Initial CTI Daily Brief"
git push -u origin main
```

### 3. Enable GitHub Pages

Repo → **Settings → Pages**:
- **Source:** GitHub Actions
- That's it. The workflow uses `actions/deploy-pages` and needs no manual branch.

### 4. (Optional) NVD API key

The NVD API works anonymously but you're rate-limited to 5 requests / 30s. With an API
key you get 50 requests / 30s. To use a key:

1. Get one at <https://nvd.nist.gov/developers/request-an-api-key>.
2. Repo → Settings → Secrets and variables → Actions → **New repository secret**:
   `NVD_API_KEY` = `your-key`.
3. Add this to `.github/workflows/build.yml` under the "Run aggregator" step:
   ```yaml
   env:
     NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
   ```
   And in `scripts/aggregate.py`, in `fetch_nvd()`, add the header:
   ```python
   headers = {"User-Agent": USER_AGENT}
   if os.getenv("NVD_API_KEY"):
       headers["apiKey"] = os.getenv("NVD_API_KEY")
   ```

### 5. Trigger the first build

Repo → **Actions** tab → "Build CTI Daily Brief" → **Run workflow**.
After ~1 minute, your site is live at `https://<user>.github.io/cti-daily-brief/`.

It will then auto-refresh every 6 hours.

---

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r scripts/requirements.txt
python scripts/aggregate.py
# Then open docs/index.html in a browser, or:
python -m http.server -d docs 8000
```

Open <http://localhost:8000>.

---

## Customizing

### Add or remove feeds
Edit `scripts/sources.yaml`. Each entry needs:
```yaml
- name: Vendor Threat Blog
  url: https://example.com/feed.xml
  type: rss          # rss | atom | nvd | cisa_kev
  trust: 4           # 1-5 (used in dedup tiebreaks)
  category: threat   # threat | vuln | advisory | breach | mixed
```

### Tune priority scoring
Edit the `score()` function in `scripts/aggregate.py`. Weights are clearly commented.

### Change the look
All CSS lives in `docs/style.css` with CSS variables at the top for the SOC-console
palette (phosphor green accent, cyan secondary). Swap the variables for a different
look without touching the rest of the stylesheet.

### Change refresh frequency
Edit the cron in `.github/workflows/build.yml`. Default is `0 */6 * * *`
(every 6h). Use `0 */1 * * *` for hourly, or `0 6 * * *` for once a day at 06:00 UTC.
GitHub free tier allows scheduled runs every 5 minutes minimum.

### Hide certain sections
The `category` filter and the `f-category` `<select>` are wired together. Remove
any `<option>` you don't want users to filter by.

---

## Adding more enrichment

The current build is keyword/regex-based, which is fast and free. If you later want
deeper correlation (named-entity extraction, ATT&CK technique tagging, IoC parsing,
LLM summaries), drop a new step into `scripts/aggregate.py` between `enrich()` and
`deduplicate()`. Suggested low-cost additions:

- **ATT&CK mapping** — pip install `mitreattack-python`, match tactic/technique keywords.
- **IoC extraction** — pip install `iocextract` to pull IPs, hashes, domains from summaries.
- **CVE metadata enrichment** — for every CVE in titles, hit NVD once to get CVSS even
  when the source didn't include it.

---

## Notes & caveats

- **Some sites 403 GitHub's IPs.** If a feed is consistently failing, swap to its
  Atom variant or a mirror (e.g. Feedly, Inoreader). Failures are logged but never
  crash the build.
- **Time zones.** Everything internal is UTC. The dashboard shows relative time
  ("3h ago") in the user's local browser time.
- **Sector tagging is keyword-based** and will produce some false positives. Use it
  as guidance, not ground truth.
- **No takedowns.** If you want to suppress a story, you'll need to add a denylist
  in `aggregate.py` after `deduplicate()`.

---

## License

MIT — do whatever you want, but the source feeds remain under their own licenses.
Attribution is in the page footer and respected via the "read on <source>" links.

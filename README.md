# cyber_news_monitor

A Python tool that polls well-known cybersecurity RSS feeds, deduplicates items you've already seen in a local SQLite database, and flags headlines that look like new CVEs, data breaches, ransomware attacks, or actively-exploited zero-days. Matches are printed to the console, logged to a local `.xlsx` spreadsheet, and optionally written as a Markdown digest or posted to Slack.

## Features

- Polls a curated list of major cybersecurity RSS feeds (Krebs on Security, BleepingComputer, The Hacker News, Dark Reading, and more)
- Tracks previously seen items in a local SQLite database so re-runs never repeat themselves
- Categorizes headlines as CVE, Zero-Day/Actively Exploited, Ransomware, or Breach using keyword and CVE-ID matching
- Maintains a running `.xlsx` log on your Desktop, with newest items always inserted at the top
- Optionally writes a Markdown digest per run and/or posts new items to a Slack channel via webhook
- Can run once or continuously in `--watch` mode on a configurable polling interval

## Requirements

- Python 3.8+
- [feedparser](https://pypi.org/project/feedparser/) >= 6.0
- [openpyxl](https://pypi.org/project/openpyxl/) >= 3.1

Install dependencies:

```bash
pip install -r cyberNewsRequirements.txt
```

## Usage

```bash
python cyberNewsMonitor.py                              # run once, print matches
python cyberNewsMonitor.py --all                         # show everything, not just matches
python cyberNewsMonitor.py --watch --interval 30          # poll every 30 minutes, forever
python cyberNewsMonitor.py --digest-dir ~/cyber-digests   # also save a Markdown digest per run
```

On first run, each feed only returns its most recent ~20-50 items, so you won't be flooded with years of history. The `--lookback-hours` flag (default 48) additionally hides anything older than that on top of deduplication.

### CLI options

| Flag | Description |
| --- | --- |
| `--feeds-file PATH` | Use a custom JSON list of feeds instead of the built-in defaults (see [Customizing sources](#customizing-sources)) |
| `--db PATH` | Path to the SQLite dedup database (default: `~/.cyber_monitor/seen.sqlite3`) |
| `--all` | Show every new item, not just CVE/breach/ransomware/zero-day matches |
| `--lookback-hours N` | Ignore items older than this many hours (default: 48) |
| `--digest-dir PATH` | Also write a Markdown digest file into this directory |
| `--xlsx-path PATH` | Override the `.xlsx` output location (default: `cyber_security_news.xlsx` on the Desktop) |
| `--no-xlsx` | Disable writing/updating the `.xlsx` log |
| `--slack-webhook URL` | Post new items to a Slack incoming webhook (or set `CYBER_MONITOR_SLACK_WEBHOOK`) |
| `--no-color` | Disable ANSI color in console output |
| `--watch` | Keep running, polling on a fixed interval |
| `--interval N` | Minutes between polls in `--watch` mode (default: 30) |

## Customization

The monitor is designed to be tuned to what you care about, either by changing which sites it reads from or which terms it flags as relevant.

### Customizing sources

By default, the script reads from the feed list in `DEFAULT_FEEDS` at the top of `cyberNewsMonitor.py`. To use your own set of sources without editing the script, pass `--feeds-file` pointing at a JSON file shaped like:

```json
[
  { "name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/" },
  { "name": "My Internal Feed", "url": "https://intranet.example.com/security/rss" }
]
```

Any valid RSS/Atom feed URL works, including internal or vendor-specific feeds.

### Customizing keywords

Categorization is intentionally simple and transparent so it's easy to tune. Near the top of `cyberNewsMonitor.py`, edit these lists to match what you want surfaced:

- `RANSOMWARE_TERMS` — ransomware groups and related terminology
- `BREACH_TERMS` — data breach / leak phrasing
- `ZERO_DAY_TERMS` — zero-day / active exploitation phrasing
- `CVE_PATTERN` — the regex used to detect CVE IDs (rarely needs changing)

Add, remove, or edit entries in these lists to broaden or narrow what counts as a match. Items that don't match any category are hidden by default unless `--all` is passed.

## Output

- **Console** — a formatted report of new matching items, grouped and color-highlighted when run in a terminal
- **`.xlsx` log** — new rows are inserted at the top of `cyber_security_news.xlsx` (Desktop by default), so the file always reads newest-first
- **Markdown digest** (optional) — a timestamped `cyber-digest-*.md` file per run when `--digest-dir` is set
- **Slack** (optional) — a summary message posted to a Slack incoming webhook when `--slack-webhook` (or `CYBER_MONITOR_SLACK_WEBHOOK`) is set

## License

Licensed under the [GNU General Public License v3.0](LICENSE).

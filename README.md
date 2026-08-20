# cyber_news_monitor

A tool that polls well-known cybersecurity RSS feeds, deduplicates items you've already seen in a local SQLite database, and flags headlines that look like new CVEs, data breaches, ransomware attacks, or actively-exploited zero-days. Matches are printed to the console, logged to a local `.xlsx` spreadsheet and/or a standalone HTML report, and optionally written as a Markdown digest or posted to Slack.

The primary implementation is a Python script (below); a Go port that builds to a single-binary `.exe` for distributing to Windows users without Python is also available -- see [Go port (single-binary distribution)](#go-port-single-binary-distribution).

## Getting started (Azure DevOps clone)

This project is also mirrored to Azure DevOps. If you have the Azure CLI installed, this is the quickest way to get a local copy open in VS Code:

1. **Sign in to Azure**, if you haven't already:
   ```bash
   az login
   ```
2. **Confirm the repo URL** (optional -- the project name has a space in it, so it's easy to get the URL-encoding wrong by hand):
   ```bash
   az repos list --organization https://dev.azure.com/GHS-ITDS --project "Information Security Operations" -o table
   ```
   The clone URL for this repo is:
   ```
   https://dev.azure.com/GHS-ITDS/Information%20Security%20Operations/_git/Cyber_News_Monitor
   ```
3. **Clone from VS Code** -- press `Ctrl+Shift+P`, run **"Git: Clone"**, paste the URL above, pick a local folder, then click **"Open"** when prompted.
4. **First-time sign-in** -- a browser window will pop up asking you to sign in with your Gundersen Microsoft account. This is Git Credential Manager doing an Azure AD login (separate from `az login`, but the same account); it only asks once and caches the credential afterward. If it asks for a username/password instead of opening a browser, reinstalling [Git for Windows](https://git-scm.com/download/win) will bring in a current Credential Manager.
5. **Install dependencies** in the VS Code terminal (opens already in the cloned folder):
   ```bash
   pip install -r cyberNewsRequirements.txt
   ```

From there, see [Usage](#usage) below -- in particular, [Running via VS Code's "Run" button](#running-via-vs-codes-run-button-no-terminal-no-flags) if you'd rather not touch the terminal at all.

## Features

- Polls a curated list of major cybersecurity RSS feeds (Krebs on Security, BleepingComputer, The Hacker News, Dark Reading, and more), including healthcare-breach news (HIPAA Journal) and OT/ICS-focused sources (Industrial Cyber) for connected-device exposure
- Tracks previously seen items in a local SQLite database so re-runs never repeat themselves
- Categorizes headlines as CVE, Zero-Day/Actively Exploited, Ransomware, or Breach using keyword and CVE-ID matching
- Maintains a running `.xlsx` log on your Desktop, with newest items always inserted at the top
- Optionally maintains the same data as a self-contained HTML report with clickable links, viewable in any browser
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
python cyberNewsMonitor.py --html-path              # save an HTML report to the Desktop & open it
python cyberNewsMonitor.py --html-path ~/cyber-news.html   # ...or save it to a custom path
```

### Running via VS Code's "Run" button (no terminal, no flags)

`cyberNewsMonitorHTML.py` is a thin wrapper around `cyberNewsMonitor.py` that defaults to the HTML report even with zero arguments -- useful for opening the script in VS Code and just hitting the play button, where there's no chance to type `--html-path`. It accepts every other flag `cyberNewsMonitor.py` does (`--watch`, `--all`, `--digest-dir`, etc.); it only changes what happens when `--html-path` is omitted.

```bash
python cyberNewsMonitorHTML.py   # run once, save the HTML report to the Desktop, and open it
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
| `--html-path [PATH]` | Also write/update an HTML report with clickable links, then open it in your default browser. Defaults to `cyber_security_news.html` on the Desktop; pass a path to override |
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
- **HTML report** (optional) — a standalone webpage (Desktop by default, or a custom path via `--html-path`), containing the same columns as the `.xlsx` log with clickable links, category badges, and light/dark theming. New items are prepended on each run, same as the spreadsheet; the underlying row data is embedded in the page itself, so no separate data file is needed. Opens automatically in your default browser after each save
- **Markdown digest** (optional) — a timestamped `cyber-digest-*.md` file per run when `--digest-dir` is set
- **Slack** (optional) — a summary message posted to a Slack incoming webhook when `--slack-webhook` (or `CYBER_MONITOR_SLACK_WEBHOOK`) is set
- **SQLite dedup database** — every item ever seen is recorded at `~/.cyber_monitor/seen.sqlite3` by default (override with `--db PATH`), so re-runs and `--watch` polls never repeat an item. This file isn't a "report" like the others above -- see [Resetting the dedup database](#resetting-the-dedup-database) if you want to clear it

## Resetting the dedup database

Because every seen item is remembered forever in the SQLite database above, testing the script repeatedly (new feeds, new keyword lists, a lower `--lookback-hours`) can look like "nothing new" even when it isn't -- everything's already marked seen. `resetSeenDb.py` deletes that database so the next run starts fresh, as if the monitor had never been run:

```bash
python resetSeenDb.py            # prompts for confirmation, deletes the default db
python resetSeenDb.py --db PATH  # delete a custom db path instead (matches --db on the monitor)
python resetSeenDb.py --yes      # skip the confirmation prompt
```

This only clears dedup history -- it does not touch the `.xlsx` log, HTML report, or Markdown digests already saved.

## Go port (single-binary distribution)

`go/` contains a Go port of this tool, built for handing a single `.exe` to Windows users who don't have Python or want to run anything from a terminal. It's not a wrapper around the Python script -- it's a from-scratch reimplementation of the same feed-fetch/dedup/categorize/report logic, kept in sync by hand.

Where the Go version differs from the Python one described above:

- **HTML report is the default output**, not opt-in -- running the `.exe` with zero flags writes/updates both the `.xlsx` log and the HTML report on the Desktop and opens the report in your browser, since a double-clicked binary has no `--html-path` to pass. Use `--no-html` or `--no-xlsx` to disable either, and `--no-open` to skip the browser launch.
- No `--feeds-file`-less customization beyond that JSON file -- there's no separate "edit the script" path for keyword lists like `RANSOMWARE_TERMS`; those are compiled into the binary (`go/internal/feeds/feeds.go`) and require a rebuild to change.
- No `resetSeenDb.py` equivalent yet -- delete the sqlite file at `--db`'s path (default `~/.cyber_monitor/seen.sqlite3`, same default as the Python version) to reset dedup history.

All other flags (`--all`, `--lookback-hours`, `--digest-dir`, `--slack-webhook`, `--watch`, `--interval`, `--db`) work the same as the table above.

### Building

Requires the [Go toolchain](https://go.dev/dl/) (1.21+). From the `go/` directory:

```powershell
.\build.ps1
```

This produces `go\dist\cybernewsmonitor.exe` -- a stripped, CGO-free, single-file binary (no Python, no DLLs, no installer needed on the machine that runs it). See `go/build.ps1` for the underlying `go build` flags if you want to build for a different target.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).

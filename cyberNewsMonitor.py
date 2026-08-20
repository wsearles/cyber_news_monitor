#!/usr/bin/env python3
"""
cyber_news_monitor.py

Pulls headlines from well-known cybersecurity RSS feeds, skips anything
you've already seen (tracked in a small local SQLite database), and
highlights items that look like new CVEs, data breaches, ransomware
attacks, or actively-exploited zero-days.

Usage:
    python3 cyber_news_monitor.py                  # run once, print results
    python3 cyber_news_monitor.py --all             # show everything, not just matches
    python3 cyber_news_monitor.py --watch --interval 30   # poll every 30 min, forever
    python3 cyber_news_monitor.py --digest-dir ~/cyber-digests   # also save a Markdown file

First run note: each feed only ever returns its most recent ~20-50 items,
so you won't get flooded with years of history. The --lookback-hours flag
(default 48) additionally hides anything older than that on top of dedup.
"""

import argparse
import calendar
import hashlib
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import feedparser
except ImportError:
    sys.exit("Missing dependency. Run: pip install -r cyberNewsRequirements.txt")

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter
except ImportError:
    sys.exit("Missing dependency. Run: pip install -r cyberNewsRequirements.txt")

XLSX_HEADERS = ["Title", "Categories", "CVEs", "Source Feed", "Published (UTC)", "Link", "First Seen (UTC)"]
XLSX_COLUMN_WIDTHS = [70, 30, 22, 24, 18, 70, 18]
XLSX_DEFAULT_FILENAME = "cyber_security_news.xlsx"


# --------------------------------------------------------------------------
# Default feed list (well-known, currently-active cybersecurity RSS feeds).
# You can override/extend this by passing --feeds-file pointing at a JSON
# file with the same [{"name": ..., "url": ...}, ...] structure.
# Note: CISA retired its public RSS feeds for alerts/KEV in May 2025 in
# favor of email/social notifications, so it's intentionally not listed.
# --------------------------------------------------------------------------
DEFAULT_FEEDS = [
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"name": "CSO Online", "url": "https://www.csoonline.com/feed/"},
    {"name": "Graham Cluley", "url": "https://grahamcluley.com/feed/"},
    {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "Wired Security", "url": "https://www.wired.com/feed/category/security/latest/rss"},
    {"name": "The Register Security", "url": "https://www.theregister.com/security/headlines.atom"},
    {"name": "404 Media", "url": "https://www.404media.co/rss/"},
    {"name": "Zero Day (Kim Zetter)", "url": "https://www.zetter-zeroday.com/feed"},
    {"name": "Ars Technica Security", "url": "https://arstechnica.com/security/feed/"},
    # Whole Microsoft Security Blog -- the site doesn't expose a separate
    # feed scoped to just the "Threat Intelligence" topic page, but threat
    # intel is most of what they publish here anyway.
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/"},
]

# --------------------------------------------------------------------------
# Categorization rules. Kept simple and transparent on purpose -- tweak
# these lists to taste.
# --------------------------------------------------------------------------
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

RANSOMWARE_TERMS = [
    "ransomware", "ransom note", "double extortion", "decryptor",
    "lockbit", "blackcat", "alphv", "conti", "revil", "cl0p", "clop",
    "akira", "ransomhub", "blacksuit", "play ransomware", "qilin", 'shinyhubters'
]

BREACH_TERMS = [
    "data breach", "breached", "leaked database", "exposed database",
    "unauthorized access", "compromised accounts", "stolen data",
    "exposed records", "data leak", "leaked data", "hacked and leaked",
    "customer data exposed",
]

ZERO_DAY_TERMS = [
    "zero-day", "0-day", "actively exploited", "exploited in the wild",
    "proof-of-concept exploit", "poc exploit", "under active exploitation",
]

CATEGORY_ORDER = ["CVE", "Zero-Day/Actively Exploited", "Ransomware", "Breach"]


@dataclass
class Item:
    feed: str
    title: str
    link: str
    summary: str
    published: Optional[datetime]
    categories: list = field(default_factory=list)
    cves: list = field(default_factory=list)

    def sort_key(self):
        return self.published or datetime.fromtimestamp(0, tz=timezone.utc)


def entry_id(entry) -> str:
    """Stable unique id for dedup, preferring the feed's own guid."""
    raw = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()


def parse_published(entry) -> Optional[datetime]:
    for field_name in ("published_parsed", "updated_parsed"):
        struct = entry.get(field_name)
        if struct:
            return datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
    return None


def categorize(title: str, summary: str):
    text = f"{title}\n{summary}".lower()
    categories = []
    cves = sorted(set(CVE_PATTERN.findall(f"{title}\n{summary}")), key=str.upper)
    if cves:
        categories.append("CVE")
    if any(term in text for term in ZERO_DAY_TERMS):
        categories.append("Zero-Day/Actively Exploited")
    if any(term in text for term in RANSOMWARE_TERMS):
        categories.append("Ransomware")
    if any(term in text for term in BREACH_TERMS):
        categories.append("Breach")
    return categories, cves


# --------------------------------------------------------------------------
# Local "seen" store -- a tiny SQLite db so re-runs don't repeat themselves.
# --------------------------------------------------------------------------
def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen (
            id TEXT PRIMARY KEY,
            feed TEXT,
            title TEXT,
            link TEXT,
            published TEXT,
            first_seen TEXT
        )
        """
    )
    conn.commit()
    return conn


def has_seen(conn: sqlite3.Connection, item_id: str) -> bool:
    cur = conn.execute("SELECT 1 FROM seen WHERE id = ?", (item_id,))
    return cur.fetchone() is not None


def mark_seen(conn: sqlite3.Connection, item_id: str, it: Item) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO seen (id, feed, title, link, published, first_seen) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            item_id,
            it.feed,
            it.title,
            it.link,
            it.published.isoformat() if it.published else "",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------
def fetch_feed(url: str, timeout: int = 15):
    """feedparser can be handed a URL directly, but doing our own request
    lets us set a timeout and a real User-Agent (some sites block the
    default urllib agent)."""
    if url.startswith("file://"):
        return feedparser.parse(url)
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; CyberNewsMonitor/1.0)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return feedparser.parse(raw)


def load_feeds(feeds_file: Optional[str]) -> list:
    if not feeds_file:
        return DEFAULT_FEEDS
    with open(feeds_file, "r", encoding="utf-8") as f:
        feeds = json.load(f)
    if not isinstance(feeds, list) or not all("url" in f for f in feeds):
        sys.exit("Feeds file must be a JSON list of {\"name\": ..., \"url\": ...} objects.")
    return feeds


# --------------------------------------------------------------------------
# Core run
# --------------------------------------------------------------------------
def run_once(args, conn: sqlite3.Connection, feeds: list) -> list:
    now = datetime.now(timezone.utc)
    lookback_seconds = args.lookback_hours * 3600
    new_items: list[Item] = []

    for feed in feeds:
        name, url = feed["name"], feed["url"]
        try:
            parsed = fetch_feed(url)
        except Exception as exc:  # network hiccups shouldn't kill the whole run
            print(f"  [warn] could not fetch {name} ({url}): {exc}", file=sys.stderr)
            continue

        if getattr(parsed, "bozo", 0) and not parsed.entries:
            print(f"  [warn] {name}: feed did not parse cleanly and had no entries", file=sys.stderr)
            continue

        for entry in parsed.entries:
            iid = entry_id(entry)
            if has_seen(conn, iid):
                continue

            title = entry.get("title", "(no title)")
            link = entry.get("link", "")
            summary = entry.get("summary", "") or entry.get("description", "")
            published = parse_published(entry)

            it = Item(feed=name, title=title, link=link, summary=summary, published=published)
            mark_seen(conn, iid, it)  # mark seen regardless, so we never re-process it

            if published and (now - published).total_seconds() > lookback_seconds:
                continue  # too old to bother surfacing, but it's now recorded as seen

            categories, cves = categorize(title, summary)
            it.categories, it.cves = categories, cves

            if categories or args.all:
                new_items.append(it)

    new_items.sort(key=lambda it: it.sort_key(), reverse=True)
    return new_items


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def fmt_item(it: Item, color: bool) -> str:
    ts = it.published.strftime("%Y-%m-%d %H:%M UTC") if it.published else "date unknown"
    tags = ", ".join(it.categories) if it.categories else "uncategorized"
    if color:
        tag_str = f"\033[1;33m[{tags}]\033[0m"
        title_str = f"\033[1m{it.title}\033[0m"
    else:
        tag_str = f"[{tags}]"
        title_str = it.title
    lines = [f"{tag_str} {title_str}", f"    {it.feed} · {ts}", f"    {it.link}"]
    if it.cves:
        lines.append(f"    CVEs: {', '.join(it.cves)}")
    return "\n".join(lines)


def print_report(items: list, color: bool) -> None:
    if not items:
        print("No new matching items this run.")
        return
    grouped: dict[str, list] = {}
    for it in items:
        key = ", ".join(it.categories) if it.categories else "Other"
        grouped.setdefault(key, []).append(it)

    print(f"\n{len(items)} new item(s) found:\n")
    for it in items:
        print(fmt_item(it, color))
        print()


def write_digest(items: list, digest_dir: str) -> Optional[str]:
    if not items:
        return None
    out_dir = Path(digest_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    out_path = out_dir / f"cyber-digest-{stamp}.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"# Cybersecurity digest — {stamp} UTC\n\n")
        for category in CATEGORY_ORDER + ["Other"]:
            bucket = [it for it in items if (category in it.categories) or
                      (category == "Other" and not it.categories)]
            if not bucket:
                continue
            f.write(f"## {category}\n\n")
            for it in bucket:
                ts = it.published.strftime("%Y-%m-%d %H:%M UTC") if it.published else "date unknown"
                f.write(f"- **{it.title}**  \n  {it.feed} · {ts}  \n  {it.link}\n")
                if it.cves:
                    f.write(f"  CVEs: {', '.join(it.cves)}\n")
                f.write("\n")
    return str(out_path)


def get_desktop_path() -> Path:
    """Best-effort, cross-platform Desktop folder detection. Falls back to
    the home directory if no Desktop folder can be found or created."""
    home = Path.home()
    system = platform.system()
    candidates = []

    if system == "Windows":
        # %USERPROFILE%\Desktop, even under OneDrive Known Folder Move, where
        # it's a junction into the OneDrive-managed folder -- so this stays
        # provider-agnostic rather than hardcoding a OneDrive-specific path.
        candidates.append(home / "Desktop")
    elif system == "Darwin":
        candidates.append(home / "Desktop")
    else:  # Linux and other Unix-likes
        try:
            result = subprocess.run(
                ["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                xdg_path = Path(result.stdout.strip())
                if xdg_path and xdg_path != home:
                    candidates.append(xdg_path)  # honors localized folder names, e.g. "Bureau"
        except (OSError, subprocess.SubprocessError):
            pass
        candidates.append(home / "Desktop")

    for c in candidates:
        if c.exists():
            return c

    target = candidates[0] if candidates else home
    try:
        target.mkdir(parents=True, exist_ok=True)
        return target
    except OSError:
        return home  # last resort: drop the file in the home directory instead


def prepend_to_xlsx(items: list, xlsx_path: Path) -> None:
    """Adds new items as rows at the top of the sheet (just below the header),
    pushing previously saved rows further down -- so the file always reads
    newest-first."""
    if not items:
        return

    if xlsx_path.exists():
        wb = load_workbook(xlsx_path)
        ws = wb.active
    else:
        wb = Workbook()
        ws = wb.active
        ws.title = "Cyber News"
        ws.append(XLSX_HEADERS)
        for cell in ws[1]:
            cell.font = Font(name="Arial", bold=True)
        ws.freeze_panes = "A2"
        for i, width in enumerate(XLSX_COLUMN_WIDTHS, start=1):
            ws.column_dimensions[get_column_letter(i)].width = width

    ws.insert_rows(2, amount=len(items))

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    for offset, it in enumerate(items):
        row = 2 + offset
        published_str = it.published.strftime("%Y-%m-%d %H:%M") if it.published else ""
        values = [
            it.title,
            ", ".join(it.categories) if it.categories else "Uncategorized",
            ", ".join(it.cves),
            it.feed,
            published_str,
            it.link,
            now_str,
        ]
        for col, value in enumerate(values, start=1):
            ws.cell(row=row, column=col, value=value).font = Font(name="Arial")
        link_cell = ws.cell(row=row, column=6)
        link_cell.hyperlink = it.link
        link_cell.font = Font(name="Arial", color="0563C1", underline="single")

    wb.save(xlsx_path)


def maybe_notify_slack(items: list, webhook_url: Optional[str]) -> None:
    if not webhook_url or not items:
        return
    lines = [f"*{len(items)} new cybersecurity item(s):*"]
    for it in items[:20]:  # keep it sane for chat
        tags = ", ".join(it.categories) if it.categories else "uncategorized"
        lines.append(f"• [{tags}] <{it.link}|{it.title}> — {it.feed}")
    payload = json.dumps({"text": "\n".join(lines)}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"  [warn] Slack notification failed: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--feeds-file", help="JSON file with a custom feed list (overrides defaults)")
    p.add_argument("--db", default=str(Path.home() / ".cyber_monitor" / "seen.sqlite3"),
                    help="Path to the SQLite dedup database")
    p.add_argument("--all", action="store_true",
                    help="Show every new item, not just CVE/breach/ransomware/zero-day matches")
    p.add_argument("--lookback-hours", type=int, default=48,
                    help="Ignore items older than this many hours (default: 48)")
    p.add_argument("--digest-dir", help="If set, also write a Markdown digest file into this directory")
    p.add_argument("--xlsx-path", help="Override the .xlsx output location (default: cyber_security_news.xlsx on the Desktop)")
    p.add_argument("--no-xlsx", action="store_true", help="Disable writing/updating the .xlsx log on the Desktop")
    p.add_argument("--slack-webhook", default=os.environ.get("CYBER_MONITOR_SLACK_WEBHOOK"),
                    help="Slack incoming-webhook URL to post new items to "
                         "(or set CYBER_MONITOR_SLACK_WEBHOOK env var)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output")
    p.add_argument("--watch", action="store_true", help="Keep running, polling on a fixed interval")
    p.add_argument("--interval", type=int, default=30, help="Minutes between polls in --watch mode (default: 30)")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    feeds = load_feeds(args.feeds_file)
    conn = open_db(Path(args.db))
    color = sys.stdout.isatty() and not args.no_color

    def cycle():
        print(f"=== Polling {len(feeds)} feed(s) at {datetime.now(timezone.utc).isoformat(timespec='seconds')} ===")
        items = run_once(args, conn, feeds)
        print_report(items, color)
        if args.digest_dir:
            path = write_digest(items, args.digest_dir)
            if path:
                print(f"Digest written to {path}")
        if not args.no_xlsx:
            xlsx_path = Path(args.xlsx_path).expanduser() if args.xlsx_path else get_desktop_path() / XLSX_DEFAULT_FILENAME
            try:
                prepend_to_xlsx(items, xlsx_path)
                if items:
                    print(f"Added {len(items)} row(s) to the top of {xlsx_path}")
            except PermissionError:
                print(f"  [warn] Could not write {xlsx_path} -- is it open in Excel? Close it and rerun.", file=sys.stderr)
            except Exception as exc:
                print(f"  [warn] Failed to update {xlsx_path}: {exc}", file=sys.stderr)
        maybe_notify_slack(items, args.slack_webhook)

    if not args.watch:
        cycle()
        return

    try:
        while True:
            cycle()
            print(f"Sleeping {args.interval} minute(s)...\n")
            time.sleep(args.interval * 60)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
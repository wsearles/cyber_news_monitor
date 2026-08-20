#!/usr/bin/env python3
"""
resetSeenDb.py

Deletes the local "seen items" SQLite database that cyberNewsMonitor.py uses
for deduplication, so the next run starts fresh -- useful for rolling back
or re-testing the script (new feeds, new keyword lists, a lower
--lookback-hours) without every item being skipped as already-seen.

Usage:
    python3 resetSeenDb.py            # prompts for confirmation, deletes the default db
    python3 resetSeenDb.py --db PATH  # delete a custom db path instead
    python3 resetSeenDb.py --yes      # skip the confirmation prompt
"""

import argparse
from pathlib import Path

DEFAULT_DB = Path.home() / ".cyber_monitor" / "seen.sqlite3"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=str(DEFAULT_DB),
                    help=f"Path to the SQLite dedup database (default: {DEFAULT_DB})")
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    db_path = Path(args.db).expanduser()

    if not db_path.exists():
        print(f"No database found at {db_path} -- nothing to do.")
        return

    if not args.yes:
        answer = input(
            f"Delete {db_path}? All dedup history will be lost and the next run "
            "will re-show every item currently in each feed. [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return

    db_path.unlink()
    print(f"Deleted {db_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
cyberNewsMonitorHTML.py

Same tool as cyberNewsMonitor.py, but defaults to writing/opening the HTML
report even when run with no arguments -- e.g. via VS Code's "Run Python
File" play button, where there's no chance to pass --html-path.

All of cyberNewsMonitor.py's flags still work here (--watch, --all,
--digest-dir, etc.); this just changes what happens when --html-path is
omitted.

Usage:
    python3 cyberNewsMonitorHTML.py                  # run once, open the HTML report
    python3 cyberNewsMonitorHTML.py --watch --interval 30   # poll every 30 min, forever
"""

import cyberNewsMonitor as cnm

if __name__ == "__main__":
    cnm.main(default_html=True)

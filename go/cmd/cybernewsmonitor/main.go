// Command cybernewsmonitor pulls headlines from cybersecurity RSS feeds,
// skips anything already seen (tracked in a local SQLite db), and
// highlights items that look like new CVEs, breaches, ransomware, or
// actively-exploited zero-days.
//
// Go port of cyberNewsMonitor.py / cyberNewsMonitorHTML.py. Since this
// ships as a single binary handed to non-technical recipients rather than
// run from a terminal, it defaults to the HTML-report behavior: write/open
// a self-contained report on the Desktop with zero flags required.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/wsearles/cyber_news_monitor/go/internal/browser"
	"github.com/wsearles/cyber_news_monitor/go/internal/feeds"
	"github.com/wsearles/cyber_news_monitor/go/internal/models"
	"github.com/wsearles/cyber_news_monitor/go/internal/notify"
	"github.com/wsearles/cyber_news_monitor/go/internal/report"
	"github.com/wsearles/cyber_news_monitor/go/internal/store"
)

const (
	xlsxDefaultFilename = "cyber_security_news.xlsx"
	htmlDefaultFilename = "cyber_security_news.html"
)

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cyber_monitor", "seen.sqlite3")
}

func main() {
	feedsFile := flag.String("feeds-file", "", "JSON file with a custom feed list (overrides defaults)")
	dbPath := flag.String("db", defaultDBPath(), "Path to the SQLite dedup database")
	all := flag.Bool("all", false, "Show every item, not just ones matching a category")
	lookbackHours := flag.Int("lookback-hours", 48, "Hide items older than this many hours (on top of dedup)")
	digestDir := flag.String("digest-dir", "", "If set, also write a Markdown digest file into this directory")
	xlsxPath := flag.String("xlsx-path", "", "Override the .xlsx output location (default: cyber_security_news.xlsx on the Desktop)")
	noXLSX := flag.Bool("no-xlsx", false, "Disable writing/updating the .xlsx log on the Desktop")
	htmlPath := flag.String("html-path", "", "Override the HTML report location (default: cyber_security_news.html on the Desktop)")
	noHTML := flag.Bool("no-html", false, "Disable writing/opening the HTML report")
	noOpen := flag.Bool("no-open", false, "Write the HTML report but don't launch it in a browser")
	slackWebhook := flag.String("slack-webhook", os.Getenv("CYBER_MONITOR_SLACK_WEBHOOK"),
		"Slack incoming-webhook URL to post new items to (or set CYBER_MONITOR_SLACK_WEBHOOK)")
	noColor := flag.Bool("no-color", false, "Disable ANSI color in console output")
	watch := flag.Bool("watch", false, "Keep running, polling on a fixed interval")
	interval := flag.Int("interval", 30, "Minutes between polls in --watch mode")
	flag.Parse()

	feedList, err := feeds.Load(*feedsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading feeds:", err)
		os.Exit(1)
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opening db:", err)
		os.Exit(1)
	}
	defer db.Close()

	cycle := func() {
		fmt.Printf("=== Polling %d feed(s) at %s ===\n", len(feedList), time.Now().UTC().Format(time.RFC3339))

		items, err := runOnce(db, feedList, *lookbackHours, *all)
		if err != nil {
			fmt.Fprintln(os.Stderr, "run failed:", err)
		}

		report.Console(os.Stdout, items, !*noColor)

		if *digestDir != "" {
			if path, err := report.WriteDigest(items, *digestDir); err != nil {
				fmt.Fprintln(os.Stderr, "writing digest:", err)
			} else if path != "" {
				fmt.Println("Digest written to", path)
			}
		}

		if !*noXLSX {
			path := *xlsxPath
			if path == "" {
				path = filepath.Join(desktopPath(), xlsxDefaultFilename)
			}
			if err := report.PrependXLSX(items, path); err != nil {
				warnWriteFailure(path, err, "Excel")
			} else if len(items) > 0 {
				fmt.Printf("Added %d row(s) to the top of %s\n", len(items), path)
			}
		}

		if !*noHTML {
			path := *htmlPath
			if path == "" {
				path = filepath.Join(desktopPath(), htmlDefaultFilename)
			}
			if err := report.PrependHTML(items, path); err != nil {
				warnWriteFailure(path, err, "your browser")
			} else if len(items) > 0 {
				fmt.Printf("Added %d row(s) to the top of %s\n", len(items), path)
				if !*noOpen {
					if abs, err := filepath.Abs(path); err == nil {
						if !browser.Open(toFileURI(abs)) {
							fmt.Fprintf(os.Stderr, "  [warn] Could not open a browser automatically -- open %s manually.\n", path)
						}
					}
				}
			}
		}

		if err := notify.Slack(items, *slackWebhook); err != nil {
			fmt.Fprintln(os.Stderr, "  [warn] Slack notification failed:", err)
		}
	}

	if !*watch {
		cycle()
		return
	}
	for {
		cycle()
		fmt.Printf("Sleeping %d minute(s)...\n\n", *interval)
		time.Sleep(time.Duration(*interval) * time.Minute)
	}
}

func warnWriteFailure(path string, err error, lockedByHint string) {
	if errors.Is(err, fs.ErrPermission) {
		fmt.Fprintf(os.Stderr, "  [warn] Could not write %s -- is it open in %s? Close it and rerun.\n", path, lockedByHint)
		return
	}
	fmt.Fprintf(os.Stderr, "  [warn] Failed to update %s: %v\n", path, err)
}

// toFileURI turns an absolute Windows path (e.g. C:\Users\...\report.html)
// into a file:// URI (file:///C:/Users/.../report.html).
func toFileURI(absPath string) string {
	return "file:///" + filepath.ToSlash(absPath)
}

func runOnce(db *store.Store, feedList []models.Feed, lookbackHours int, all bool) ([]models.Item, error) {
	now := time.Now().UTC()
	lookback := time.Duration(lookbackHours) * time.Hour
	var newItems []models.Item

	for _, feed := range feedList {
		parsed, err := feeds.Fetch(feed.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [warn] could not fetch %s (%s): %v\n", feed.Name, feed.URL, err)
			continue
		}

		for _, entry := range parsed.Items {
			id := feeds.EntryID(entry)
			seen, err := db.HasSeen(id)
			if err != nil {
				return nil, err
			}
			if seen {
				continue
			}

			it := models.Item{
				Feed:      feed.Name,
				Title:     entry.Title,
				Link:      entry.Link,
				Summary:   entry.Description,
				Published: feeds.Published(entry),
			}
			if it.Title == "" {
				it.Title = "(no title)"
			}

			if err := db.MarkSeen(id, it); err != nil {
				return nil, err
			}

			if it.Published != nil && now.Sub(*it.Published) > lookback {
				continue // too old to surface, but now recorded as seen
			}

			it.Categories, it.CVEs = feeds.Categorize(it.Title, it.Summary)
			if len(it.Categories) > 0 || all {
				newItems = append(newItems, it)
			}
		}
	}

	sort.Slice(newItems, func(i, j int) bool {
		return newItems[i].SortKey().After(newItems[j].SortKey())
	})
	return newItems, nil
}

// desktopPath returns %USERPROFILE%\Desktop, falling back to the home
// directory if it can't be found. Works whether or not OneDrive Known
// Folder Move has turned Desktop into a junction into an OneDrive-managed
// folder, since it just resolves whatever "Desktop" currently points to.
func desktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	candidate := filepath.Join(home, "Desktop")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return home
}

// Package report renders Item lists to various outputs (console now;
// Markdown digest, .xlsx log, and HTML report are scaffolded for a later pass).
package report

import (
	"fmt"
	"io"

	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

func fmtItem(it models.Item, color bool) string {
	ts := "date unknown"
	if it.Published != nil {
		ts = it.Published.Format("2006-01-02 15:04 UTC")
	}
	tags := "uncategorized"
	if len(it.Categories) > 0 {
		tags = joinComma(it.Categories)
	}

	tagStr, titleStr := fmt.Sprintf("[%s]", tags), it.Title
	if color {
		tagStr = fmt.Sprintf("\033[1;33m[%s]\033[0m", tags)
		titleStr = fmt.Sprintf("\033[1m%s\033[0m", it.Title)
	}

	out := fmt.Sprintf("%s %s\n    %s · %s\n    %s", tagStr, titleStr, it.Feed, ts, it.Link)
	if len(it.CVEs) > 0 {
		out += fmt.Sprintf("\n    CVEs: %s", joinComma(it.CVEs))
	}
	return out
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// Console writes a human-readable report of items to w.
func Console(w io.Writer, items []models.Item, color bool) {
	if len(items) == 0 {
		fmt.Fprintln(w, "No new matching items this run.")
		return
	}
	fmt.Fprintf(w, "\n%d new item(s) found:\n\n", len(items))
	for _, it := range items {
		fmt.Fprintln(w, fmtItem(it, color))
		fmt.Fprintln(w)
	}
}

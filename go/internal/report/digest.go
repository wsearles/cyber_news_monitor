package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wsearles/cyber_news_monitor/go/internal/feeds"
	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

// WriteDigest writes a Markdown digest grouped by category into digestDir
// and returns the path written, or "" if there were no items.
// Mirrors write_digest() in the Python script.
func WriteDigest(items []models.Item, digestDir string) (string, error) {
	if len(items) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(digestDir, 0o755); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("2006-01-02_1504")
	outPath := filepath.Join(digestDir, fmt.Sprintf("cyber-digest-%s.md", stamp))

	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Cybersecurity digest — %s UTC\n\n", stamp)
	for _, category := range append(append([]string{}, feeds.CategoryOrder...), "Other") {
		var bucket []models.Item
		for _, it := range items {
			inCategory := contains(it.Categories, category)
			isOther := category == "Other" && len(it.Categories) == 0
			if inCategory || isOther {
				bucket = append(bucket, it)
			}
		}
		if len(bucket) == 0 {
			continue
		}
		fmt.Fprintf(f, "## %s\n\n", category)
		for _, it := range bucket {
			ts := "date unknown"
			if it.Published != nil {
				ts = it.Published.Format("2006-01-02 15:04 UTC")
			}
			fmt.Fprintf(f, "- **%s**  \n  %s · %s  \n  %s\n", it.Title, it.Feed, ts, it.Link)
			if len(it.CVEs) > 0 {
				fmt.Fprintf(f, "  CVEs: %s\n", joinComma(it.CVEs))
			}
			fmt.Fprintln(f)
		}
	}
	return outPath, nil
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	htmlpkg "html"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

// htmlRow is the shape embedded as a JSON blob in the generated page, so a
// later run can load prior rows back out and prepend to them without a
// separate data file. Field order/names mirror item_to_row() in the
// Python script.
type htmlRow struct {
	Title      string `json:"title"`
	Categories string `json:"categories"`
	CVEs       string `json:"cves"`
	Feed       string `json:"feed"`
	Published  string `json:"published"`
	Link       string `json:"link"`
	FirstSeen  string `json:"first_seen"`
}

var htmlHeaders = []string{"Title", "Categories", "CVEs", "Source Feed", "Published (UTC)", "Link", "First Seen (UTC)"}

var categoryBadgeClasses = map[string]string{
	"CVE":                          "badge-cve",
	"Zero-Day/Actively Exploited":  "badge-zeroday",
	"Ransomware":                   "badge-ransomware",
	"Breach":                       "badge-breach",
}

var htmlDataRe = regexp.MustCompile(`(?s)<script type="application/json" id="row-data">(.*?)</script>`)

func itemToRow(it models.Item, nowStr string) htmlRow {
	categories := "Uncategorized"
	if len(it.Categories) > 0 {
		categories = joinComma(it.Categories)
	}
	published := ""
	if it.Published != nil {
		published = it.Published.Format("2006-01-02 15:04")
	}
	return htmlRow{
		Title:      it.Title,
		Categories: categories,
		CVEs:       joinComma(it.CVEs),
		Feed:       it.Feed,
		Published:  published,
		Link:       it.Link,
		FirstSeen:  nowStr,
	}
}

func renderCategoryBadges(categories string) string {
	if categories == "" {
		return ""
	}
	var b strings.Builder
	for _, cat := range strings.Split(categories, ", ") {
		class, ok := categoryBadgeClasses[cat]
		if !ok {
			class = "badge-other"
		}
		fmt.Fprintf(&b, `<span class="badge %s">%s</span>`, class, htmlpkg.EscapeString(cat))
	}
	return b.String()
}

// loadHTMLRows extracts the previously-saved rows embedded in an existing
// report page, if any.
func loadHTMLRows(path string) []htmlRow {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	match := htmlDataRe.FindSubmatch(raw)
	if match == nil {
		return nil
	}
	var rows []htmlRow
	if err := json.Unmarshal(match[1], &rows); err != nil {
		return nil
	}
	return rows
}

func renderHTMLReport(rows []htmlRow) (string, error) {
	generated := time.Now().UTC().Format("2006-01-02 15:04 UTC")

	var tableRows strings.Builder
	for _, row := range rows {
		linkCell := ""
		if row.Link != "" {
			linkCell = fmt.Sprintf(
				`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`,
				htmlpkg.EscapeString(row.Link), htmlpkg.EscapeString(row.Link),
			)
		}
		fmt.Fprintf(&tableRows,
			"<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			htmlpkg.EscapeString(row.Title),
			renderCategoryBadges(row.Categories),
			htmlpkg.EscapeString(row.CVEs),
			htmlpkg.EscapeString(row.Feed),
			htmlpkg.EscapeString(row.Published),
			linkCell,
			htmlpkg.EscapeString(row.FirstSeen),
		)
	}

	var headerCells strings.Builder
	for _, h := range htmlHeaders {
		fmt.Fprintf(&headerCells, "<th>%s</th>", htmlpkg.EscapeString(h))
	}

	// Escape "</" so a title/summary containing "</script>" can't break out
	// of the data blob early -- "\/" is a valid JSON escape for "/", so this
	// is transparent to json.Unmarshal on the next run.
	dataBlobBytes, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	dataBlob := strings.ReplaceAll(string(dataBlobBytes), "</", `<\/`)

	var page bytes.Buffer
	fmt.Fprintf(&page, htmlTemplate, len(rows), generated, headerCells.String(), tableRows.String(), dataBlob)
	return page.String(), nil
}

// PrependHTML adds new items as rows at the top of the page, ahead of
// previously saved rows -- so the file always reads newest-first, mirroring
// the .xlsx log. Mirrors prepend_to_html() in the Python script.
func PrependHTML(items []models.Item, path string) error {
	if len(items) == 0 {
		return nil
	}

	existingRows := loadHTMLRows(path)
	nowStr := time.Now().UTC().Format("2006-01-02 15:04")

	newRows := make([]htmlRow, 0, len(items))
	for _, it := range items {
		newRows = append(newRows, itemToRow(it, nowStr))
	}
	combined := append(newRows, existingRows...)

	page, err := renderHTMLReport(combined)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(page), 0o644)
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cyber Security News</title>
<style>
  :root {
    --bg: #f7f8fa; --surface: #ffffff; --text: #1a1d21; --muted: #5b6270;
    --border: #e2e5ea; --link: #0b57d0; --header-bg: #14161a; --header-text: #ffffff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a; --surface: #1c1f24; --text: #e8eaed; --muted: #9aa1ac;
      --border: #2b2f36; --link: #8ab4f8; --header-bg: #0e0f12; --header-text: #e8eaed;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem; background: var(--bg); color: var(--text);
    font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  }
  h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
  .meta { color: var(--muted); margin: 0 0 1.25rem; font-size: 0.9rem; }
  .table-wrap {
    overflow-x: auto; border: 1px solid var(--border); border-radius: 8px;
    background: var(--surface);
  }
  table { border-collapse: collapse; width: 100%%; min-width: 900px; }
  th, td {
    text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border);
    vertical-align: top; font-size: 0.9rem;
  }
  thead th {
    background: var(--header-bg); color: var(--header-text); position: sticky; top: 0;
  }
  tbody tr:hover { background: color-mix(in srgb, var(--text) 4%%, transparent); }
  a { color: var(--link); text-decoration: none; word-break: break-all; }
  a:hover { text-decoration: underline; }
  .badge {
    display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 600; margin: 0 0.25rem 0.25rem 0; white-space: nowrap;
  }
  .badge-cve { background: #e3edff; color: #0b3d91; }
  .badge-zeroday { background: #fde3e3; color: #8a1c1c; }
  .badge-ransomware { background: #f1e3ff; color: #5a1c8a; }
  .badge-breach { background: #ffe9d1; color: #8a4a0a; }
  .badge-other { background: var(--border); color: var(--muted); }
  @media (prefers-color-scheme: dark) {
    .badge-cve { background: #1c2b4a; color: #a9c3ff; }
    .badge-zeroday { background: #3a1c1c; color: #ffb3b3; }
    .badge-ransomware { background: #2f1c3a; color: #dcb3ff; }
    .badge-breach { background: #3a2a10; color: #ffcf94; }
  }
</style>
</head>
<body>
  <h1>Cyber Security News</h1>
  <p class="meta">%d item(s) &middot; last updated %s</p>
  <div class="table-wrap">
    <table>
      <thead><tr>%s</tr></thead>
      <tbody>
        %s
      </tbody>
    </table>
  </div>
  <script type="application/json" id="row-data">%s</script>
</body>
</html>
`

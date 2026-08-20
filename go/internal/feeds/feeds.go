// Package feeds handles fetching RSS/Atom feeds and categorizing entries.
package feeds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

// Default, currently-active cybersecurity RSS feeds. Mirrors DEFAULT_FEEDS
// in the original Python script. CISA retired its public RSS feeds for
// alerts/KEV in May 2025 in favor of email/social notifications, so it's
// intentionally not listed.
var Default = []models.Feed{
	{Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/"},
	{Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/"},
	{Name: "The Hacker News", URL: "https://feeds.feedburner.com/TheHackersNews"},
	{Name: "Dark Reading", URL: "https://www.darkreading.com/rss.xml"},
	{Name: "SecurityWeek", URL: "https://www.securityweek.com/feed/"},
	{Name: "CSO Online", URL: "https://www.csoonline.com/feed/"},
	{Name: "Graham Cluley", URL: "https://grahamcluley.com/feed/"},
	{Name: "SANS Internet Storm Center", URL: "https://isc.sans.edu/rssfeed_full.xml"},
	{Name: "Wired Security", URL: "https://www.wired.com/feed/category/security/latest/rss"},
	{Name: "The Register Security", URL: "https://www.theregister.com/security/headlines.atom"},
	{Name: "404 Media", URL: "https://www.404media.co/rss/"},
	{Name: "Zero Day (Kim Zetter)", URL: "https://www.zetter-zeroday.com/feed"},
	{Name: "Ars Technica Security", URL: "https://arstechnica.com/security/feed/"},
	{Name: "Microsoft Security Blog", URL: "https://www.microsoft.com/en-us/security/blog/feed/"},
	{Name: "Securelist (Kaspersky)", URL: "https://securelist.com/feed/"},
	{Name: "FortiGuard Labs Threat Research", URL: "https://feeds.fortinet.com/fortinet/blog/threat-research"},
	{Name: "HIPAA Journal", URL: "https://www.hipaajournal.com/feed/"},
	{Name: "The Guardian Security", URL: "https://www.theguardian.com/technology/data-computer-security/rss"},
	{Name: "Industrial Cyber", URL: "https://industrialcyber.co/feed"},
	{Name: "Seclists Full Disclosure", URL: "https://seclists.org/rss/fulldisclosure.rss"},
}

// Load returns the default feed list, or the contents of feedsFile if given.
func Load(feedsFile string) ([]models.Feed, error) {
	if feedsFile == "" {
		return Default, nil
	}
	raw, err := os.ReadFile(feedsFile)
	if err != nil {
		return nil, err
	}
	var out []models.Feed
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Fetch retrieves and parses a single feed, setting a real User-Agent since
// some sites block Go's default one.
func Fetch(url string) (*gofeed.Feed, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CyberNewsMonitor/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return gofeed.NewParser().Parse(resp.Body)
}

// EntryID returns a stable dedup id for a feed entry, preferring its GUID.
func EntryID(item *gofeed.Item) string {
	raw := item.GUID
	if raw == "" {
		raw = item.Link
	}
	if raw == "" {
		raw = item.Title
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Published returns the entry's timestamp in UTC, if the feed provided one.
func Published(item *gofeed.Item) *time.Time {
	switch {
	case item.PublishedParsed != nil:
		t := item.PublishedParsed.UTC()
		return &t
	case item.UpdatedParsed != nil:
		t := item.UpdatedParsed.UTC()
		return &t
	default:
		return nil
	}
}

// --------------------------------------------------------------------------
// Categorization rules. Kept simple and transparent on purpose -- tweak
// these lists to taste. Mirrors categorize() in the original Python script.
// --------------------------------------------------------------------------

var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

var ransomwareTerms = []string{
	"ransomware", "ransom note", "double extortion", "decryptor",
	"lockbit", "blackcat", "alphv", "conti", "revil", "cl0p", "clop",
	"akira", "ransomhub", "blacksuit", "play ransomware", "qilin", "shinyhubters",
}

var breachTerms = []string{
	"data breach", "breached", "leaked database", "exposed database",
	"unauthorized access", "compromised accounts", "stolen data",
	"exposed records", "data leak", "leaked data", "hacked and leaked",
	"customer data exposed",
}

var zeroDayTerms = []string{
	"zero-day", "0-day", "actively exploited", "exploited in the wild",
	"proof-of-concept exploit", "poc exploit", "under active exploitation",
}

// CategoryOrder is the display/grouping order used by report writers.
var CategoryOrder = []string{"CVE", "Zero-Day/Actively Exploited", "Ransomware", "Breach"}

func containsAny(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

// Categorize inspects a title+summary and returns the matched category
// labels plus any CVE ids found, sorted and de-duplicated.
func Categorize(title, summary string) (categories []string, cves []string) {
	text := strings.ToLower(title + "\n" + summary)

	seen := map[string]bool{}
	for _, m := range cvePattern.FindAllString(title+"\n"+summary, -1) {
		u := strings.ToUpper(m)
		if !seen[u] {
			seen[u] = true
			cves = append(cves, u)
		}
	}
	sort.Strings(cves)

	if len(cves) > 0 {
		categories = append(categories, "CVE")
	}
	if containsAny(text, zeroDayTerms) {
		categories = append(categories, "Zero-Day/Actively Exploited")
	}
	if containsAny(text, ransomwareTerms) {
		categories = append(categories, "Ransomware")
	}
	if containsAny(text, breachTerms) {
		categories = append(categories, "Breach")
	}
	return categories, cves
}

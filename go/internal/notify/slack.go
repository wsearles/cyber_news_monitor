// Package notify posts new-item summaries to external destinations.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Slack posts a summary of items to a Slack incoming webhook. A no-op if
// webhookURL or items is empty. Mirrors maybe_notify_slack() in the Python
// script.
func Slack(items []models.Item, webhookURL string) error {
	if webhookURL == "" || len(items) == 0 {
		return nil
	}

	lines := []string{fmt.Sprintf("*%d new cybersecurity item(s):*", len(items))}
	limit := len(items)
	if limit > 20 { // keep it sane for chat
		limit = 20
	}
	for _, it := range items[:limit] {
		tags := "uncategorized"
		if len(it.Categories) > 0 {
			tags = strings.Join(it.Categories, ", ")
		}
		lines = append(lines, fmt.Sprintf("• [%s] <%s|%s> — %s", tags, it.Link, it.Title, it.Feed))
	}

	payload, err := json.Marshal(map[string]string{"text": strings.Join(lines, "\n")})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Package models holds the shared data shapes used across the app.
package models

import "time"

// Item is a single feed entry after fetching and categorization.
type Item struct {
	Feed      string
	Title     string
	Link      string
	Summary   string
	Published *time.Time // nil if the feed entry had no parseable date
	Categories []string
	CVEs       []string
}

// SortKey returns the timestamp used to order items newest-first,
// falling back to the Unix epoch when Published is unknown.
func (it Item) SortKey() time.Time {
	if it.Published != nil {
		return *it.Published
	}
	return time.Unix(0, 0).UTC()
}

// Feed is one configured RSS/Atom source.
type Feed struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

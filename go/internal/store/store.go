// Package store wraps the local SQLite "seen" database so re-runs don't
// repeat themselves. Mirrors open_db/has_seen/mark_seen in the Python script.
package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

type Store struct {
	db *sql.DB
}

// Open creates the db file and "seen" table if needed, and returns a Store.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS seen (
			id TEXT PRIMARY KEY,
			feed TEXT,
			title TEXT,
			link TEXT,
			published TEXT,
			first_seen TEXT
		)
	`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// HasSeen reports whether an entry id has already been recorded.
func (s *Store) HasSeen(id string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM seen WHERE id = ?`, id).Scan(&one)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	default:
		return true, nil
	}
}

// MarkSeen records an entry id so it's never processed again.
func (s *Store) MarkSeen(id string, it models.Item) error {
	published := ""
	if it.Published != nil {
		published = it.Published.Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO seen (id, feed, title, link, published, first_seen)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, it.Feed, it.Title, it.Link, published, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

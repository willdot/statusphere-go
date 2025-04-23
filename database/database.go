package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	_ "github.com/glebarez/go-sqlite"
)

type DB struct {
	db *sql.DB
}

func New(dbPath string) (*DB, error) {
	if dbPath != ":memory:" {
		err := createDbFile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("create db file: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	err = createOauthRequestsTable(db)
	if err != nil {
		return nil, fmt.Errorf("creating oauth requests table: %w", err)
	}

	err = createOauthSessionsTable(db)
	if err != nil {
		return nil, fmt.Errorf("creating oauth sessions table: %w", err)
	}

	err = createStatusTable(db)
	if err != nil {
		return nil, fmt.Errorf("creating status table: %w", err)
	}

	err = createProfileTable(db)
	if err != nil {
		return nil, fmt.Errorf("creating profile table: %w", err)
	}

	return &DB{db: db}, nil
}

func (d *DB) Close() {
	err := d.db.Close()
	if err != nil {
		slog.Error("failed to close db", "error", err)
	}
}

func createDbFile(dbFilename string) error {
	if _, err := os.Stat(dbFilename); !errors.Is(err, os.ErrNotExist) {
		return nil
	}

	f, err := os.Create(dbFilename)
	if err != nil {
		return fmt.Errorf("create db file : %w", err)
	}
	f.Close()
	return nil
}

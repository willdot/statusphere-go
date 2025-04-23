package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/willdot/statusphere-go"
)

func createProfileTable(db *sql.DB) error {
	createProfileTableSQL := `CREATE TABLE IF NOT EXISTS profile (
		"did" TEXT NOT NULL PRIMARY KEY,
		"handle" TEXT,
		"displayName" TEXT
	  );`

	slog.Info("Create profile table...")
	statement, err := db.Prepare(createProfileTableSQL)
	if err != nil {
		return fmt.Errorf("prepare DB statement to create profile table: %w", err)
	}
	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("exec sql statement to create profile table: %w", err)
	}
	slog.Info("profile table created")

	return nil
}

func (d *DB) CreateProfile(profile statusphere.UserProfile) error {
	sql := `INSERT INTO profile (did, handle, displayName) VALUES (?, ?, ?) ON CONFLICT(did) DO NOTHING;` // TODO: What about when users change their handle or display name???
	_, err := d.db.Exec(sql, profile.Did, profile.Handle, profile.DisplayName)
	if err != nil {
		return fmt.Errorf("exec insert profile: %w", err)
	}

	return nil
}

func (d *DB) GetHandleAndDisplayNameForDid(did string) (statusphere.UserProfile, error) {
	sql := "SELECT did, handle, displayName FROM profile WHERE did = ?;"
	rows, err := d.db.Query(sql, did)
	if err != nil {
		return statusphere.UserProfile{}, fmt.Errorf("run query to get profile': %w", err)
	}
	defer rows.Close()

	var profile statusphere.UserProfile
	for rows.Next() {
		if err := rows.Scan(&profile.Did, &profile.Handle, &profile.DisplayName); err != nil {
			return statusphere.UserProfile{}, fmt.Errorf("scan row: %w", err)
		}

		return profile, nil
	}
	return profile, statusphere.ErrorNotFound
}

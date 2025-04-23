package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	statusphere "github.com/willdot/statusphere-go"
)

func createStatusTable(db *sql.DB) error {
	createStatusTableSQL := `CREATE TABLE IF NOT EXISTS status (
		"uri" TEXT NOT NULL PRIMARY KEY,
		"did" TEXT,
		"status" TEXT,
		"createdAt" integer,
		"indexedAt" integer
	  );`

	slog.Info("Create status table...")
	statement, err := db.Prepare(createStatusTableSQL)
	if err != nil {
		return fmt.Errorf("prepare DB statement to create status table: %w", err)
	}
	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("exec sql statement to create status table: %w", err)
	}
	slog.Info("status table created")

	return nil
}

func (d *DB) CreateStatus(status statusphere.Status) error {
	sql := `INSERT INTO status (uri, did, status, createdAt, indexedAt) VALUES (?, ?, ?, ?, ?) ON CONFLICT(uri) DO NOTHING;`
	_, err := d.db.Exec(sql, status.URI, status.Did, status.Status, status.CreatedAt, status.IndexedAt)
	if err != nil {
		return fmt.Errorf("exec insert status: %w", err)
	}

	return nil
}

func (d *DB) GetStatuses(limit int) ([]statusphere.Status, error) {
	sql := "SELECT uri, did, status, createdAt FROM status ORDER BY createdAt desc LIMIT ?;"
	rows, err := d.db.Query(sql, limit)
	if err != nil {
		return nil, fmt.Errorf("run query to get status': %w", err)
	}
	defer rows.Close()

	var results []statusphere.Status
	for rows.Next() {
		var status statusphere.Status
		if err := rows.Scan(&status.URI, &status.Did, &status.Status, &status.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		results = append(results, status)
	}
	return results, nil
}

package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/willdot/statusphere-go/oauth"
)

func createOauthSessionsTable(db *sql.DB) error {
	createOauthSessionsTableSQL := `CREATE TABLE IF NOT EXISTS oauthsessions (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"did" TEXT,
		"pdsUrl" TEXT,
		"authserverIss" TEXT,
		"accessToken" TEXT,
		"refreshToken" TEXT,
		"dpopPdsNonce" TEXT,
		"dpopAuthserverNonce" TEXT,
		"dpopPrivateJwk" TEXT,
		"expiration" integer,
		UNIQUE(did)
	  );`

	slog.Info("Create oauthsessions table...")
	statement, err := db.Prepare(createOauthSessionsTableSQL)
	if err != nil {
		return fmt.Errorf("prepare DB statement to create oauthsessions table: %w", err)
	}
	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("exec sql statement to create oauthsessions table: %w", err)
	}
	slog.Info("oauthsessions table created")

	return nil
}

func (d *DB) CreateOauthSession(session oauth.Session) error {
	sql := `INSERT INTO oauthsessions (did, pdsUrl, authserverIss, accessToken, refreshToken, dpopPdsNonce, dpopAuthserverNonce, dpopPrivateJwk, expiration) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(did) DO NOTHING;` // TODO: update on conflict
	_, err := d.db.Exec(sql, session.Did, session.PdsUrl, session.AuthserverIss, session.AccessToken, session.RefreshToken, session.DpopPdsNonce, session.DpopAuthserverNonce, session.DpopPrivateJwk, session.Expiration)
	if err != nil {
		return fmt.Errorf("exec insert oauth session: %w", err)
	}

	return nil
}

func (d *DB) GetOauthSession(did string) (oauth.Session, error) {
	var session oauth.Session
	sql := "SELECT * FROM oauthsessions WHERE did = ?;"
	rows, err := d.db.Query(sql, did)
	if err != nil {
		return session, fmt.Errorf("run query to get oauth session: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&session.ID, &session.Did, &session.PdsUrl, &session.AuthserverIss, &session.AccessToken, &session.RefreshToken, &session.DpopPdsNonce, &session.DpopAuthserverNonce, &session.DpopPrivateJwk, &session.Expiration); err != nil {
			return session, fmt.Errorf("scan row: %w", err)
		}

		return session, nil
	}
	return session, fmt.Errorf("not found")
}

func (d *DB) UpdateOauthSession(accessToken, refreshToken, dpopAuthServerNonce, did string, expiration int64) error {
	sql := `UPDATE oauthsessions SET accessToken = ?, refreshToken = ?, dpopAuthserverNonce = ?, expiration = ? where did = ?`
	_, err := d.db.Exec(sql, accessToken, refreshToken, dpopAuthServerNonce, expiration, did)
	if err != nil {
		return fmt.Errorf("exec update oauth session: %w", err)
	}

	return nil
}

func (d *DB) UpdateOauthSessionDpopPdsNonce(dpopPdsServerNonce, did string) error {
	sql := `UPDATE oauthsessions SET dpopPdsNonce = ? where did = ?`
	_, err := d.db.Exec(sql, dpopPdsServerNonce, did)
	if err != nil {
		return fmt.Errorf("exec update oauth session dpop pds nonce: %w", err)
	}

	return nil
}

func (d *DB) DeleteOauthSession(did string) error {
	sql := "DELETE FROM oauthsessions WHERE did = ?;"
	_, err := d.db.Exec(sql, did)
	if err != nil {
		return fmt.Errorf("exec delete oauth session: %w", err)
	}
	return nil
}

package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/willdot/statusphere-go/oauth"
)

func createOauthRequestsTable(db *sql.DB) error {
	createOauthRequestsTableSQL := `CREATE TABLE IF NOT EXISTS oauthrequests (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"authserverIss" TEXT,
		"state" TEXT,
		"did" TEXT,
		"pdsUrl" TEXT,
		"pkceVerifier" TEXT,
		"dpopAuthserverNonce" TEXT,
		"dpopPrivateJwk" TEXT,
		UNIQUE(did,state)
	  );`

	slog.Info("Create oauthrequests table...")
	statement, err := db.Prepare(createOauthRequestsTableSQL)
	if err != nil {
		return fmt.Errorf("prepare DB statement to create oauthrequests table: %w", err)
	}
	_, err = statement.Exec()
	if err != nil {
		return fmt.Errorf("exec sql statement to create oauthrequests table: %w", err)
	}
	slog.Info("oauthrequests table created")

	return nil
}

func (d *DB) CreateOauthRequest(request oauth.Request) error {
	sql := `INSERT INTO oauthrequests (authserverIss, state, did, pdsUrl, pkceVerifier, dpopAuthServerNonce, dpopPrivateJwk) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(did,state) DO NOTHING;`
	_, err := d.db.Exec(sql, request.AuthserverIss, request.State, request.Did, request.PdsURL, request.PkceVerifier, request.DpopAuthserverNonce, request.DpopPrivateJwk)
	if err != nil {
		return fmt.Errorf("exec insert oauth request: %w", err)
	}

	return nil
}

func (d *DB) GetOauthRequest(state string) (oauth.Request, error) {
	var oauthRequest oauth.Request
	sql := "SELECT authserverIss, state, did, pdsUrl, pkceVerifier, dpopAuthServerNonce, dpopPrivateJwk FROM oauthrequests WHERE state = ?;"
	rows, err := d.db.Query(sql, state)
	if err != nil {
		return oauthRequest, fmt.Errorf("run query to get oauth request: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&oauthRequest.AuthserverIss, &oauthRequest.State, &oauthRequest.Did, &oauthRequest.PdsURL, &oauthRequest.PkceVerifier, &oauthRequest.DpopAuthserverNonce, &oauthRequest.DpopPrivateJwk); err != nil {
			return oauthRequest, fmt.Errorf("scan row: %w", err)
		}

		return oauthRequest, nil
	}
	return oauthRequest, fmt.Errorf("not found")
}

func (d *DB) DeleteOauthRequest(state string) error {
	sql := "DELETE FROM oauthrequests WHERE state = ?;"
	_, err := d.db.Exec(sql, state)
	if err != nil {
		return fmt.Errorf("exec delete oauth request: %w", err)
	}
	return nil
}

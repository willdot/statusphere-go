package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func createOauthRequestsTable(db *sql.DB) error {
	createOauthRequestsTableSQL := `CREATE TABLE IF NOT EXISTS oauthrequests (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"state" TEXT,
		"authServerURL" TEXT,
		"accountDID" TEXT,
		"scope" TEXT,
		"requestURI" TEXT,
		"authServerTokenEndpoint" TEXT,
		"pkceVerifier" TEXT,
		"dpopAuthserverNonce" TEXT,
		"dpopPrivateKeyMultibase" TEXT,
		UNIQUE(state)
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

func (d *DB) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	did := ""
	if info.AccountDID != nil {
		did = info.AccountDID.String()
	}

	sql := `INSERT INTO oauthrequests (state, authServerURL, accountDID, scope, requestURI, authServerTokenEndpoint, pkceVerifier, dpopAuthserverNonce, dpopPrivateKeyMultibase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(state) DO NOTHING;`
	_, err := d.db.Exec(sql, info.State, info.AuthServerURL, did, info.Scope, info.RequestURI, info.AuthServerTokenEndpoint, info.PKCEVerifier, info.DPoPAuthServerNonce, info.DPoPPrivateKeyMultibase)
	if err != nil {
		slog.Error("saving auth request info", "error", err)
		return fmt.Errorf("exec insert oauth request: %w", err)
	}

	return nil
}

func (d *DB) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	var oauthRequest oauth.AuthRequestData
	sql := "SELECT state, authServerURL, accountDID, scope, requestURI, authServerTokenEndpoint, pkceVerifier, dpopAuthserverNonce, dpopPrivateKeyMultibase FROM oauthrequests where state = ?;"
	rows, err := d.db.Query(sql, state)
	if err != nil {
		return nil, fmt.Errorf("run query to get oauth request: %w", err)
	}
	defer rows.Close()

	var did string

	for rows.Next() {
		if err := rows.Scan(&oauthRequest.State, &oauthRequest.AuthServerURL, &did, &oauthRequest.Scope, &oauthRequest.RequestURI, &oauthRequest.AuthServerTokenEndpoint, &oauthRequest.PKCEVerifier, &oauthRequest.DPoPAuthServerNonce, &oauthRequest.DPoPPrivateKeyMultibase); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if did != "" {
			parsedDID, err := syntax.ParseDID(did)
			if err != nil {
				return nil, fmt.Errorf("invalid DID stored in record: %w", err)
			}
			oauthRequest.AccountDID = &parsedDID
		}

		return &oauthRequest, nil
	}
	return nil, fmt.Errorf("not found")
}

func (d *DB) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	sql := "DELETE FROM oauthrequests WHERE state = ?;"
	_, err := d.db.Exec(sql, state)
	if err != nil {
		return fmt.Errorf("exec delete oauth request: %w", err)
	}
	return nil
}

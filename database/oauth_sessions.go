package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func createOauthSessionsTable(db *sql.DB) error {
	createOauthSessionsTableSQL := `CREATE TABLE IF NOT EXISTS oauthsessions (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"accountDID" TEXT,
		"sessionID" TEXT,
		"hostURL" TEXT,
		"authServerURL" TEXT,
		"authServerTokenEndpoint" TEXT,
		"scopes" TEXT,
		"accessToken" TEXT,
		"refreshToken" TEXT,
		"dpopAuthServerNonce" TEXT,
		"dpopHostNonce" TEXT,
		"dpopPrivateKeyMultibase" TEXT,
		UNIQUE(accountDID)
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

func (d *DB) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	scopes, err := json.Marshal(sess.Scopes)
	if err != nil {
		return fmt.Errorf("marshalling scopes: %w", err)
	}

	slog.Info("session to save", "did", sess.AccountDID.String(), "session id", sess.SessionID)

	sql := `INSERT INTO oauthsessions (accountDID, sessionID, hostURL,  authServerURL, authServerTokenEndpoint, scopes, accessToken, refreshToken, dpopAuthServerNonce, dpopHostNonce, dpopPrivateKeyMultibase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(accountDID) DO NOTHING;` // TODO: update on conflict
	_, err = d.db.Exec(sql, sess.AccountDID.String(), sess.SessionID, sess.HostURL, sess.AuthServerURL, sess.AuthServerTokenEndpoint, string(scopes), sess.AccessToken, sess.RefreshToken, sess.DPoPAuthServerNonce, sess.DPoPHostNonce, sess.DPoPPrivateKeyMultibase)
	if err != nil {
		slog.Error("saving session", "error", err)
		return fmt.Errorf("exec insert oauth session: %w", err)
	}

	return nil
}

func (d *DB) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	var session oauth.ClientSessionData
	sql := "SELECT hostURL, authServerURL, authServerTokenEndpoint, scopes, accessToken, refreshToken, dpopAuthServerNonce, dpopHostNonce, dpopPrivateKeyMultibase FROM oauthsessions where accountDID = ? AND sessionID = ?;"
	rows, err := d.db.Query(sql, did.String(), sessionID)
	if err != nil {
		return nil, fmt.Errorf("run query to get oauth session: %w", err)
	}
	defer rows.Close()

	scopes := ""
	for rows.Next() {
		if err := rows.Scan(&session.HostURL, &session.AuthServerURL, &session.AuthServerTokenEndpoint, &scopes, &session.AccessToken, &session.RefreshToken, &session.DPoPAuthServerNonce, &session.DPoPHostNonce, &session.DPoPPrivateKeyMultibase); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		session.AccountDID = did

		var parsedScopes []string
		err = json.Unmarshal([]byte(scopes), &parsedScopes)
		if err != nil {
			return nil, fmt.Errorf("parsing scopes: %w", err)
		}

		session.Scopes = parsedScopes

		return &session, nil
	}
	return nil, fmt.Errorf("not found")
}

func (d *DB) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	sql := "DELETE FROM oauthsessions WHERE accountDID = ?;"
	_, err := d.db.Exec(sql, did.String())
	if err != nil {
		return fmt.Errorf("exec delete oauth session: %w", err)
	}
	return nil
}

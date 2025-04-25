package statusphere

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/willdot/statusphere-go/oauth"
)

type Status struct {
	URI       string
	Did       string
	Status    string
	CreatedAt int64
	IndexedAt int64
}

type XRPCError struct {
	ErrStr  string `json:"error"`
	Message string `json:"message"`
}

type CreateRecordResp struct {
	URI     string `json:"uri"`
	ErrStr  string `json:"error"`
	Message string `json:"message"`
}

func (s *Server) CreateNewStatus(ctx context.Context, oauthsession oauth.Session, status string, createdAt time.Time) (string, error) {
	bodyReq := map[string]any{
		"repo":       oauthsession.Did,
		"collection": "xyz.statusphere.status",
		"record": map[string]any{
			"status":    status,
			"createdAt": createdAt,
		},
	}

	bodyB, err := json.Marshal(bodyReq)
	if err != nil {
		return "", fmt.Errorf("marshal update message request body: %w", err)
	}

	r := bytes.NewReader(bodyB)
	url := fmt.Sprintf("%s/xrpc/com.atproto.repo.createRecord", oauthsession.PdsUrl)
	request, err := http.NewRequestWithContext(ctx, "POST", url, r)
	if err != nil {
		return "", fmt.Errorf("create http request: %w", err)
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")
	request.Header.Set("Authorization", "DPoP "+oauthsession.AccessToken)

	privateKey, err := oauthsession.CreatePrivateKey()
	if err != nil {
		return "", fmt.Errorf("create private key: %w", err)
	}

	// try a maximum of 2 times to make the request. If the first attempt fails because the server returns an unauthorized due to a new use_dpop_nonce being issued,
	// then try again. Otherwise just try once.
	for range 2 {
		dpopJwt, err := s.oauthService.PdsDpopJwt("POST", url, oauthsession, privateKey)
		if err != nil {
			return "", err
		}

		request.Header.Set("DPoP", dpopJwt)

		resp, err := s.httpClient.Do(request)
		if err != nil {
			return "", fmt.Errorf("do http request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			return "", fmt.Errorf("unexpected status code returned: %d", resp.StatusCode)
		}

		var result CreateRecordResp
		err = decodeResp(resp.Body, &result)
		if err != nil {
			// just log the error.
			// if a HTTP 200 is received then the record has been created and we only use the response URI to make an optimistic write to our DB, so nothing will go wrong here.
			// if a HTTP 400 then we can at least log return that it was a bad request.
			// if a HTTP 401 we only do something if the error string is use_dpop_nonce
			slog.Error("decode response body", "error", err)
		}

		slog.Info("resp", "status", resp.StatusCode)

		if resp.StatusCode == http.StatusOK {
			return result.URI, nil
		}

		if resp.StatusCode == http.StatusBadRequest {
			return "", fmt.Errorf("bad request: %s - %s", result.Message, result.ErrStr)
		}

		if resp.StatusCode == http.StatusUnauthorized && result.ErrStr == "use_dpop_nonce" {
			newNonce := resp.Header.Get("DPoP-Nonce")
			oauthsession.DpopPdsNonce = newNonce
			err := s.oauthService.UpdateOAuthSessionDPopPDSNonce(oauthsession.Did, newNonce)
			if err != nil {
				// just log the error because we can still proceed without storing it.
				slog.Error("updating oauth session in store with new DPoP PDS nonce", "error", err)
			}
			continue
		}

		return "", fmt.Errorf("received an unauthorized status code and message: %s - %s", result.ErrStr, result.Message)
	}

	return "", fmt.Errorf("failed to create status record")
}

func decodeResp(body io.Reader, result any) error {
	resBody, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	err = json.Unmarshal(resBody, result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return nil
}

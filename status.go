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
	URI string `json:"uri"`
}

func (s *Server) CreateNewStatus(ctx context.Context, oauthsession oauth.Session, status string, createdAt time.Time) (string, error) {
	privateJwk, err := oauthsession.CreatePrivateKey()
	if err != nil {
		return "", fmt.Errorf("create private jwk: %w", err)
	}

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

	// TODO: redo this loop business
	for range 2 {
		r := bytes.NewReader(bodyB)
		url := fmt.Sprintf("%s/xrpc/com.atproto.repo.createRecord", oauthsession.PdsUrl)
		request, err := http.NewRequestWithContext(ctx, "POST", url, r)
		if err != nil {
			return "", fmt.Errorf("create http request: %w", err)
		}

		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Accept", "application/json")

		dpopJwt, err := pdsDpopJwt("POST", url, oauthsession.AuthserverIss, oauthsession.AccessToken, oauthsession.DpopPdsNonce, privateJwk)
		if err != nil {
			return "", err
		}

		request.Header.Set("DPoP", dpopJwt)
		request.Header.Set("Authorization", "DPoP "+oauthsession.AccessToken)

		resp, err := s.httpClient.Do(request)
		if err != nil {
			return "", fmt.Errorf("do http request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result CreateRecordResp
			err = decodeResp(resp.Body, &result)
			if err != nil {
				// just log error because we got a 200 indicating that the record was created. If this were to be tried again due to an error
				// returned here, there would be duplicate data
				slog.Error("decode success response", "error", err)
			}
			return result.URI, nil
		}

		var errorResp XRPCError
		err = decodeResp(resp.Body, &errorResp)
		if err != nil {
			return "", fmt.Errorf("decode error resp: %w", err)
		}

		if resp.StatusCode == 400 || resp.StatusCode == 401 && errorResp.ErrStr == "use_dpop_nonce" {
			newNonce := resp.Header.Get("DPoP-Nonce")
			oauthsession.DpopPdsNonce = newNonce
			err := s.oauthService.UpdateOAuthSessionDPopPDSNonce(oauthsession.Did, newNonce)
			if err != nil {
				slog.Error("updating oauth session in store with new DPoP PDS nonce", "error", err)
			}
			continue
		}

		slog.Error("got error", "status code", resp.StatusCode, "message", errorResp.Message, "error", errorResp.ErrStr)
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

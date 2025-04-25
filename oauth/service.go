package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	atoauth "github.com/haileyok/atproto-oauth-golang"
	oauthhelpers "github.com/haileyok/atproto-oauth-golang/helpers"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	scope = "atproto transition:generic"
)

type Request struct {
	ID                  uint
	AuthserverIss       string
	State               string
	Did                 string
	PdsURL              string
	PkceVerifier        string
	DpopAuthserverNonce string
	DpopPrivateJwk      string
}

type Session struct {
	ID                  uint
	Did                 string
	PdsUrl              string
	AuthserverIss       string
	AccessToken         string
	RefreshToken        string
	DpopPdsNonce        string
	DpopAuthserverNonce string
	DpopPrivateJwk      string
	Expiration          int64
}

func (s *Session) CreatePrivateKey() (jwk.Key, error) {
	privateJwk, err := oauthhelpers.ParseJWKFromBytes([]byte(s.DpopPrivateJwk))
	if err != nil {
		return nil, fmt.Errorf("create private jwk: %w", err)
	}
	return privateJwk, nil
}

type OAuthFlowResult struct {
	AuthorizationEndpoint string
	State                 string
	DID                   string
	RequestURI            string
}

type CallBackParams struct {
	State string
	Iss   string
	Code  string
}

type Store interface {
	CreateOauthRequest(request Request) error
	GetOauthRequest(state string) (Request, error)
	DeleteOauthRequest(state string) error
	CreateOauthSession(session Session) error
	GetOauthSession(did string) (Session, error)
	UpdateOauthSession(accessToken, refreshToken, dpopAuthServerNonce, did string, expiration int64) error
	DeleteOauthSession(did string) error
	UpdateOauthSessionDpopPdsNonce(dpopPdsServerNonce, did string) error
}

type Service struct {
	store       Store
	oauthClient *atoauth.Client
	httpClient  *http.Client
	jwks        *JWKS
}

func NewService(store Store, serverBase string, httpClient *http.Client) (*Service, error) {
	jwks, err := getJWKS()
	if err != nil {
		return nil, fmt.Errorf("getting JWKS: %w", err)
	}

	oauthClient, err := createOauthClient(jwks, serverBase, httpClient)
	if err != nil {
		return nil, fmt.Errorf("create oauth client: %w", err)
	}

	return &Service{
		store:       store,
		oauthClient: oauthClient,
		httpClient:  httpClient,
		jwks:        jwks,
	}, nil
}

func (s *Service) StartOAuthFlow(ctx context.Context, handle string) (*OAuthFlowResult, error) {
	usersDID, err := s.resolveHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("resolve handle: %w", err)
	}

	dpopPrivateKey, err := oauthhelpers.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	parResp, meta, service, err := s.makeOAuthRequest(ctx, usersDID, handle, dpopPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("make oauth request: %w", err)
	}

	dpopPrivateKeyJson, err := json.Marshal(dpopPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal dpop private key: %w", err)
	}

	oauthRequst := Request{
		AuthserverIss:       meta.Issuer,
		State:               parResp.State,
		Did:                 usersDID,
		PkceVerifier:        parResp.PkceVerifier,
		DpopAuthserverNonce: parResp.DpopAuthserverNonce,
		DpopPrivateJwk:      string(dpopPrivateKeyJson),
		PdsURL:              service,
	}
	err = s.store.CreateOauthRequest(oauthRequst)
	if err != nil {
		return nil, fmt.Errorf("store oauth request: %w", err)
	}

	result := OAuthFlowResult{
		AuthorizationEndpoint: meta.AuthorizationEndpoint,
		State:                 parResp.State,
		DID:                   usersDID,
		RequestURI:            parResp.RequestUri,
	}

	return &result, nil
}

func (s *Service) OAuthCallback(ctx context.Context, params CallBackParams) (string, error) {
	oauthRequest, err := s.store.GetOauthRequest(fmt.Sprintf("%s", params.State))
	if err != nil {
		return "", fmt.Errorf("get oauth request from store: %w", err)
	}

	err = s.store.DeleteOauthRequest(fmt.Sprintf("%s", params.State))
	if err != nil {
		return "", fmt.Errorf("delete oauth request from store: %w", err)
	}

	jwk, err := oauthhelpers.ParseJWKFromBytes([]byte(oauthRequest.DpopPrivateJwk))
	if err != nil {
		return "", fmt.Errorf("parse dpop private key: %w", err)
	}

	initialTokenResp, err := s.oauthClient.InitialTokenRequest(ctx, params.Code, params.Iss, oauthRequest.PkceVerifier, oauthRequest.DpopAuthserverNonce, jwk)
	if err != nil {
		return "", fmt.Errorf("make oauth token request: %w", err)
	}

	if initialTokenResp.Scope != scope {
		return "", fmt.Errorf("incorrect scope from token request")
	}

	oauthSession := Session{
		Did:                 oauthRequest.Did,
		PdsUrl:              oauthRequest.PdsURL,
		AuthserverIss:       oauthRequest.AuthserverIss,
		AccessToken:         initialTokenResp.AccessToken,
		RefreshToken:        initialTokenResp.RefreshToken,
		DpopAuthserverNonce: initialTokenResp.DpopAuthserverNonce,
		DpopPrivateJwk:      oauthRequest.DpopPrivateJwk,
		Expiration:          time.Now().Add(time.Duration(int(time.Second) * int(initialTokenResp.ExpiresIn))).UnixMilli(),
	}

	err = s.store.CreateOauthSession(oauthSession)
	if err != nil {
		return "", fmt.Errorf("create oauth session in store: %w", err)
	}
	return oauthRequest.Did, nil
}

func (s *Service) GetOauthSession(ctx context.Context, did string) (Session, error) {
	session, err := s.store.GetOauthSession(did)
	if err != nil {
		return Session{}, fmt.Errorf("find oauth session: %w", err)
	}

	// if the session expires in more than 5 minutes, return it
	if session.Expiration > time.Now().Add(time.Minute*5).UnixMilli() {
		return session, nil
	}

	// refresh the session
	privateJwk, err := oauthhelpers.ParseJWKFromBytes([]byte(session.DpopPrivateJwk))
	if err != nil {
		return Session{}, fmt.Errorf("parse sessions private JWK: %w", err)
	}

	resp, err := s.oauthClient.RefreshTokenRequest(ctx, session.RefreshToken, session.AuthserverIss, session.DpopAuthserverNonce, privateJwk)
	if err != nil {
		return Session{}, fmt.Errorf("refresh token: %w", err)
	}

	expiration := time.Now().Add(time.Duration(int(time.Second) * int(resp.ExpiresIn))).UnixMilli()

	err = s.store.UpdateOauthSession(resp.AccessToken, resp.RefreshToken, resp.DpopAuthserverNonce, did, expiration)
	if err != nil {
		return Session{}, fmt.Errorf("update session after refresh: %w", err)
	}

	session.AccessToken = resp.AccessToken
	session.RefreshToken = resp.RefreshToken
	session.DpopAuthserverNonce = resp.DpopAuthserverNonce
	session.Expiration = expiration

	return session, nil
}

func (s *Service) DeleteOAuthSession(did string) error {
	err := s.store.DeleteOauthSession(did)
	if err != nil {
		return fmt.Errorf("delete oauth session from store: %w", err)
	}
	return nil
}

func (s *Service) UpdateOAuthSessionDPopPDSNonce(did, newDPopNonce string) error {
	return s.store.UpdateOauthSessionDpopPdsNonce(newDPopNonce, did)
}

func (s *Service) PublicKey() []byte {
	return s.jwks.public
}

func (s *Service) PdsDpopJwt(method, url string, session Session, privateKey jwk.Key) (string, error) {
	return atoauth.PdsDpopJwt(method, url, session.AuthserverIss, session.AccessToken, session.DpopPdsNonce, privateKey)
}

func (s *Service) makeOAuthRequest(ctx context.Context, did, handle string, dpopPrivateKey jwk.Key) (*atoauth.SendParAuthResponse, *atoauth.OauthAuthorizationMetadata, string, error) {
	service, err := s.resolveService(ctx, did)
	if err != nil {
		return nil, nil, "", err
	}

	authserver, err := s.oauthClient.ResolvePdsAuthServer(ctx, service)
	if err != nil {
		return nil, nil, "", err
	}

	meta, err := s.oauthClient.FetchAuthServerMetadata(ctx, authserver)
	if err != nil {
		return nil, nil, "", err
	}

	resp, err := s.oauthClient.SendParAuthRequest(ctx, authserver, meta, handle, scope, dpopPrivateKey)
	if err != nil {
		return nil, nil, "", err
	}
	return resp, meta, service, nil
}

func (s *Service) resolveHandle(handle string) (string, error) {
	params := url.Values{
		"handle": []string{handle},
	}
	reqUrl := "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?" + params.Encode()

	resp, err := s.httpClient.Get(reqUrl)
	if err != nil {
		return "", fmt.Errorf("make http request: %w", err)
	}

	defer resp.Body.Close()

	type did struct {
		Did string
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	var resDid did
	err = json.Unmarshal(b, &resDid)
	if err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	return resDid.Did, nil
}

func (s *Service) resolveService(ctx context.Context, did string) (string, error) {
	type Identity struct {
		Service []struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ServiceEndpoint string `json:"serviceEndpoint"`
		} `json:"service"`
	}

	var url string
	if strings.HasPrefix(did, "did:plc:") {
		url = fmt.Sprintf("https://plc.directory/%s", did)
	} else if strings.HasPrefix(did, "did:web:") {
		url = fmt.Sprintf("https://%s/.well-known/did.json", strings.TrimPrefix(did, "did:web:"))
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("could not find identity in plc registry")
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	var identity Identity
	err = json.Unmarshal(b, &identity)
	if err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	var service string
	for _, svc := range identity.Service {
		if svc.ID == "#atproto_pds" {
			service = svc.ServiceEndpoint
		}
	}

	if service == "" {
		return "", fmt.Errorf("could not find atproto_pds service in identity services")
	}

	return service, nil
}

type JWKS struct {
	public  []byte
	private jwk.Key
}

func getJWKS() (*JWKS, error) {
	jwksB64 := os.Getenv("PRIVATEJWKS")
	if jwksB64 == "" {
		return nil, fmt.Errorf("PRIVATEJWKS env not set")
	}

	jwksB, err := base64.StdEncoding.DecodeString(jwksB64)
	if err != nil {
		return nil, fmt.Errorf("decode jwks env: %w", err)
	}

	k, err := oauthhelpers.ParseJWKFromBytes([]byte(jwksB))
	if err != nil {
		return nil, fmt.Errorf("parse JWK from bytes: %w", err)
	}

	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key from JWKS: %w", err)
	}

	resp := oauthhelpers.CreateJwksResponseObject(pubkey)
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal public JWKS: %w", err)
	}

	return &JWKS{
		public:  b,
		private: k,
	}, nil
}

func createOauthClient(jwks *JWKS, serverBase string, httpClient *http.Client) (*atoauth.Client, error) {
	return atoauth.NewClient(atoauth.ClientArgs{
		Http:        httpClient,
		ClientJwk:   jwks.private,
		ClientId:    fmt.Sprintf("%s/client-metadata.json", serverBase),
		RedirectUri: fmt.Sprintf("%s/oauth-callback", serverBase),
	})
}

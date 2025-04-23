package statusphere

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"text/template"

	"github.com/gorilla/sessions"

	"github.com/willdot/statusphere-go/oauth"
)

var ErrorNotFound = fmt.Errorf("not found")

type UserProfile struct {
	Did         string `json:"did"`
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
}

type Store interface {
	GetHandleAndDisplayNameForDid(did string) (UserProfile, error)
	CreateProfile(profile UserProfile) error
	GetStatuses(limit int) ([]Status, error)
	CreateStatus(status Status) error
}

type Server struct {
	host         string
	httpserver   *http.Server
	sessionStore *sessions.CookieStore
	templates    []*template.Template
	oauthService *oauth.Service
	store        Store
	httpClient   *http.Client
}

func NewServer(host string, port int, store Store, oauthService *oauth.Service, httpClient *http.Client) (*Server, error) {
	sessionStore := sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

	homeTemplate, err := template.ParseFiles("./html/home.html")
	if err != nil {
		return nil, fmt.Errorf("parsing home template: %w", err)
	}
	loginTemplate, err := template.ParseFiles("./html/login.html")
	if err != nil {
		return nil, fmt.Errorf("parsing login template: %w", err)
	}

	templates := []*template.Template{
		homeTemplate,
		loginTemplate,
	}

	srv := &Server{
		host:         host,
		oauthService: oauthService,
		sessionStore: sessionStore,
		templates:    templates,
		store:        store,
		httpClient:   httpClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.authMiddleware(srv.HandleHome))
	mux.HandleFunc("POST /status", srv.authMiddleware(srv.HandleStatus))

	mux.HandleFunc("GET /login", srv.HandleLogin)
	mux.HandleFunc("POST /login", srv.HandlePostLogin)
	mux.HandleFunc("POST /logout", srv.HandleLogOut)

	mux.HandleFunc("/public/app.css", serveCSS)
	mux.HandleFunc("/jwks.json", srv.serveJwks)
	mux.HandleFunc("/client-metadata.json", srv.serveClientMetadata)
	mux.HandleFunc("/oauth-callback", srv.handleOauthCallback)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	srv.httpserver = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return srv, nil
}

func (s *Server) Run() {
	err := s.httpserver.ListenAndServe()
	if err != nil {
		slog.Error("listen and serve", "error", err)
	}
}

func (s *Server) Stop(ctx context.Context) error {
	return s.httpserver.Shutdown(ctx)
}

func (s *Server) getTemplate(name string) *template.Template {
	for _, template := range s.templates {
		if template.Name() == name {
			return template
		}
	}
	return nil
}

func (s *Server) serveJwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.oauthService.PublicKey())
}

//go:embed html/app.css
var cssFile []byte

func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(cssFile)
}

func (s *Server) serveClientMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"client_id":                       fmt.Sprintf("%s/client-metadata.json", s.host),
		"client_name":                     "Bsky-bookmark",
		"client_uri":                      s.host,
		"redirect_uris":                   []string{fmt.Sprintf("%s/oauth-callback", s.host)},
		"grant_types":                     []string{"authorization_code", "refresh_token"},
		"response_types":                  []string{"code"},
		"application_type":                "web",
		"dpop_bound_access_tokens":        true,
		"jwks_uri":                        fmt.Sprintf("%s/jwks.json", s.host),
		"scope":                           "atproto transition:generic",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}

	b, err := json.Marshal(metadata)
	if err != nil {
		slog.Error("failed to marshal client metadata", "error", err)
		http.Error(w, "marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *Server) getDidFromSession(r *http.Request) (string, bool) {
	session, err := s.sessionStore.Get(r, "oauth-session")
	if err != nil {
		slog.Error("getting session", "error", err)
		return "", false
	}

	did, ok := session.Values["did"].(string)
	if !ok {
		return "", false
	}

	return did, true
}

func (s *Server) getUserProfileForDid(did string) (UserProfile, error) {
	profile, err := s.store.GetHandleAndDisplayNameForDid(did)
	if err == nil {
		return UserProfile{
			Did:         did,
			Handle:      profile.Handle,
			DisplayName: profile.DisplayName,
		}, nil
	}

	if !errors.Is(err, ErrorNotFound) {
		slog.Error("getting profile from database", "error", err)
	}

	profile, err = s.lookupUserProfile(did)
	if err != nil {
		return UserProfile{}, fmt.Errorf("looking up profile: %w", err)
	}
	err = s.store.CreateProfile(profile)
	if err != nil {
		slog.Error("store profile", "error", err)
	}

	return profile, nil
}

func (s *Server) lookupUserProfile(did string) (UserProfile, error) {
	params := url.Values{
		"actor": []string{did},
	}
	reqUrl := "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?" + params.Encode()

	resp, err := s.httpClient.Get(reqUrl)
	if err != nil {
		return UserProfile{}, fmt.Errorf("make http request: %w", err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserProfile{}, fmt.Errorf("read response body: %w", err)
	}

	var profile UserProfile
	err = json.Unmarshal(b, &profile)
	if err != nil {
		return UserProfile{}, fmt.Errorf("unmarshal response: %w", err)
	}

	return profile, nil
}

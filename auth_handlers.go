package statusphere

import (
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/willdot/statusphere-go/oauth"
)

type LoginData struct {
	Handle string
	Error  string
}

func (s *Server) authMiddleware(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := s.getDidFromSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	tmpl := s.getTemplate("login.html")
	data := LoginData{}
	tmpl.Execute(w, data)
}

func (s *Server) HandlePostLogin(w http.ResponseWriter, r *http.Request) {
	tmpl := s.getTemplate("login.html")
	data := LoginData{}

	err := r.ParseForm()
	if err != nil {
		slog.Error("parsing form", "error", err)
		data.Error = "error parsing data"
		tmpl.Execute(w, data)
		return
	}

	handle := r.FormValue("handle")

	result, err := s.oauthService.StartOAuthFlow(r.Context(), handle)
	if err != nil {
		slog.Error("starting oauth flow", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	u, _ := url.Parse(result.AuthorizationEndpoint)
	u.RawQuery = fmt.Sprintf("client_id=%s&request_uri=%s", url.QueryEscape(fmt.Sprintf("%s/client-metadata.json", s.host)), result.RequestURI)

	// ignore error here as it only returns an error for decoding an existing session but it will always return a session anyway which
	// is what we want
	session, _ := s.sessionStore.Get(r, "oauth-session")
	session.Values = map[any]any{}

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   300, // save for five minutes
		HttpOnly: true,
	}

	session.Values["oauth_state"] = result.State
	session.Values["oauth_did"] = result.DID

	err = session.Save(r, w)
	if err != nil {
		slog.Error("save session", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleOauthCallback(w http.ResponseWriter, r *http.Request) {
	tmpl := s.getTemplate("login.html")
	data := LoginData{}

	resState := r.FormValue("state")
	resIss := r.FormValue("iss")
	resCode := r.FormValue("code")

	session, err := s.sessionStore.Get(r, "oauth-session")
	if err != nil {
		slog.Error("getting session", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	if resState == "" || resIss == "" || resCode == "" {
		slog.Error("request missing needed parameters")
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	sessionState, ok := session.Values["oauth_state"].(string)
	if !ok {
		slog.Error("oauth_state not found in sesssion")
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	if resState != sessionState {
		slog.Error("session state does not match response state")
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	params := oauth.CallBackParams{
		Iss:   resIss,
		State: resState,
		Code:  resCode,
	}
	usersDID, err := s.oauthService.OAuthCallback(r.Context(), params)
	if err != nil {
		slog.Error("handling oauth callback", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	// make sure the session is empty before setting new values
	session.Values = map[any]any{}
	session.Values["did"] = usersDID

	err = session.Save(r, w)
	if err != nil {
		slog.Error("save session", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) HandleLogOut(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessionStore.Get(r, "oauth-session")
	if err != nil {
		slog.Error("getting session", "error", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	did, ok := session.Values["did"]
	if ok {
		err = s.oauthService.DeleteOAuthSession(fmt.Sprintf("%s", did))
		if err != nil {
			slog.Error("deleting oauth session", "error", err)
		}
	}

	session.Values = map[any]any{}
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	err = session.Save(r, w)
	if err != nil {
		slog.Error("save session", "error", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

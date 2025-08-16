package statusphere

import (
	_ "embed"
	"log/slog"
	"net/http"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

type LoginData struct {
	Handle string
	Error  string
}

func (s *Server) authMiddleware(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		did, _ := s.currentSessionDID(r)
		if did == nil {
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

	redirectURL, err := s.oauthClient.StartAuthFlow(r.Context(), handle)
	if err != nil {
		slog.Error("starting oauth flow", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleOauthCallback(w http.ResponseWriter, r *http.Request) {
	tmpl := s.getTemplate("login.html")
	data := LoginData{}

	sessData, err := s.oauthClient.ProcessCallback(r.Context(), r.URL.Query())
	if err != nil {
		slog.Error("processing OAuth callback", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	// create signed cookie session, indicating account DID
	sess, _ := s.sessionStore.Get(r, "oauth-demo")
	sess.Values["account_did"] = sessData.AccountDID.String()
	sess.Values["session_id"] = sessData.SessionID
	if err := sess.Save(r, w); err != nil {
		slog.Error("storing session data", "error", err)
		data.Error = "error logging in"
		tmpl.Execute(w, data)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) HandleLogOut(w http.ResponseWriter, r *http.Request) {
	did, sessionID := s.currentSessionDID(r)
	if did != nil {
		err := s.oauthClient.Store.DeleteSession(r.Context(), *did, sessionID)
		if err != nil {
			slog.Error("deleting oauth session", "error", err)
		}
	}

	sess, _ := s.sessionStore.Get(r, "oauth-demo")
	sess.Values = make(map[any]any)
	err := sess.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) currentSessionDID(r *http.Request) (*syntax.DID, string) {
	sess, _ := s.sessionStore.Get(r, "oauth-demo")
	accountDID, ok := sess.Values["account_did"].(string)
	if !ok || accountDID == "" {
		return nil, ""
	}
	did, err := syntax.ParseDID(accountDID)
	if err != nil {
		return nil, ""
	}
	sessionID, ok := sess.Values["session_id"].(string)
	if !ok || sessionID == "" {
		return nil, ""
	}

	return &did, sessionID
}

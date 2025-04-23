package statusphere

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

var Availablestatus = []string{
	"👍",
	"👎",
	"💙",
	"🥹",
	"😧",
	"😤",
	"🙃",
	"😉",
	"😎",
	"🤓",
	"🤨",
	"🥳",
	"😭",
	"😤",
	"🤯",
	"🫡",
	"💀",
	"✊",
	"🤘",
	"👀",
	"🧠",
	"👩‍💻",
	"🧑‍💻",
	"🥷",
	"🧌",
	"🦋",
	"🚀",
}

type HomeData struct {
	DisplayName     string
	AvailableStatus []string
	UsersStatus     []UserStatus
}

type UserStatus struct {
	Status    string
	Handle    string
	HandleURL string
	Date      string
	IsToday   bool
}

func (s *Server) HandleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := s.getTemplate("home.html")
	data := HomeData{
		AvailableStatus: Availablestatus,
	}
	usersDid, ok := s.getDidFromSession(r)
	if ok {
		profile, err := s.getUserProfileForDid(usersDid)
		if err != nil {
			slog.Error("getting logged in users profile", "error", err)
		}
		data.DisplayName = profile.DisplayName
	}

	today := time.Now().Format(time.DateOnly)

	results, err := s.store.GetStatuses(10)
	if err != nil {
		slog.Error("get status'", "error", err)
	}

	for _, status := range results {
		date := time.UnixMilli(status.CreatedAt).Format(time.DateOnly)

		profile, err := s.getUserProfileForDid(status.Did)
		if err != nil {
			slog.Error("getting user profile for status - skipping", "error", err, "did", status.Did)
			continue
		}

		data.UsersStatus = append(data.UsersStatus, UserStatus{
			Status:    status.Status,
			Handle:    profile.Handle,
			HandleURL: fmt.Sprintf("https://bsky.app/profile/%s", status.Did),
			Date:      date,
			IsToday:   date == today,
		})
	}

	tmpl.Execute(w, data)
}

func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		slog.Error("parsing form", "error", err)
		http.Error(w, "parsing form", http.StatusBadRequest)
		return
	}

	status := r.FormValue("status")
	if status == "" {
		http.Error(w, "missing status", http.StatusBadRequest)
		return
	}

	did, ok := s.getDidFromSession(r)
	if !ok {
		http.Error(w, "failed to get did from session", http.StatusBadRequest)
		return
	}

	oauthSession, err := s.oauthService.GetOauthSession(r.Context(), did)
	if err != nil {
		http.Error(w, "failed to get oauth session", http.StatusInternalServerError)
		return
	}

	createdAt := time.Now()
	uri, err := s.CreateNewStatus(r.Context(), oauthSession, status, createdAt)
	if err != nil {
		slog.Error("failed to create new status", "error", err)
	}

	if uri != "" {
		statusToStore := Status{
			URI:       uri,
			Did:       did,
			Status:    status,
			CreatedAt: createdAt.UnixMilli(),
			IndexedAt: time.Now().UnixMilli(),
		}
		err = s.store.CreateStatus(statusToStore)
		if err != nil {
			slog.Error("failed to store status that has been created", "error", err)
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

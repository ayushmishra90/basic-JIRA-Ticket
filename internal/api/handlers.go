package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"ticket-system/internal/auth"
	"ticket-system/internal/models"
	"ticket-system/internal/store"
)

// ---- Request / response payloads ----

// credentials is the body for register and login. Both `email` and `username`
// are accepted as the account identifier (see README assumptions); whichever
// is present is used.
type credentials struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c credentials) identifier() string {
	if strings.TrimSpace(c.Email) != "" {
		return c.Email
	}
	return c.Username
}

type createTicketRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

type refreshToken struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}
// ---- Handlers ----

// handleHealth -> GET /health
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRegister -> POST /auth/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decodeJSON(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := strings.TrimSpace(c.identifier())
	if id == "" || c.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	hash, err := auth.HashPassword(c.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not process password")
		return
	}

	u, err := s.store.CreateUser(id, hash)
	if err != nil {
		if errors.Is(err, store.ErrUserExists) {
			writeError(w, http.StatusConflict, "a user with that email already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":    u.ID,
		"email": u.Email,
	})
}

// handleLogin -> POST /auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decodeJSON(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := strings.TrimSpace(c.identifier())
	if id == "" || c.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	u, err := s.store.GetUserByEmail(id)
	// Same generic response whether the user is missing or the password is
	// wrong, to avoid leaking which accounts exist.
	if err != nil || !auth.VerifyPassword(u.PasswordHash, c.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	access, err := s.auth.Generate(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	refresh, err := s.auth.GenerateRefresh(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token refresh")
		return
	}
	claims, err := s.auth.ParseRefresh(refresh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not parse refresh token")
		return
	}
	s.store.SaveRefreshToken(
		u.ID,
		refresh,
		claims.ExpiresAt.Time,
	)
	writeJSON(w, http.StatusOK, map[string]any{"access": access, "refresh" : refresh})
}

func (s *Server) handleRefreshAccess(w http.ResponseWriter, r *http.Request) {
	var c refreshToken
	if err := decodeJSON(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	//verify refresh token is correct
	refresh, err := s.auth.ParseRefresh(c.RefreshToken)
	if err != nil{
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	_, er := s.store.GetRefresh(c.RefreshToken)

	if er != nil{
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	access, err := s.auth.Generate(refresh.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access": access})

}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest

	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify the JWT
	_, err := s.auth.ParseRefresh(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	// Remove it from storage
	err = s.store.DeleteRefreshToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh token not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

// handleCreateTicket -> POST /tickets
func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req createTicketRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}

	ticket := s.store.CreateTicket(userID, req.Title, strings.TrimSpace(req.Description))
	writeJSON(w, http.StatusCreated, ticket)
}

// handleListTickets -> GET /tickets
func (s *Server) handleListTickets(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	tickets := s.store.ListTicketsByUser(userID)
	writeJSON(w, http.StatusOK, tickets)
}

// handleGetTicket -> GET /tickets/{id}
func (s *Server) handleGetTicket(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	ticket, err := s.store.GetTicket(id)
	// Tickets owned by another user are reported as not found so their
	// existence is not disclosed.
	if err != nil || ticket.UserID != userID {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

// handleUpdateStatus -> PATCH /tickets/{id}/status
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	var req updateStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	newStatus := models.Status(strings.TrimSpace(req.Status))
	if !models.IsValidStatus(newStatus) {
		writeError(w, http.StatusBadRequest, "invalid status; must be one of: open, in_progress, closed")
		return
	}

	updated, err := s.store.UpdateTicketStatus(id, userID, newStatus)
	switch {
	case errors.Is(err, store.ErrTicketNotFound):
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	case errors.Is(err, store.ErrInvalidTransition):
		// Surface the most useful message for the common terminal case.
		current, _ := s.store.GetTicket(id)
		msg := "invalid status transition; allowed flow is open -> in_progress -> closed"
		if current.Status == models.StatusClosed {
			msg = "a closed ticket cannot be reopened"
		}
		writeError(w, http.StatusConflict, msg)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not update ticket")
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

// ---- small helpers ----

// decodeJSON decodes the request body into v. Unknown fields are ignored so
// the API stays tolerant of clients that send extra data.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func parseID(s string) (int, error) {
	id, err := strconv.Atoi(s)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

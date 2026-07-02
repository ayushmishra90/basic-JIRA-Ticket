package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"ticket-system/internal/auth"
	"ticket-system/internal/store"
)

// Server wires HTTP handlers to the store and token manager.
type Server struct {
	store *store.Store
	auth  *auth.Manager
}

// NewServer constructs a Server.
func NewServer(s *store.Store, a *auth.Manager) *Server {
	return &Server{store: s, auth: a}
}

// Routes builds the HTTP handler with all routes registered. It uses the
// Go 1.22 method-aware ServeMux, so no third-party router is needed.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public routes.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/refresh",s.handleRefreshAccess)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	// Protected routes (require a valid Bearer token).
	mux.Handle("POST /tickets", s.authMiddleware(http.HandlerFunc(s.handleCreateTicket)))
	mux.Handle("GET /tickets", s.authMiddleware(http.HandlerFunc(s.handleListTickets)))
	mux.Handle("GET /tickets/{id}", s.authMiddleware(http.HandlerFunc(s.handleGetTicket)))
	mux.Handle("PATCH /tickets/{id}/status", s.authMiddleware(http.HandlerFunc(s.handleUpdateStatus)))


	return mux
}

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey string

const userIDKey contextKey = "userID"

// authMiddleware validates the Authorization: Bearer <token> header and
// injects the authenticated user ID into the request context.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			writeError(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}
		claims, err := s.auth.Parse(strings.TrimSpace(parts[1]))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// userIDFromContext returns the authenticated user ID set by authMiddleware.
func userIDFromContext(ctx context.Context) int {
	id, _ := ctx.Value(userIDKey).(int)
	return id
}

// writeJSON serializes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits a JSON error body: {"error": "..."}.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

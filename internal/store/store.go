package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"ticket-system/internal/models"
)

// Store-level sentinel errors.
var (
	ErrUserExists     = errors.New("user already exists")
	ErrUserNotFound   = errors.New("user not found")
	ErrTicketNotFound = errors.New("ticket not found")
)

// Store is a concurrency-safe, in-memory persistence layer.
//
// In-memory storage is intentionally chosen to keep the service simple and
// dependency-free (the assignment explicitly permits it). All state is lost
// on restart. Swapping this out for SQLite/Postgres would only require
// reimplementing these methods behind the same interface.
type Store struct {
	mu           sync.RWMutex
	usersByEmail map[string]*models.User
	tickets      map[int]*models.Ticket
	nextUserID   int
	nextTicketID int
}

// New returns an empty, ready-to-use store.
func New() *Store {
	return &Store{
		usersByEmail: make(map[string]*models.User),
		tickets:      make(map[int]*models.Ticket),
		nextUserID:   1,
		nextTicketID: 1,
	}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateUser registers a new user. Returns ErrUserExists if the email is taken.
func (s *Store) CreateUser(email, passwordHash string) (models.User, error) {
	email = normalizeEmail(email)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.usersByEmail[email]; ok {
		return models.User{}, ErrUserExists
	}
	u := &models.User{
		ID:           s.nextUserID,
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}
	s.usersByEmail[email] = u
	s.nextUserID++
	return *u, nil
}

// GetUserByEmail looks up a user by (normalized) email.
func (s *Store) GetUserByEmail(email string) (models.User, error) {
	email = normalizeEmail(email)

	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.usersByEmail[email]
	if !ok {
		return models.User{}, ErrUserNotFound
	}
	return *u, nil
}

// CreateTicket creates a new open ticket owned by userID.
func (s *Store) CreateTicket(userID int, title, description string) models.Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	t := &models.Ticket{
		ID:          s.nextTicketID,
		Title:       title,
		Description: description,
		Status:      models.StatusOpen,
		UserID:      userID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.tickets[t.ID] = t
	s.nextTicketID++
	return *t
}

// ListTicketsByUser returns all tickets owned by userID, ordered by ID.
func (s *Store) ListTicketsByUser(userID int) []models.Ticket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]models.Ticket, 0)
	for _, t := range s.tickets {
		if t.UserID == userID {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// GetTicket fetches a ticket by ID regardless of owner. Ownership checks are
// the caller's responsibility.
func (s *Store) GetTicket(id int) (models.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tickets[id]
	if !ok {
		return models.Ticket{}, ErrTicketNotFound
	}
	return *t, nil
}

// UpdateTicketStatus atomically validates ownership and the status transition,
// then applies the new status. Doing this under a single lock avoids
// time-of-check/time-of-use races.
//
// Possible errors: ErrTicketNotFound (also returned when the ticket is owned
// by someone else, so existence is not leaked), or ErrInvalidTransition.
func (s *Store) UpdateTicketStatus(id, userID int, newStatus models.Status) (models.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[id]
	if !ok || t.UserID != userID {
		return models.Ticket{}, ErrTicketNotFound
	}
	if !models.CanTransition(t.Status, newStatus) {
		return models.Ticket{}, ErrInvalidTransition
	}
	t.Status = newStatus
	t.UpdatedAt = time.Now().UTC()
	return *t, nil
}

// ErrInvalidTransition signals a disallowed status change.
var ErrInvalidTransition = errors.New("invalid status transition")

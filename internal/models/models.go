package models

import "time"

// User is an application account. PasswordHash is never serialized.
type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Status is the lifecycle state of a ticket.
type Status string

const (
	StatusOpen       Status = "open"
	StatusInProgress Status = "in_progress"
	StatusClosed     Status = "closed"
)

// Ticket is a unit of work owned by exactly one user.
type Ticket struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      Status    `json:"status"`
	UserID      int       `json:"user_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	Expiry    time.Time `json:"expiry"`
}
// IsValidStatus reports whether s is one of the supported statuses.
func IsValidStatus(s Status) bool {
	switch s {
	case StatusOpen, StatusInProgress, StatusClosed:
		return true
	default:
		return false
	}
}

// CanTransition reports whether a ticket may move from `from` to `to`.
//
// The required lifecycle is strictly sequential and forward-only:
//
//	open -> in_progress -> closed
//
// A closed ticket is terminal and can never be reopened. Skipping a step
// (e.g. open -> closed) and any backward move are both rejected.
func CanTransition(from, to Status) bool {
	switch from {
	case StatusOpen:
		return to == StatusInProgress
	case StatusInProgress:
		return to == StatusClosed
	default: // closed (or unknown) is terminal
		return false
	}
}

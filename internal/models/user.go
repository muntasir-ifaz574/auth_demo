package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents an account stored in the Supabase (Postgres) database.
type User struct {
	ID              uuid.UUID
	Email           string
	FullName        string
	PhoneNumber     string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	LastLogin       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

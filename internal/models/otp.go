package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OTPPurpose enumerates the supported one-time-password flows.
type OTPPurpose string

const (
	OTPPurposeSignup        OTPPurpose = "signup"
	OTPPurposeSignin        OTPPurpose = "signin"
	OTPPurposePasswordReset OTPPurpose = "password_reset"
)

// OTP encapsulates the code stored in the database.
type OTP struct {
	ID         uuid.UUID
	Email      string
	Code       string
	Purpose    OTPPurpose
	Payload    json.RawMessage
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

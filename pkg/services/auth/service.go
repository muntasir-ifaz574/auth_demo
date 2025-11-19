package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	emailpkg "auth_demo/pkg/email"
	"auth_demo/pkg/jwtutil"
	"auth_demo/pkg/models"
	"auth_demo/pkg/otp"
	"auth_demo/pkg/password"
	"auth_demo/pkg/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Service orchestrates all authentication use-cases.
type Service struct {
	repo   repository.Storage
	email  emailpkg.Sender
	jwt    *jwtutil.Manager
	otpTTL time.Duration
}

// NewService builds the auth service.
func NewService(repo repository.Storage, mailer emailpkg.Sender, jwtManager *jwtutil.Manager, otpTTL time.Duration) *Service {
	return &Service{repo: repo, email: mailer, jwt: jwtManager, otpTTL: otpTTL}
}

// Inputs

type SignupInput struct {
	Email       string
	FullName    string
	PhoneNumber string
	Password    string
}

type VerifyInput struct {
	Email string
	Code  string
}

type ForgotPasswordVerifyInput struct {
	Email       string
	Code        string
	NewPassword string
}

type SigninInput struct {
	Email    string
	Password string
}

type AuthResult struct {
	Token     string
	ExpiresAt time.Time
	User      models.User
}

var (
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrOTPNotFound        = errors.New("no active otp found")
	ErrOTPExpired         = errors.New("otp has expired")
	ErrOTPCodeMismatch    = errors.New("otp code mismatch")
	ErrUserNotFound       = errors.New("user not found")
	ErrSamePassword       = errors.New("new password cannot match current password")
)

type signupPayload struct {
	FullName     string `json:"full_name"`
	PhoneNumber  string `json:"phone_number"`
	PasswordHash string `json:"password_hash"`
}

func (s *Service) StartSignup(ctx context.Context, input SignupInput) error {
	email := normalizeEmail(input.Email)
	if email == "" || input.Password == "" || strings.TrimSpace(input.FullName) == "" {
		return fmt.Errorf("email, fullName and password are required")
	}
	existing, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if existing != nil {
		return ErrUserExists
	}

	hashed, err := password.Hash(input.Password)
	if err != nil {
		return err
	}

	payload := signupPayload{
		FullName:     strings.TrimSpace(input.FullName),
		PhoneNumber:  strings.TrimSpace(input.PhoneNumber),
		PasswordHash: hashed,
	}

	if err := s.repo.DeleteActiveOTPs(ctx, email, models.OTPPurposeSignup); err != nil {
		return err
	}
	code, err := otp.GenerateNumeric(6)
	if err != nil {
		return err
	}
	otpModel := models.OTP{
		Email:     email,
		Code:      code,
		Purpose:   models.OTPPurposeSignup,
		Payload:   repository.MarshalPayload(payload),
		ExpiresAt: time.Now().Add(s.otpTTL),
	}
	if err := s.repo.CreateOTP(ctx, otpModel); err != nil {
		return err
	}

	return s.email.SendOTP(ctx, emailpkg.OTPMessage{
		ToEmail:   email,
		ToName:    payload.FullName,
		Purpose:   string(models.OTPPurposeSignup),
		Code:      code,
		ExpiresIn: s.otpTTL,
	})
}

func (s *Service) CompleteSignup(ctx context.Context, input VerifyInput) (AuthResult, error) {
	email := normalizeEmail(input.Email)
	otpModel, err := s.repo.GetActiveOTP(ctx, email, models.OTPPurposeSignup)
	if err != nil {
		return AuthResult{}, err
	}
	if otpModel == nil {
		return AuthResult{}, ErrOTPNotFound
	}
	if time.Now().After(otpModel.ExpiresAt) {
		return AuthResult{}, ErrOTPExpired
	}
	if !constantTimeEqual(otpModel.Code, input.Code) {
		return AuthResult{}, ErrOTPCodeMismatch
	}

	var payload signupPayload
	if err := repository.UnmarshalPayload(otpModel.Payload, &payload); err != nil {
		return AuthResult{}, err
	}
	if payload.PasswordHash == "" {
		return AuthResult{}, errors.New("signup payload corrupted")
	}

	now := time.Now()
	user := models.User{
		Email:           email,
		FullName:        payload.FullName,
		PhoneNumber:     payload.PhoneNumber,
		PasswordHash:    payload.PasswordHash,
		EmailVerifiedAt: &now,
	}
	created, err := s.repo.CreateUser(ctx, user)
	if err != nil {
		return AuthResult{}, err
	}
	if err := s.repo.ConsumeOTP(ctx, otpModel.ID, now); err != nil {
		return AuthResult{}, err
	}

	token, expiresAt, err := s.jwt.Generate(created)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{Token: token, ExpiresAt: expiresAt, User: created}, nil
}

func (s *Service) ResendSignupOTP(ctx context.Context, emailAddr string) error {
	email := normalizeEmail(emailAddr)
	otpModel, err := s.repo.GetActiveOTP(ctx, email, models.OTPPurposeSignup)
	if err != nil {
		return err
	}
	if otpModel == nil {
		return ErrOTPNotFound
	}
	var payload signupPayload
	if err := repository.UnmarshalPayload(otpModel.Payload, &payload); err != nil {
		return err
	}
	if err := s.repo.DeleteActiveOTPs(ctx, email, models.OTPPurposeSignup); err != nil {
		return err
	}
	code, err := otp.GenerateNumeric(6)
	if err != nil {
		return err
	}
	newOTP := models.OTP{
		Email:     email,
		Code:      code,
		Purpose:   models.OTPPurposeSignup,
		Payload:   repository.MarshalPayload(payload),
		ExpiresAt: time.Now().Add(s.otpTTL),
	}
	if err := s.repo.CreateOTP(ctx, newOTP); err != nil {
		return err
	}
	return s.email.SendOTP(ctx, emailpkg.OTPMessage{
		ToEmail:   email,
		ToName:    payload.FullName,
		Purpose:   string(models.OTPPurposeSignup),
		Code:      code,
		ExpiresIn: s.otpTTL,
	})
}

func (s *Service) StartSignin(ctx context.Context, input SigninInput) error {
	email := normalizeEmail(input.Email)
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrInvalidCredentials
	}
	if err := password.Compare(user.PasswordHash, input.Password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		return err
	}
	if err := s.repo.DeleteActiveOTPs(ctx, email, models.OTPPurposeSignin); err != nil {
		return err
	}
	code, err := otp.GenerateNumeric(6)
	if err != nil {
		return err
	}
	otpModel := models.OTP{
		Email:     email,
		Code:      code,
		Purpose:   models.OTPPurposeSignin,
		ExpiresAt: time.Now().Add(s.otpTTL),
	}
	if err := s.repo.CreateOTP(ctx, otpModel); err != nil {
		return err
	}
	return s.email.SendOTP(ctx, emailpkg.OTPMessage{
		ToEmail:   email,
		ToName:    user.FullName,
		Purpose:   string(models.OTPPurposeSignin),
		Code:      code,
		ExpiresIn: s.otpTTL,
	})
}

func (s *Service) VerifySignin(ctx context.Context, input VerifyInput) (AuthResult, error) {
	email := normalizeEmail(input.Email)
	otpModel, err := s.repo.GetActiveOTP(ctx, email, models.OTPPurposeSignin)
	if err != nil {
		return AuthResult{}, err
	}
	if otpModel == nil {
		return AuthResult{}, ErrOTPNotFound
	}
	if time.Now().After(otpModel.ExpiresAt) {
		return AuthResult{}, ErrOTPExpired
	}
	if !constantTimeEqual(otpModel.Code, input.Code) {
		return AuthResult{}, ErrOTPCodeMismatch
	}
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return AuthResult{}, err
	}
	if user == nil {
		return AuthResult{}, ErrUserNotFound
	}
	now := time.Now()
	if err := s.repo.ConsumeOTP(ctx, otpModel.ID, now); err != nil {
		return AuthResult{}, err
	}
	if err := s.repo.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return AuthResult{}, err
	}
	token, expiresAt, err := s.jwt.Generate(*user)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{Token: token, ExpiresAt: expiresAt, User: *user}, nil
}

func (s *Service) ResendSigninOTP(ctx context.Context, emailAddr string) error {
	email := normalizeEmail(emailAddr)
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if err := s.repo.DeleteActiveOTPs(ctx, email, models.OTPPurposeSignin); err != nil {
		return err
	}
	code, err := otp.GenerateNumeric(6)
	if err != nil {
		return err
	}
	otpModel := models.OTP{
		Email:     email,
		Code:      code,
		Purpose:   models.OTPPurposeSignin,
		ExpiresAt: time.Now().Add(s.otpTTL),
	}
	if err := s.repo.CreateOTP(ctx, otpModel); err != nil {
		return err
	}
	return s.email.SendOTP(ctx, emailpkg.OTPMessage{
		ToEmail:   email,
		ToName:    user.FullName,
		Purpose:   string(models.OTPPurposeSignin),
		Code:      code,
		ExpiresIn: s.otpTTL,
	})
}

func (s *Service) StartForgotPassword(ctx context.Context, emailAddr string) error {
	email := normalizeEmail(emailAddr)
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if err := s.repo.DeleteActiveOTPs(ctx, email, models.OTPPurposePasswordReset); err != nil {
		return err
	}
	code, err := otp.GenerateNumeric(6)
	if err != nil {
		return err
	}
	otpModel := models.OTP{
		Email:     email,
		Code:      code,
		Purpose:   models.OTPPurposePasswordReset,
		ExpiresAt: time.Now().Add(s.otpTTL),
	}
	if err := s.repo.CreateOTP(ctx, otpModel); err != nil {
		return err
	}
	return s.email.SendOTP(ctx, emailpkg.OTPMessage{
		ToEmail:   email,
		ToName:    user.FullName,
		Purpose:   string(models.OTPPurposePasswordReset),
		Code:      code,
		ExpiresIn: s.otpTTL,
	})
}

// ResendForgotPassword invalidates existing OTPs and sends another reset code.
func (s *Service) ResendForgotPassword(ctx context.Context, emailAddr string) error {
	return s.StartForgotPassword(ctx, emailAddr)
}

func (s *Service) CompleteForgotPassword(ctx context.Context, input ForgotPasswordVerifyInput) error {
	email := normalizeEmail(input.Email)
	if strings.TrimSpace(input.NewPassword) == "" {
		return fmt.Errorf("new password is required")
	}
	otpModel, err := s.repo.GetActiveOTP(ctx, email, models.OTPPurposePasswordReset)
	if err != nil {
		return err
	}
	if otpModel == nil {
		return ErrOTPNotFound
	}
	if time.Now().After(otpModel.ExpiresAt) {
		return ErrOTPExpired
	}
	if !constantTimeEqual(otpModel.Code, input.Code) {
		return ErrOTPCodeMismatch
	}
	hashed, err := password.Hash(input.NewPassword)
	if err != nil {
		return err
	}
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if password.Compare(user.PasswordHash, input.NewPassword) == nil {
		return ErrSamePassword
	}
	if err := s.repo.UpdateUserPassword(ctx, user.ID, hashed); err != nil {
		return err
	}
	if err := s.repo.ConsumeOTP(ctx, otpModel.ID, time.Now()); err != nil {
		return err
	}
	return nil
}

func (s *Service) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	if strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("new password is required")
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if err := password.Compare(user.PasswordHash, currentPassword); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		return err
	}
	if currentPassword == newPassword {
		return ErrSamePassword
	}
	hashed, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	return s.repo.UpdateUserPassword(ctx, user.ID, hashed)
}

func normalizeEmail(val string) string {
	return strings.TrimSpace(strings.ToLower(val))
}

func constantTimeEqual(expected, provided string) bool {
	if len(expected) != len(provided) {
		return false
	}
	var diff byte
	for i := 0; i < len(expected); i++ {
		diff |= expected[i] ^ provided[i]
	}
	return diff == 0
}

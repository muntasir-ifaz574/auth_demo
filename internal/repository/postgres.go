package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"auth_demo/internal/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Storage defines the persistence operations required by the auth service.
type Storage interface {
	CreateUser(ctx context.Context, user models.User) (models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, ts time.Time) error
	CreateOTP(ctx context.Context, otp models.OTP) error
	GetActiveOTP(ctx context.Context, email string, purpose models.OTPPurpose) (*models.OTP, error)
	ConsumeOTP(ctx context.Context, id uuid.UUID, consumedAt time.Time) error
	DeleteActiveOTPs(ctx context.Context, email string, purpose models.OTPPurpose) error
}

// PostgresRepository implements Storage using Supabase's Postgres database.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository builds a repository backed by pgx pool.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) CreateUser(ctx context.Context, user models.User) (models.User, error) {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	query := `INSERT INTO users (id, email, full_name, phone_number, password_hash, email_verified_at)
              VALUES ($1,$2,$3,$4,$5,$6)
              RETURNING created_at, updated_at, last_login`
	row := r.pool.QueryRow(ctx, query, user.ID, user.Email, user.FullName, user.PhoneNumber, user.PasswordHash, user.EmailVerifiedAt)
	if err := row.Scan(&user.CreatedAt, &user.UpdatedAt, &user.LastLogin); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, full_name, phone_number, password_hash, email_verified_at, last_login, created_at, updated_at
              FROM users WHERE email = $1`
	row := r.pool.QueryRow(ctx, query, email)
	var user models.User
	if err := row.Scan(&user.ID, &user.Email, &user.FullName, &user.PhoneNumber, &user.PasswordHash, &user.EmailVerifiedAt, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *PostgresRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT id, email, full_name, phone_number, password_hash, email_verified_at, last_login, created_at, updated_at
              FROM users WHERE id = $1`
	row := r.pool.QueryRow(ctx, query, id)
	var user models.User
	if err := row.Scan(&user.ID, &user.Email, &user.FullName, &user.PhoneNumber, &user.PasswordHash, &user.EmailVerifiedAt, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *PostgresRepository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`, passwordHash, userID)
	return err
}

func (r *PostgresRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ts time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_login=$1, updated_at=NOW() WHERE id=$2`, ts, userID)
	return err
}

func (r *PostgresRepository) CreateOTP(ctx context.Context, otp models.OTP) error {
	if otp.ID == uuid.Nil {
		otp.ID = uuid.New()
	}
	query := `INSERT INTO otp_codes (id, email, code, purpose, payload, expires_at)
              VALUES ($1,$2,$3,$4,$5,$6)`
	_, err := r.pool.Exec(ctx, query, otp.ID, otp.Email, otp.Code, otp.Purpose, otp.Payload, otp.ExpiresAt)
	return err
}

func (r *PostgresRepository) GetActiveOTP(ctx context.Context, email string, purpose models.OTPPurpose) (*models.OTP, error) {
	query := `SELECT id, email, code, purpose, payload, expires_at, consumed_at, created_at
              FROM otp_codes
              WHERE email=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at > NOW()
              ORDER BY created_at DESC
              LIMIT 1`
	row := r.pool.QueryRow(ctx, query, email, purpose)
	var otp models.OTP
	if err := row.Scan(&otp.ID, &otp.Email, &otp.Code, &otp.Purpose, &otp.Payload, &otp.ExpiresAt, &otp.ConsumedAt, &otp.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &otp, nil
}

func (r *PostgresRepository) ConsumeOTP(ctx context.Context, id uuid.UUID, consumedAt time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE otp_codes SET consumed_at=$1 WHERE id=$2`, consumedAt, id)
	return err
}

func (r *PostgresRepository) DeleteActiveOTPs(ctx context.Context, email string, purpose models.OTPPurpose) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM otp_codes WHERE email=$1 AND purpose=$2 AND consumed_at IS NULL`, email, purpose)
	return err
}

// MarshalPayload helper to create json payloads for OTPs.
func MarshalPayload(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return data
}

// UnmarshalPayload decodes JSON payloads into the provided destination struct.
func UnmarshalPayload(data json.RawMessage, dst any) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, dst)
}

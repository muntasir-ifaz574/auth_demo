package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"auth_demo/pkg/email"
)

// Config represents the application configuration loaded from environment variables.
type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string
	JWTIssuer   string
	JWTExpiry   time.Duration
	OTPExpiry   time.Duration
	Email       email.Config
	Environment string
}

// Load reads configuration from environment variables and returns a Config instance.
func Load() (Config, error) {
	cfg := Config{}
	cfg.Port = getEnv("PORT", "8080")
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	cfg.JWTIssuer = getEnv("JWT_ISSUER", "auth-demo")
	cfg.Environment = getEnv("APP_ENV", "local")

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}

	jwtDays := getInt("JWT_EXPIRY_DAYS", 30)
	cfg.JWTExpiry = time.Duration(jwtDays) * 24 * time.Hour

	otpMinutes := getInt("OTP_TTL_MINUTES", 3)
	cfg.OTPExpiry = time.Duration(otpMinutes) * time.Minute

	emailCfg, err := email.LoadFromEnv()
	if err != nil {
		return Config{}, err
	}
	cfg.Email = emailCfg

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
	}
	return fallback
}

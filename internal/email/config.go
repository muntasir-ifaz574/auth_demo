package email

import (
	"fmt"
	"os"
	"strconv"
)

// Config captures all settings needed for sending transactional emails.
type Config struct {
	Provider       string
	FromEmail      string
	FromName       string
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPSkipVerify bool
}

// LoadFromEnv builds an email configuration using the EMAIL_* environment variables.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		Provider:     getEnv("EMAIL_PROVIDER", "log"),
		FromEmail:    os.Getenv("EMAIL_FROM"),
		FromName:     getEnv("EMAIL_FROM_NAME", "Auth Demo"),
		SMTPHost:     os.Getenv("EMAIL_SMTP_HOST"),
		SMTPUsername: os.Getenv("EMAIL_SMTP_USERNAME"),
		SMTPPassword: os.Getenv("EMAIL_SMTP_PASSWORD"),
	}

	smtpPort := getEnv("EMAIL_SMTP_PORT", "587")
	if p, err := strconv.Atoi(smtpPort); err == nil {
		cfg.SMTPPort = p
	} else {
		cfg.SMTPPort = 587
	}

	skipVerify := getEnv("EMAIL_SMTP_SKIP_VERIFY", "false")
	cfg.SMTPSkipVerify = skipVerify == "true"

	if cfg.Provider == "smtp" {
		if cfg.FromEmail == "" || cfg.SMTPHost == "" || cfg.SMTPUsername == "" || cfg.SMTPPassword == "" {
			return Config{}, fmt.Errorf("SMTP email provider selected but mandatory settings are missing")
		}
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

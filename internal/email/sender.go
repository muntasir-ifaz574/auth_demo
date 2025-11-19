package email

import (
	"context"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"
)

// OTPMessage describes the payload used for sending OTP emails.
type OTPMessage struct {
	ToEmail   string
	ToName    string
	Purpose   string
	Code      string
	ExpiresIn time.Duration
}

// Sender defines the contract for delivering transactional emails.
type Sender interface {
	SendOTP(ctx context.Context, msg OTPMessage) error
}

// NewSender returns the appropriate email sender for the given config.
func NewSender(cfg Config) (Sender, error) {
	switch strings.ToLower(cfg.Provider) {
	case "log":
		return logSender{fromEmail: cfg.FromEmail, fromName: cfg.FromName}, nil
	case "smtp":
		return smtpSender{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unsupported email provider: %s", cfg.Provider)
	}
}

// logSender simply writes OTP payloads to stdout, useful for local development.
type logSender struct {
	fromEmail string
	fromName  string
}

func (l logSender) SendOTP(_ context.Context, msg OTPMessage) error {
	log.Printf("[EMAIL:LOG] to=%s code=%s purpose=%s expires_in=%s", msg.ToEmail, msg.Code, msg.Purpose, msg.ExpiresIn)
	return nil
}

// smtpSender sends email via a traditional SMTP server.
type smtpSender struct {
	cfg Config
}

func (s smtpSender) SendOTP(_ context.Context, msg OTPMessage) error {
	purpose := msg.Purpose
	if purpose == "" {
		purpose = "OTP"
	} else if len(purpose) > 1 {
		purpose = strings.ToUpper(purpose[:1]) + purpose[1:]
	} else {
		purpose = strings.ToUpper(purpose)
	}
	subject := fmt.Sprintf("Your %s verification code", purpose)
	body := fmt.Sprintf("Hello %s,\n\nYour verification code is %s. It expires in %d minutes.\n\nIf you did not request this, you can ignore this email.\n",
		msg.ToName, msg.Code, int(msg.ExpiresIn.Minutes()))

	message := strings.Builder{}
	from := s.cfg.FromEmail
	if from == "" {
		from = s.cfg.SMTPUsername
	}
	message.WriteString(fmt.Sprintf("From: %s\r\n", from))
	message.WriteString(fmt.Sprintf("To: %s\r\n", msg.ToEmail))
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	message.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	message.WriteString(body)

	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	return smtp.SendMail(addr, auth, from, []string{msg.ToEmail}, []byte(message.String()))
}

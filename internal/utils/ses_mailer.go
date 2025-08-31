package utils

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

// SESMailerConfig holds the configuration for AWS SES SMTP
type SESMailerConfig struct {
	Region       string // e.g., "us-east-1", "us-west-2", "eu-west-1"
	SMTPUsername string // SMTP username (IAM access key)
	SMTPPassword string // SMTP password (generated from secret key)
	FromEmail    string // Must be verified in SES
	FromName     string
}

// SESMailer handles email sending via AWS SES using SMTP
type SESMailer struct {
	config SESMailerConfig
	host   string
	port   string
}

// NewSESMailer creates a new SES mailer instance using SMTP
// SMTP endpoints by region:
// us-east-1: email-smtp.us-east-1.amazonaws.com
// us-west-2: email-smtp.us-west-2.amazonaws.com
// eu-west-1: email-smtp.eu-west-1.amazonaws.com
func NewSESMailer(cfg SESMailerConfig) (*SESMailer, error) {
	host := fmt.Sprintf("email-smtp.%s.amazonaws.com", cfg.Region)
	return &SESMailer{
		config: cfg,
		host:   host,
		port:   "587", // Use port 587 for STARTTLS
	}, nil
}

// EmailMessage represents an email to be sent
type EmailMessage struct {
	To      []string
	Subject string
	Body    string
	IsHTML  bool
}

// SendEmail sends an email using AWS SES SMTP interface
func (m *SESMailer) SendEmail(msg EmailMessage) error {
	from := m.config.FromEmail
	if m.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", m.config.FromName, m.config.FromEmail)
	}

	// Build email message
	var contentType string
	if msg.IsHTML {
		contentType = "Content-Type: text/html; charset=UTF-8\r\n"
	} else {
		contentType = "Content-Type: text/plain; charset=UTF-8\r\n"
	}

	subject := fmt.Sprintf("Subject: %s\r\n", msg.Subject)
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\n", from, strings.Join(msg.To, ","))
	message := []byte(subject + headers + contentType + "\r\n" + msg.Body)

	// Authentication
	auth := smtp.PlainAuth("", m.config.SMTPUsername, m.config.SMTPPassword, m.host)

	// Connect to SMTP server
	addr := m.host + ":" + m.port
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SES SMTP server: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Start TLS
	tlsConfig := &tls.Config{
		ServerName: m.host,
		MinVersion: tls.VersionTLS12,
	}
	if err = client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Authenticate
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate with SES: %w", err)
	}

	// Set sender
	if err = client.Mail(m.config.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range msg.To {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send email data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	// Quit
	if err = client.Quit(); err != nil {
		return fmt.Errorf("failed to quit: %w", err)
	}

	fmt.Println("Email sent successfully via AWS SES!")
	return nil
}

// SendVerificationCodeEmail sends a plain text verification code email
func (m *SESMailer) SendVerificationCodeEmail(to string, code string, expiryMinutes int) error {
	msg := EmailMessage{
		To:      []string{to},
		Subject: "Your Verification Code",
		Body:    fmt.Sprintf("Your verification code is: %s (valid for %d minutes)", code, expiryMinutes),
		IsHTML:  false,
	}
	return m.SendEmail(msg)
}

// SendVerificationCodeEmailHTML sends an HTML formatted verification code email
func (m *SESMailer) SendVerificationCodeEmailHTML(to string, code string, expiryMinutes int) error {
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { background-color: #f9f9f9; padding: 30px; border-radius: 5px; margin-top: 20px; }
        .code { font-size: 32px; font-weight: bold; color: #4CAF50; text-align: center; letter-spacing: 5px; padding: 20px; background-color: #fff; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verification Code</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>You have requested a verification code. Please use the code below to complete your verification:</p>
            <div class="code">%s</div>
            <p>This code will expire in <strong>%d minutes</strong>.</p>
            <p>If you did not request this code, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, code, expiryMinutes)

	msg := EmailMessage{
		To:      []string{to},
		Subject: "Your Verification Code",
		Body:    htmlBody,
		IsHTML:  true,
	}
	return m.SendEmail(msg)
}

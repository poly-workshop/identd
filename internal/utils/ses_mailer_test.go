package utils

import (
	"testing"
)

func TestSESMailing(t *testing.T) {
	// Load configuration from environment variables
	// You need to set these before running the test:
	// export AWS_REGION="us-east-1"  (or your preferred region, e.g., us-west-2, eu-west-1)
	// export SES_SMTP_USERNAME="your-smtp-username"  (SMTP credentials from SES console)
	// export SES_SMTP_PASSWORD="your-smtp-password"  (SMTP credentials from SES console)
	// export SES_FROM_EMAIL="verified@yourdomain.com"  (must be verified in SES)
	// export SES_TO_EMAIL="recipient@example.com"

	region := "ap-southeast-2"
	smtpUsername := "AKIA2OCMXDPHSJ42XCHS"
	smtpPassword := "BI1iMRKkq1igmgQKYIb1h5M5c4Nc2xzePQXRvo4Cljya"
	fromEmail := "slhmy.zzy@outlook.com"
	toEmail := "slhmy.zzy@gmail.com"

	if region == "" || smtpUsername == "" || smtpPassword == "" || fromEmail == "" || toEmail == "" {
		t.Skip("Skipping SES test: required environment variables not set")
	}

	// Create SES mailer
	config := SESMailerConfig{
		Region:       region,
		SMTPUsername: smtpUsername,
		SMTPPassword: smtpPassword,
		FromEmail:    fromEmail,
		FromName:     "Auth Portal",
	}

	mailer, err := NewSESMailer(config)
	if err != nil {
		t.Fatalf("Failed to create SES mailer: %v", err)
	}

	// Test sending plain text verification code email
	t.Run("SendPlainTextVerificationCode", func(t *testing.T) {
		err := mailer.SendVerificationCodeEmail(
			toEmail,
			"123456",
			5,
		)
		if err != nil {
			t.Fatalf("Failed to send plain text email: %v", err)
		}
		t.Log("Plain text verification code email sent successfully!")
	})

	// Test sending HTML verification code email
	t.Run("SendHTMLVerificationCode", func(t *testing.T) {
		err := mailer.SendVerificationCodeEmailHTML(
			toEmail,
			"654321",
			10,
		)
		if err != nil {
			t.Fatalf("Failed to send HTML email: %v", err)
		}
		t.Log("HTML verification code email sent successfully!")
	})

	// Test sending custom email
	t.Run("SendCustomEmail", func(t *testing.T) {
		msg := EmailMessage{
			To:      []string{toEmail},
			Subject: "Test Email from Auth Portal",
			Body:    "This is a test email sent via AWS SES using SMTP.",
			IsHTML:  false,
		}
		err := mailer.SendEmail(msg)
		if err != nil {
			t.Fatalf("Failed to send custom email: %v", err)
		}
		t.Log("Custom email sent successfully!")
	})
}

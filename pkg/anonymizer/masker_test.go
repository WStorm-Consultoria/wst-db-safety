package anonymizer

import (
	"testing"
	"wst-db-safety/pkg/config"
)

func TestMasker(t *testing.T) {
	cfg := config.DefaultConfig()
	masker := NewMasker(cfg)

	// Test Column Sensitivity Detection
	t.Run("Column Sensitivity", func(t *testing.T) {
		sensitiveCols := []string{"email", "user_email", "cpf", "password_hash", "secret_token", "credit_card", "telefone_celular"}
		for _, col := range sensitiveCols {
			if !masker.IsSensitiveColumn(col) {
				t.Errorf("expected column %q to be flagged as sensitive", col)
			}
		}

		safeCols := []string{"id", "created_at", "title", "description", "quantity"}
		for _, col := range safeCols {
			if masker.IsSensitiveColumn(col) {
				t.Errorf("expected column %q to NOT be flagged as sensitive", col)
			}
		}
	})

	// Test Value Masking
	t.Run("Value Masking", func(t *testing.T) {
		// Entirely masked because of sensitive column name
		if val := masker.MaskValue("email", "john.doe@example.com"); val != "[REDACTED_PII]" {
			t.Errorf("expected sensitive column 'email' to be fully masked, got %v", val)
		}
		if val := masker.MaskValue("password", "supersecret123"); val != "[REDACTED_PII]" {
			t.Errorf("expected sensitive column 'password' to be fully masked, got %v", val)
		}

		// Non-sensitive column name, but contains PII pattern in text (should mask inline)
		textWithPII := "Please contact me at alice@gmail.com or CPF: 111.222.333-44"
		expectedMasked := "Please contact me at [REDACTED_PII] or CPF: [REDACTED_PII]"
		if val := masker.MaskValue("description", textWithPII); val != expectedMasked {
			t.Errorf("expected inline PII masking, got %q", val)
		}

		// Safe value unchanged
		safeVal := "This is a safe description without PII"
		if val := masker.MaskValue("description", safeVal); val != safeVal {
			t.Errorf("expected safe value to remain unchanged, got %v", val)
		}
	})
}

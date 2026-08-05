package config

import (
	"encoding/json"
	"os"
)

// Config holds the application configuration for security policies and database parameters.
type Config struct {
	DatabaseType     string   `json:"database_type"`     // "postgres" or "sqlite"
	ConnectionString string   `json:"connection_string"` // DSN or file path
	AllowDDL         bool     `json:"allow_ddl"`         // Whether to allow DROP/TRUNCATE
	PIIKeywords      []string `json:"pii_keywords"`      // Keywords to identify PII columns
	MaskString       string   `json:"mask_string"`       // Mask replacement (default: [REDACTED_PII])
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		DatabaseType: "sqlite",
		AllowDDL:     false,
		PIIKeywords:  []string{"email", "cpf", "password", "token", "secret", "credit_card", "telefone", "phone", "ssn"},
		MaskString:   "[REDACTED_PII]",
	}
}

// LoadConfig loads configuration from a JSON file path.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

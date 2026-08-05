package anonymizer

import (
	"regexp"
	"strings"
	"wst-db-safety/pkg/config"
)

// Masker handles PII masking based on column name matching and content regex patterns.
type Masker struct {
	cfg        *config.Config
	emailRegex *regexp.Regexp
	cpfRegex   *regexp.Regexp
	ssnRegex   *regexp.Regexp
}

// NewMasker creates a new instance of Masker.
func NewMasker(cfg *config.Config) *Masker {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Masker{
		cfg:        cfg,
		emailRegex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		cpfRegex:   regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
		ssnRegex:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	}
}

// IsSensitiveColumn checks if a column name matches any of the configured PII keywords.
func (m *Masker) IsSensitiveColumn(colName string) bool {
	colNameLower := strings.ToLower(colName)
	for _, kw := range m.cfg.PIIKeywords {
		if strings.Contains(colNameLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// MaskValue masks an entire value if the column is sensitive, or performs inline regex masking if it is a string.
func (m *Masker) MaskValue(colName string, val interface{}) interface{} {
	if val == nil {
		return nil
	}

	// If column is sensitive, redact the entire value
	if m.IsSensitiveColumn(colName) {
		return m.cfg.MaskString
	}

	// If the value is a string, check for inline PII leakage
	if str, ok := val.(string); ok {
		return m.MaskText(str)
	}

	return val
}

// MaskText scans string content for inline PII patterns (email, CPF, SSN) and replaces them.
func (m *Masker) MaskText(text string) string {
	// Mask emails
	text = m.emailRegex.ReplaceAllString(text, m.cfg.MaskString)
	// Mask CPFs
	text = m.cpfRegex.ReplaceAllString(text, m.cfg.MaskString)
	// Mask SSNs
	text = m.ssnRegex.ReplaceAllString(text, m.cfg.MaskString)
	return text
}

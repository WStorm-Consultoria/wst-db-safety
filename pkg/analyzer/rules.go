package analyzer

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/xwb1989/sqlparser"
	"wst-db-safety/pkg/config"
)

// ValidateQuery analyzes the SQL query against safety rules.
// It returns nil if the query is safe, or a validation error if it is blocked.
func ValidateQuery(query string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Split the query by semicolons to validate each statement independently.
	statements := splitStatements(query)
	for _, stmtStr := range statements {
		stmtStr = strings.TrimSpace(stmtStr)
		if stmtStr == "" {
			continue
		}

		// 1. Try to parse using strict AST parser
		stmt, err := ParseQuery(stmtStr)
		if err == nil {
			if err := ValidateAST(stmt, cfg); err != nil {
				return err
			}
			continue
		}

		// 2. If AST parsing fails, fallback to lexical validation
		if err := ValidateFallback(stmtStr, cfg); err != nil {
			return err
		}
	}

	return nil
}

// ValidateAST validates an AST statement representation of a query.
func ValidateAST(stmt sqlparser.Statement, cfg *config.Config) error {
	switch s := stmt.(type) {
	case *sqlparser.Delete:
		if s.Where == nil {
			return errors.New("BLOCKED: DELETE command missing WHERE clause")
		}
	case *sqlparser.Update:
		if s.Where == nil {
			return errors.New("BLOCKED: UPDATE command missing WHERE clause")
		}
	case *sqlparser.DDL:
		action := strings.ToLower(s.Action)
		if (action == "drop" || action == "truncate") && !cfg.AllowDDL {
			return fmt.Errorf("BLOCKED: %s command is restricted", strings.ToUpper(action))
		}
	case *sqlparser.DBDDL:
		action := strings.ToLower(s.Action)
		if (action == "drop" || action == "create") && !cfg.AllowDDL {
			return fmt.Errorf("BLOCKED: %s command is restricted", strings.ToUpper(action))
		}
	}
	return nil
}

type tokenType int

const (
	tokenWord tokenType = iota
	tokenParenOpen
	tokenParenClose
	tokenSemicolon
	tokenOther
)

type token struct {
	typ   tokenType
	value string
}

// tokenize splits the SQL query into tokens while ignoring comments and string literals.
func tokenize(sql string) []token {
	var tokens []token
	runes := []rune(sql)
	n := len(runes)
	i := 0

	for i < n {
		r := runes[i]

		// 1. Single-line comment
		if r == '-' && i+1 < n && runes[i+1] == '-' {
			i += 2
			for i < n && runes[i] != '\n' {
				i++
			}
			continue
		}

		// 2. Block comment
		if r == '/' && i+1 < n && runes[i+1] == '*' {
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				i++
			}
			i += 2 // skip */
			continue
		}

		// 3. String literal single-quoted
		if r == '\'' {
			i++
			for i < n {
				if runes[i] == '\'' {
					if i+1 < n && runes[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// 4. Double-quoted identifier
		if r == '"' {
			i++
			for i < n {
				if runes[i] == '"' {
					i++
					break
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// 5. Postgres dollar-quoted strings
		if r == '$' {
			startTagIdx := i
			i++
			for i < n && runes[i] != '$' && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
				i++
			}
			if i < n && runes[i] == '$' {
				i++
				tag := string(runes[startTagIdx:i])
				for i < n {
					if i+len(tag) <= n && string(runes[i:i+len(tag)]) == tag {
						i += len(tag)
						break
					}
					i++
				}
				continue
			}
			tokens = append(tokens, token{typ: tokenOther, value: "$"})
			continue
		}

		// 6. Parentheses and semicolons
		if r == '(' {
			tokens = append(tokens, token{typ: tokenParenOpen, value: "("})
			i++
			continue
		}
		if r == ')' {
			tokens = append(tokens, token{typ: tokenParenClose, value: ")"})
			i++
			continue
		}
		if r == ';' {
			tokens = append(tokens, token{typ: tokenSemicolon, value: ";"})
			i++
			continue
		}

		// 7. Word characters
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			start := i
			for i < n && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
				i++
			}
			word := string(runes[start:i])
			tokens = append(tokens, token{typ: tokenWord, value: word})
			continue
		}

		// 8. Other characters
		i++
	}

	return tokens
}

// splitStatements splits query statements by semicolon at depth 0, ignoring strings/comments.
func splitStatements(query string) []string {
	var statements []string
	runes := []rune(query)
	n := len(runes)
	i := 0
	depth := 0
	lastIdx := 0

	for i < n {
		r := runes[i]

		// 1. Single-line comment
		if r == '-' && i+1 < n && runes[i+1] == '-' {
			i += 2
			for i < n && runes[i] != '\n' {
				i++
			}
			continue
		}

		// 2. Block comment
		if r == '/' && i+1 < n && runes[i+1] == '*' {
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}

		// 3. String literal
		if r == '\'' {
			i++
			for i < n {
				if runes[i] == '\'' {
					if i+1 < n && runes[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// 4. Double-quoted
		if r == '"' {
			i++
			for i < n {
				if runes[i] == '"' {
					i++
					break
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// 5. Postgres dollar-quoted
		if r == '$' {
			startTagIdx := i
			i++
			for i < n && runes[i] != '$' && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
				i++
			}
			if i < n && runes[i] == '$' {
				i++
				tag := string(runes[startTagIdx:i])
				for i < n {
					if i+len(tag) <= n && string(runes[i:i+len(tag)]) == tag {
						i += len(tag)
						break
					}
					i++
				}
				continue
			}
			continue
		}

		// Track depth
		if r == '(' {
			depth++
		} else if r == ')' {
			depth--
		}

		// Split on semicolon at depth 0
		if r == ';' && depth == 0 {
			statements = append(statements, string(runes[lastIdx:i]))
			lastIdx = i + 1
		}

		i++
	}

	if lastIdx < n {
		statements = append(statements, string(runes[lastIdx:]))
	}

	return statements
}

// ValidateFallback tokenizes and validates queries that fail strict AST parsing.
func ValidateFallback(statement string, cfg *config.Config) error {
	tokens := tokenize(statement)

	// Check DDL restrictions first (DROP / TRUNCATE)
	if !cfg.AllowDDL {
		for _, t := range tokens {
			if t.typ == tokenWord {
				val := strings.ToLower(t.value)
				if val == "drop" || val == "truncate" {
					return fmt.Errorf("BLOCKED: %s command is restricted", strings.ToUpper(val))
				}
			}
		}
	}

	// Check DELETE and UPDATE queries
	type stmtMarker struct {
		typ   string // "DELETE" or "UPDATE"
		depth int
		found bool
	}

	var activeMarkers []stmtMarker
	depth := 0

	for _, t := range tokens {
		switch t.typ {
		case tokenParenOpen:
			depth++
		case tokenParenClose:
			// If depth is closing, check if any active markers at this depth did not find WHERE
			for j := len(activeMarkers) - 1; j >= 0; j-- {
				if activeMarkers[j].depth == depth && !activeMarkers[j].found {
					return fmt.Errorf("BLOCKED: %s command missing WHERE clause", activeMarkers[j].typ)
				}
			}
			// Remove markers at this depth
			var remaining []stmtMarker
			for _, m := range activeMarkers {
				if m.depth < depth {
					remaining = append(remaining, m)
				}
			}
			activeMarkers = remaining
			depth--

		case tokenWord:
			val := strings.ToUpper(t.value)
			if val == "DELETE" || val == "UPDATE" {
				activeMarkers = append(activeMarkers, stmtMarker{
					typ:   val,
					depth: depth,
					found: false,
				})
			} else if val == "WHERE" {
				// Mark all active markers at the current depth D as found
				for j := range activeMarkers {
					if activeMarkers[j].depth == depth {
						activeMarkers[j].found = true
					}
				}
			}
		}
	}

	// At the end of the statement, any active marker that didn't find WHERE is blocked
	for _, m := range activeMarkers {
		if !m.found {
			return fmt.Errorf("BLOCKED: %s command missing WHERE clause", m.typ)
		}
	}

	return nil
}

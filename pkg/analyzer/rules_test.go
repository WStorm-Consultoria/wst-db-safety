package analyzer

import (
	"strings"
	"testing"
	"wst-db-safety/pkg/config"
)

func TestValidateQuery(t *testing.T) {
	defaultCfg := config.DefaultConfig()
	allowDDLCfg := config.DefaultConfig()
	allowDDLCfg.AllowDDL = true

	tests := []struct {
		name      string
		query     string
		cfg       *config.Config
		wantBlock bool
		errMsg    string
	}{
		// Basic SELECT tests
		{
			name:      "Simple SELECT",
			query:     "SELECT * FROM users",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "SELECT with WHERE",
			query:     "SELECT * FROM users WHERE id = 1",
			cfg:       defaultCfg,
			wantBlock: false,
		},

		// DELETE tests
		{
			name:      "DELETE with WHERE (Allowed)",
			query:     "DELETE FROM users WHERE id = 1",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "DELETE without WHERE (Blocked)",
			query:     "DELETE FROM users",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "DELETE lowercase without WHERE (Blocked)",
			query:     "delete from users",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "DELETE with subquery WHERE (Allowed)",
			query:     "DELETE FROM users WHERE id IN (SELECT user_id FROM orders)",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "DELETE with table alias and WHERE (Allowed)",
			query:     "DELETE u FROM users u WHERE u.id = 1",
			cfg:       defaultCfg,
			wantBlock: false,
		},

		// UPDATE tests
		{
			name:      "UPDATE with WHERE (Allowed)",
			query:     "UPDATE users SET name = 'John' WHERE id = 1",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "UPDATE without WHERE (Blocked)",
			query:     "UPDATE users SET name = 'John'",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: UPDATE command missing WHERE clause",
		},
		{
			name:      "UPDATE lowercase without WHERE (Blocked)",
			query:     "update users set name = 'John'",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: UPDATE command missing WHERE clause",
		},

		// DDL tests
		{
			name:      "DROP TABLE by default (Blocked)",
			query:     "DROP TABLE users",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DROP command is restricted",
		},
		{
			name:      "DROP TABLE with AllowDDL = true (Allowed)",
			query:     "DROP TABLE users",
			cfg:       allowDDLCfg,
			wantBlock: false,
		},
		{
			name:      "DROP DATABASE by default (Blocked)",
			query:     "DROP DATABASE production",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DROP command is restricted",
		},
		{
			name:      "TRUNCATE TABLE by default (Blocked)",
			query:     "TRUNCATE TABLE logs",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: TRUNCATE command is restricted",
		},
		{
			name:      "TRUNCATE TABLE with AllowDDL = true (Allowed)",
			query:     "TRUNCATE TABLE logs",
			cfg:       allowDDLCfg,
			wantBlock: false,
		},

		// Fallback scanning / dialect-specific parser failures (CTE, RETURNING, etc.)
		{
			name:      "CTE DELETE without WHERE (Blocked)",
			query:     "WITH deleted AS (DELETE FROM users) SELECT * FROM deleted",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "CTE DELETE with WHERE (Allowed)",
			query:     "WITH deleted AS (DELETE FROM users WHERE id = 1) SELECT * FROM deleted",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "UPDATE with RETURNING but no WHERE (Blocked)",
			query:     "UPDATE users SET name = 'John' RETURNING *",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: UPDATE command missing WHERE clause",
		},
		{
			name:      "UPDATE with RETURNING and WHERE (Allowed)",
			query:     "UPDATE users SET name = 'John' WHERE id = 1 RETURNING *",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "UPDATE with nested WHERE but outer lacks WHERE (Blocked)",
			query:     "UPDATE users SET val = (SELECT count(*) FROM orders WHERE active = 1)",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: UPDATE command missing WHERE clause",
		},
		{
			name:      "UPDATE with nested WHERE and outer WHERE (Allowed)",
			query:     "UPDATE users SET val = (SELECT count(*) FROM orders WHERE active = 1) WHERE id = 2",
			cfg:       defaultCfg,
			wantBlock: false,
		},

		// Multi-statement queries (separated by semicolon)
		{
			name:      "Multi-statement with unsafe delete (Blocked)",
			query:     "SELECT * FROM users; DELETE FROM logs;",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "Multi-statement safe (Allowed)",
			query:     "SELECT * FROM users; DELETE FROM logs WHERE id = 1;",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "Multi-statement with restricted DDL (Blocked)",
			query:     "SELECT * FROM users; DROP TABLE logs;",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DROP command is restricted",
		},

		// Comment/String literal bypass attempts
		{
			name:      "DELETE inside string literal (Allowed)",
			query:     "INSERT INTO sql_queries (query_text) VALUES ('DELETE FROM users')",
			cfg:       defaultCfg,
			wantBlock: false,
		},
		{
			name:      "DELETE with -- comment containing WHERE (Blocked)",
			query:     "DELETE FROM users -- WHERE id = 1",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "DELETE with /* comment */ containing WHERE (Blocked)",
			query:     "DELETE FROM users /* WHERE id = 1 */",
			cfg:       defaultCfg,
			wantBlock: true,
			errMsg:    "BLOCKED: DELETE command missing WHERE clause",
		},
		{
			name:      "DROP keyword inside string (Allowed)",
			query:     "SELECT * FROM tbl WHERE name = 'drop table'",
			cfg:       defaultCfg,
			wantBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQuery(tt.query, tt.cfg)
			if tt.wantBlock {
				if err == nil {
					t.Errorf("expected query %q to be blocked, but it was allowed", tt.query)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected query %q to be allowed, but got error: %v", tt.query, err)
				}
			}
		})
	}
}

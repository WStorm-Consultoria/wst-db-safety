package analyzer

import (
	"github.com/xwb1989/sqlparser"
)

// ParseQuery parses a SQL query string using the sqlparser AST library.
func ParseQuery(query string) (sqlparser.Statement, error) {
	return sqlparser.Parse(query)
}

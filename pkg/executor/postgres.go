package executor

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresDriver implements the Driver interface for PostgreSQL databases.
type PostgresDriver struct {
	db *sql.DB
}

// NewPostgresDriver initializes a connection to a PostgreSQL database.
func NewPostgresDriver(connStr string) (*PostgresDriver, error) {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &PostgresDriver{db: db}, nil
}

// Close closes the database connection.
func (d *PostgresDriver) Close() error {
	return d.db.Close()
}

// GetSchema extracts table and column metadata from PostgreSQL information_schema.
func (d *PostgresDriver) GetSchema() ([]TableSchema, error) {
	query := `
		SELECT table_name, column_name, data_type 
		FROM information_schema.columns 
		WHERE table_schema = 'public'
		ORDER BY table_name, ordinal_position
	`
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tableMap := make(map[string][]ColumnSchema)
	var tableOrder []string

	for rows.Next() {
		var tableName, columnName, dataType string
		if err := rows.Scan(&tableName, &columnName, &dataType); err != nil {
			return nil, err
		}
		if _, exists := tableMap[tableName]; !exists {
			tableOrder = append(tableOrder, tableName)
		}
		tableMap[tableName] = append(tableMap[tableName], ColumnSchema{
			ColumnName: columnName,
			DataType:   dataType,
		})
	}

	var schemas []TableSchema
	for _, name := range tableOrder {
		schemas = append(schemas, TableSchema{
			TableName: name,
			Columns:   tableMap[name],
		})
	}

	return schemas, nil
}

// DryRun executes the query inside a transaction with EXPLAIN ANALYZE, and rolls back.
func (d *PostgresDriver) DryRun(query string) (*DryRunResult, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // Compulsory Rollback

	// 1. Fetch Explain Plan
	explainQuery := fmt.Sprintf("EXPLAIN ANALYZE %s", query)
	explainRows, err := tx.Query(explainQuery)
	var planStr string
	if err == nil {
		defer explainRows.Close()
		var lines []string
		for explainRows.Next() {
			var line string
			if err := explainRows.Scan(&line); err == nil {
				lines = append(lines, line)
			}
		}
		planStr = strings.Join(lines, "\n")
	} else {
		planStr = fmt.Sprintf("Explain failed: %v", err)
	}

	// 2. Execute query in sandbox transaction to count affected rows
	trimmed := strings.ToUpper(strings.TrimSpace(query))
	isSelect := strings.HasPrefix(trimmed, "SELECT")

	var rowsAffected int64
	if isSelect {
		resRows, err := tx.Query(query)
		if err != nil {
			return nil, err
		}
		defer resRows.Close()
		var count int64
		for resRows.Next() {
			count++
		}
		rowsAffected = count
	} else {
		res, err := tx.Exec(query)
		if err != nil {
			return nil, err
		}
		rowsAffected, _ = res.RowsAffected()
	}

	return &DryRunResult{
		Query:         query,
		ExecutionPlan: planStr,
		RowsAffected:  rowsAffected,
	}, nil
}

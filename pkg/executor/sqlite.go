package executor

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteDriver implements the Driver interface for SQLite databases.
type SQLiteDriver struct {
	db *sql.DB
}

// NewSQLiteDriver initializes a connection to a SQLite database.
func NewSQLiteDriver(connStr string) (*SQLiteDriver, error) {
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteDriver{db: db}, nil
}

// Close closes the database connection.
func (d *SQLiteDriver) Close() error {
	return d.db.Close()
}

// GetSchema extracts table and column metadata from SQLite system catalogs.
func (d *SQLiteDriver) GetSchema() ([]TableSchema, error) {
	rows, err := d.db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []TableSchema
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, TableSchema{TableName: name})
	}

	for i, t := range tables {
		colRows, err := d.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", t.TableName))
		if err != nil {
			return nil, err
		}

		var cols []ColumnSchema
		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltVal interface{}
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dfltVal, &pk); err != nil {
				colRows.Close()
				return nil, err
			}
			cols = append(cols, ColumnSchema{
				ColumnName: name,
				DataType:   ctype,
			})
		}
		colRows.Close()
		tables[i].Columns = cols
	}

	return tables, nil
}

// DryRun executes the query inside a transaction, fetches execution plans, and guarantees rollback.
func (d *SQLiteDriver) DryRun(query string) (*DryRunResult, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // Compulsory Rollback

	// 1. Fetch Explain Plan
	explainQuery := fmt.Sprintf("EXPLAIN QUERY PLAN %s", query)
	explainRows, err := tx.Query(explainQuery)
	var planStr string
	if err == nil {
		defer explainRows.Close()
		cols, _ := explainRows.Columns()
		vals := make([]interface{}, len(cols))
		valPtrs := make([]interface{}, len(cols))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}

		var lines []string
		for explainRows.Next() {
			if err := explainRows.Scan(valPtrs...); err == nil {
				if len(vals) > 0 {
					detailVal := vals[len(vals)-1]
					if detailVal != nil {
						lines = append(lines, fmt.Sprintf("%v", detailVal))
					} else {
						lines = append(lines, fmt.Sprintf("%v", vals))
					}
				}
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

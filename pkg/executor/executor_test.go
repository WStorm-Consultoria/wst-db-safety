package executor

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteExecutorIntegration(t *testing.T) {
	// Initialize in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}
	defer db.Close()

	// Create test table
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			email TEXT,
			password TEXT
		);
	`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	// Insert initial seed data
	_, err = db.Exec(`
		INSERT INTO users (name, email, password) VALUES 
		('Alice', 'alice@example.com', 'alicepwd123'),
		('Bob', 'bob@example.com', 'bobpwd456');
	`)
	if err != nil {
		t.Fatalf("failed to seed table: %v", err)
	}

	// Create driver
	drv := &SQLiteDriver{db: db}

	// 1. Verify schema extraction
	t.Run("GetSchema", func(t *testing.T) {
		schemas, err := drv.GetSchema()
		if err != nil {
			t.Fatalf("GetSchema failed: %v", err)
		}

		if len(schemas) != 1 {
			t.Fatalf("expected 1 table schema, got %d", len(schemas))
		}

		if schemas[0].TableName != "users" {
			t.Errorf("expected table name 'users', got %s", schemas[0].TableName)
		}

		expectedCols := map[string]bool{
			"id":       true,
			"name":     true,
			"email":    true,
			"password": true,
		}

		for _, col := range schemas[0].Columns {
			if !expectedCols[col.ColumnName] {
				t.Errorf("unexpected column %s in schema", col.ColumnName)
			}
		}
	})

	// 2. Verify DryRun UPDATE rollback behavior
	t.Run("DryRun UPDATE Rollback", func(t *testing.T) {
		res, err := drv.DryRun("UPDATE users SET name = 'New Alice' WHERE id = 1")
		if err != nil {
			t.Fatalf("DryRun failed: %v", err)
		}

		if res.RowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", res.RowsAffected)
		}

		if res.ExecutionPlan == "" {
			t.Error("expected non-empty execution plan")
		}

		// Query the database to verify changes were NOT saved (rollback worked)
		var name string
		err = db.QueryRow("SELECT name FROM users WHERE id = 1").Scan(&name)
		if err != nil {
			t.Fatalf("failed to query row: %v", err)
		}

		if name != "Alice" {
			t.Errorf("rollback failed: database contains modified value %q, expected %q", name, "Alice")
		}
	})

	// 3. Verify DryRun DELETE rollback behavior
	t.Run("DryRun DELETE Rollback", func(t *testing.T) {
		res, err := drv.DryRun("DELETE FROM users WHERE id = 2")
		if err != nil {
			t.Fatalf("DryRun failed: %v", err)
		}

		if res.RowsAffected != 1 {
			t.Errorf("expected 1 row affected, got %d", res.RowsAffected)
		}

		// Query the database to verify Bob is still there
		var name string
		err = db.QueryRow("SELECT name FROM users WHERE id = 2").Scan(&name)
		if err != nil {
			t.Fatalf("failed to query row: %v", err)
		}

		if name != "Bob" {
			t.Errorf("rollback failed: deleted user Bob still missing from DB, got %q", name)
		}
	})
}

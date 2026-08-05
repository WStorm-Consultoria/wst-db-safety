# DB Safety (`wst-db-safety`)

DB Safety is a secure database gateway proxy and Model Context Protocol (MCP) server that acts as a guardrail between AI assistants (Claude Desktop, Cursor, VS Code) and relational databases (PostgreSQL, SQLite, Supabase).

It prevents data leakage, PII exposure, and accidental execution of hazardous/destructive SQL statements through AST query analysis, fail-safe regex fallback scanning, actual-execution sandboxes with compulsory rollback, and schema sanitization.

---

## Key Features

1. **AST Query Guardrails**: Analyzes SQL query structures before execution to block unsafe `DELETE` or `UPDATE` statements lacking a `WHERE` clause, and blocks restricted DDL commands like `DROP TABLE`, `DROP DATABASE`, and `TRUNCATE` unless explicitly configured.
2. **Dynamic PII Masker**: Sanitizes sensitive data columns based on customizable keywords (e.g., `email`, `cpf`, `password`) and scans text bodies with regex to redact emails, CPFs, and SSNs.
3. **Sandbox Dry-Run Engine**: Opens a dedicated transaction, executes statements to measure impact and retrieve plans (using `EXPLAIN ANALYZE` or `EXPLAIN QUERY PLAN`), and guarantees a `tx.Rollback()` via deferred routines.
4. **JSON-RPC 2.0 MCP Server**: Exposes tools to AI assistants via stdin/stdout transport.

---

## Quick Start & Compilation

Make sure Go 1.22+ is installed on your system.

### Build Executable
```bash
go build -o wst-db-safety cmd/db-safety/main.go
```

### Run Tests and Coverage
```bash
go test -v -race -coverprofile=coverage.out ./...
```

---

## Configuration

You can configure DB Safety using a JSON configuration file. Create a file called `db-safety-config.json`:

```json
{
  "database_type": "sqlite",
  "connection_string": "dev_database.db",
  "allow_ddl": false,
  "pii_keywords": ["email", "cpf", "password", "token", "secret", "credit_card", "telefone"],
  "mask_string": "[REDACTED_PII]"
}
```

---

## MCP Tool Reference

DB Safety exposes three tools to AI clients:

### 1. `inspect_query`
Validates a SQL query structure against the guardrails rules statically without interacting with the database.

- **Arguments**: `query` (string)
- **Sample Result**:
  ```
  Query is safe. AST and syntax checks passed.
  ```
  or
  ```
  BLOCKED: DELETE command missing WHERE clause
  ```

### 2. `dry_run_query`
Safely runs the query inside a transaction sandbox to obtain the execution plan and the number of affected rows, then performs an unconditional rollback.

- **Arguments**: `query` (string)
- **Sample Result**:
  ```markdown
  ### Dry-Run Report
  **Query**:
  ```sql
    UPDATE users SET status = 'active' WHERE id = 42
  ```
  
  **Rows Affected**: 1
  
  #### Execution Plan
  ```
  SEARCH table users USING INTEGER PRIMARY KEY (rowid=42)
  ```
  
  > [!NOTE]
  > All changes have been completely rolled back. No database modifications were committed.
  ```

### 3. `get_safe_schema`
Extracts the database schema (tables and columns) while flagging and masking column metadata containing sensitive PII fields.

- **Arguments**: None
- **Sample Result**:
  ```markdown
  ### Database Schema (PII Sanitized)
  
  #### Table: `users`
  | Column | Data Type | PII Flag | Status |
  | :--- | :--- | :--- | :--- |
  | `id` | `INTEGER` | No | Normal |
  | `name` | `TEXT` | No | Normal |
  | `email` | `TEXT` | Yes | [REDACTED] |
  | `password` | `TEXT` | Yes | [REDACTED] |
  ```

---

## Client Integration Guide

To connect DB Safety to your preferred AI environment:

### Claude Desktop
Add DB Safety to your Claude configuration file (located at `~/.config/Claude/claude_desktop_config.json` on Linux/macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "db-safety": {
      "command": "/absolute/path/to/wst-db-safety",
      "args": [
        "--config", "/absolute/path/to/db-safety-config.json"
      ]
    }
  }
}
```

### Cursor / VS Code
If using Cursor, go to **Settings > Features > MCP**, click **+ Add New MCP Server**, and enter:
- **Name**: `db-safety`
- **Type**: `command`
- **Command**: `/absolute/path/to/wst-db-safety --db-type sqlite --conn-str /absolute/path/to/db.sqlite`

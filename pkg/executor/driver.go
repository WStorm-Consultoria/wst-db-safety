package executor

// TableSchema defines the metadata for a database table.
type TableSchema struct {
	TableName string         `json:"table_name"`
	Columns   []ColumnSchema `json:"columns"`
}

// ColumnSchema defines the metadata for a column inside a table.
type ColumnSchema struct {
	ColumnName string `json:"column_name"`
	DataType   string `json:"data_type"`
	IsPII      bool   `json:"is_pii"`
}

// DryRunResult holds the execution plan and estimated or actual metrics.
type DryRunResult struct {
	Query         string `json:"query"`
	ExecutionPlan string `json:"execution_plan"`
	RowsAffected  int64  `json:"rows_affected"`
}

// Driver represents a database adapter wrapper.
type Driver interface {
	Close() error
	GetSchema() ([]TableSchema, error)
	DryRun(query string) (*DryRunResult, error)
}

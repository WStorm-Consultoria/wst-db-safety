package main

import (
	"flag"
	"log"
	"os"

	"wst-db-safety/pkg/config"
	"wst-db-safety/pkg/executor"
	"wst-db-safety/pkg/mcp"
)

func main() {
	// 1. CLI Flags
	configPath := flag.String("config", "", "Path to config JSON file")
	dbType := flag.String("db-type", "", "Database type ('postgres' or 'sqlite')")
	connStr := flag.String("conn-str", "", "Database connection string or file path")
	allowDDL := flag.Bool("allow-ddl", false, "Override configuration to allow DDL statements")
	flag.Parse()

	// Redirect standard log to stderr to avoid polluting stdout (which is used by MCP JSON-RPC protocol)
	log.SetOutput(os.Stderr)
	log.SetPrefix("[db-safety-main] ")

	// 2. Load Configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// 3. Override Configuration via CLI Flags if provided
	if *dbType != "" {
		cfg.DatabaseType = *dbType
	}
	if *connStr != "" {
		cfg.ConnectionString = *connStr
	}
	// Only override if the flag is explicitly set or if we want to enable it
	if *allowDDL {
		cfg.AllowDDL = true
	}

	// Validate configuration parameters
	if cfg.ConnectionString == "" {
		log.Fatal("Error: Connection string must not be empty. Please specify via config or --conn-str flag.")
	}

	// 4. Initialize Database Driver Adapter
	var driver executor.Driver
	switch cfg.DatabaseType {
	case "sqlite", "sqlite3":
		driver, err = executor.NewSQLiteDriver(cfg.ConnectionString)
		if err != nil {
			log.Fatalf("Error initializing SQLite driver: %v", err)
		}
	case "postgres", "postgresql":
		driver, err = executor.NewPostgresDriver(cfg.ConnectionString)
		if err != nil {
			log.Fatalf("Error initializing Postgres driver: %v", err)
		}
	default:
		log.Fatalf("Error: Unsupported database type %q. Supported types: 'postgres', 'sqlite'.", cfg.DatabaseType)
	}
	defer driver.Close()

	log.Printf("Starting DB Safety Gateway MCP Server using database type: %s...", cfg.DatabaseType)

	// 5. Run MCP Server stdio protocol loop
	server := mcp.NewServer(cfg, driver, os.Stdin, os.Stdout)
	if err := server.Start(); err != nil {
		log.Fatalf("Server loop terminated with error: %v", err)
	}

	log.Println("Server shut down cleanly.")
}

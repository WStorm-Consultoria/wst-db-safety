package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"wst-db-safety/pkg/analyzer"
	"wst-db-safety/pkg/anonymizer"
	"wst-db-safety/pkg/config"
	"wst-db-safety/pkg/executor"
)

// Server coordinates the MCP stdio protocol loop and resolves tool requests.
type Server struct {
	cfg    *config.Config
	driver executor.Driver
	masker *anonymizer.Masker
	logger *log.Logger
	in     io.Reader
	out    io.Writer
}

// NewServer initializes a new Server.
func NewServer(cfg *config.Config, drv executor.Driver, in io.Reader, out io.Writer) *Server {
	logger := log.New(os.Stderr, "[db-safety] ", log.LstdFlags)
	return &Server{
		cfg:    cfg,
		driver: drv,
		masker: anonymizer.NewMasker(cfg),
		logger: logger,
		in:     in,
		out:    out,
	}
}

// Start runs the read/write JSON-RPC protocol loop on stdio.
func (s *Server) Start() error {
	reader := bufio.NewReader(s.in)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		s.logger.Printf("Received: %s", line)

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(nil, CodeParseError, "Parse error", nil)
			continue
		}

		if req.ID == nil {
			s.handleNotification(req.Method, req.Params)
			continue
		}

		s.handleRequest(&req)
	}
}

func (s *Server) sendResponse(id *json.RawMessage, result interface{}) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		s.logger.Printf("Error marshaling response: %v", err)
		return
	}
	s.out.Write(append(data, '\n'))
}

func (s *Server) sendError(id *json.RawMessage, code int, message string, data interface{}) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		s.logger.Printf("Error marshaling error response: %v", err)
		return
	}
	s.out.Write(append(raw, '\n'))
}

func (s *Server) handleRequest(req *Request) {
	switch req.Method {
	case "initialize":
		s.sendResponse(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "db-safety",
				"version": "1.0.0",
			},
		})

	case "tools/list":
		s.sendResponse(req.ID, map[string]interface{}{
			"tools": []map[string]interface{}{
				{
					"name":        "inspect_query",
					"description": "Analyzes the syntax and runs guardrails validation on the SQL query without executing it.",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"query": map[string]interface{}{
								"type":        "string",
								"description": "SQL query to validate",
							},
						},
						"required": []string{"query"},
					},
				},
				{
					"name":        "dry_run_query",
					"description": "Executes the query inside a transaction sandbox, returns the execution plan and rows affected, then rolls back.",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"query": map[string]interface{}{
								"type":        "string",
								"description": "SQL query to dry-run",
							},
						},
						"required": []string{"query"},
					},
				},
				{
					"name":        "get_safe_schema",
					"description": "Extracts the schema of all public tables with sensitive PII columns identified and sanitized.",
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
					},
				},
			},
		})

	case "tools/call":
		s.handleToolCall(req)

	default:
		s.sendError(req.ID, CodeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method), nil)
	}
}

type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError"`
}

func (s *Server) handleToolCall(req *Request) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, CodeInvalidParams, "Invalid params", nil)
		return
	}

	switch params.Name {
	case "inspect_query":
		var args struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			s.sendError(req.ID, CodeInvalidParams, "Invalid arguments", nil)
			return
		}

		err := analyzer.ValidateQuery(args.Query, s.cfg)
		if err != nil {
			s.sendResponse(req.ID, ToolCallResult{
				Content: []TextContent{{
					Type: "text",
					Text: fmt.Sprintf("BLOCKED: %v", err),
				}},
				IsError: true,
			})
			return
		}

		s.sendResponse(req.ID, ToolCallResult{
			Content: []TextContent{{
				Type: "text",
				Text: "Query is safe. AST and syntax checks passed.",
			}},
			IsError: false,
		})

	case "dry_run_query":
		var args struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			s.sendError(req.ID, CodeInvalidParams, "Invalid arguments", nil)
			return
		}

		// Validate query before DryRun execution
		err := analyzer.ValidateQuery(args.Query, s.cfg)
		if err != nil {
			s.sendResponse(req.ID, ToolCallResult{
				Content: []TextContent{{
					Type: "text",
					Text: fmt.Sprintf("BLOCKED: %v", err),
				}},
				IsError: true,
			})
			return
		}

		res, err := s.driver.DryRun(args.Query)
		if err != nil {
			s.sendResponse(req.ID, ToolCallResult{
				Content: []TextContent{{
					Type: "text",
					Text: fmt.Sprintf("Execution Error: %v", err),
				}},
				IsError: true,
			})
			return
		}

		mdReport := fmt.Sprintf(`### Dry-Run Report
**Query**:
%s

**Rows Affected**: %d

#### Execution Plan
%s

> [!NOTE]
> All changes have been completely rolled back. No database modifications were committed.
`, indentQuery(res.Query), res.RowsAffected, formatPlan(res.ExecutionPlan))

		s.sendResponse(req.ID, ToolCallResult{
			Content: []TextContent{{
				Type: "text",
				Text: mdReport,
			}},
			IsError: false,
		})

	case "get_safe_schema":
		schemas, err := s.driver.GetSchema()
		if err != nil {
			s.sendResponse(req.ID, ToolCallResult{
				Content: []TextContent{{
					Type: "text",
					Text: fmt.Sprintf("Schema retrieval failed: %v", err),
				}},
				IsError: true,
			})
			return
		}

		var builder strings.Builder
		builder.WriteString("### Database Schema (PII Sanitized)\n\n")

		for _, t := range schemas {
			builder.WriteString(fmt.Sprintf("#### Table: `%s`\n", t.TableName))
			builder.WriteString("| Column | Data Type | PII Flag | Status |\n")
			builder.WriteString("| :--- | :--- | :--- | :--- |\n")
			for _, col := range t.Columns {
				isPII := s.masker.IsSensitiveColumn(col.ColumnName)
				piiLabel := "No"
				statusLabel := "Normal"
				if isPII {
					piiLabel = "Yes"
					statusLabel = "[REDACTED]"
				}
				builder.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n", col.ColumnName, col.DataType, piiLabel, statusLabel))
			}
			builder.WriteString("\n")
		}

		s.sendResponse(req.ID, ToolCallResult{
			Content: []TextContent{{
				Type: "text",
				Text: builder.String(),
			}},
			IsError: false,
		})

	default:
		s.sendError(req.ID, CodeMethodNotFound, fmt.Sprintf("Tool not found: %s", params.Name), nil)
	}
}

func indentQuery(q string) string {
	lines := strings.Split(q, "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return "```sql\n" + strings.Join(lines, "\n") + "\n```"
}

func formatPlan(plan string) string {
	if plan == "" {
		return "_No execution plan returned._"
	}
	return "```\n" + plan + "\n```"
}

func (s *Server) handleNotification(method string, params json.RawMessage) {
	s.logger.Printf("Notification received: %s", method)
}

package compiler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var (
	runtimeRouteDeclaration = regexp.MustCompile(`^api ([A-Za-z]+) "([^"]+)" do$`)
	runtimeDatabaseEnv      = regexp.MustCompile(`^db connect env "([A-Z_][A-Z0-9_]*)"$`)
	runtimeAssignment       = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*=\s*(.+)$`)
	runtimeInsertCall       = regexp.MustCompile(`^db\.insert\("([^"]+)",\s*(.+)\)$`)
	runtimeUpdateCall       = regexp.MustCompile(`^db\.update\("([^"]+)",\s*(.+?),\s*(.+)\)$`)
	runtimeDeleteCall       = regexp.MustCompile(`^db\.delete\("([^"]+)",\s*(.+)\)$`)
	runtimeJSONReturn       = regexp.MustCompile(`^return (.+) json$`)
	runtimeStatusReturn     = regexp.MustCompile(`^return (.+) status ([0-9]+)$`)
	runtimePasswordHash     = regexp.MustCompile(`^pbkdf2_sha256\$([0-9]+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$`)
)

const (
	passwordHashIterations = 210_000
	passwordHashLength     = 32
	jwtLifetime            = time.Hour
	maxRequestBodyBytes    = 1 << 20
)

type runtimeRoute struct {
	method     string
	path       string
	statements []runtimeStatement
	secured    bool
}

type runtimeStatement struct {
	kind  string
	name  string
	table string
	value string
	code  int
}

type runtimeProgram struct {
	port           int
	logs           []string
	routes         []runtimeRoute
	databaseURL    string
	databaseEnv    string
	entryDirectory string
	usesJWT        bool
	jwtSecret      []byte
}

type runtimeDB struct {
	mu      sync.Mutex
	data    map[string][]map[string]interface{}
	sqlDB   *sql.DB
	dialect string
}

type runtimeBranch struct {
	parentActive bool
	condition    bool
	inElse       bool
}

func (db *runtimeDB) all(table string) ([]map[string]interface{}, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.sqlDB != nil {
		query := "SELECT data FROM jokotin_records WHERE table_name = " + db.placeholder(1)
		rows, err := db.sqlDB.Query(query, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var result []map[string]interface{}
		for rows.Next() {
			var encoded string
			if err := rows.Scan(&encoded); err != nil {
				return nil, err
			}
			record := make(map[string]interface{})
			if err := json.Unmarshal([]byte(encoded), &record); err != nil {
				return nil, fmt.Errorf("decode stored Jokotin record: %w", err)
			}
			result = append(result, record)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if result == nil {
			result = make([]map[string]interface{}, 0)
		}
		return result, nil
	}
	records := db.data[table]
	result := make([]map[string]interface{}, len(records))
	for i, record := range records {
		result[i] = cloneRecord(record)
	}
	return result, nil
}

func (db *runtimeDB) find(table, field string, value interface{}) (map[string]interface{}, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.sqlDB != nil {
		query := "SELECT data FROM jokotin_records WHERE table_name = " + db.placeholder(1)
		rows, err := db.sqlDB.Query(query, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var encoded string
			if err := rows.Scan(&encoded); err != nil {
				return nil, err
			}
			record := make(map[string]interface{})
			if err := json.Unmarshal([]byte(encoded), &record); err != nil {
				return nil, fmt.Errorf("decode stored Jokotin record: %w", err)
			}
			if valuesEqual(record[field], value) {
				return record, nil
			}
		}
		return nil, rows.Err()
	}
	for _, record := range db.data[table] {
		if valuesEqual(record[field], value) {
			return cloneRecord(record), nil
		}
	}
	return nil, nil
}

func (db *runtimeDB) insert(table string, record map[string]interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if record["id"] == nil {
		id, err := generateUUID()
		if err != nil {
			return err
		}
		record["id"] = id
	}
	if db.sqlDB != nil {
		encoded, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode record: %w", err)
		}
		query := "INSERT INTO jokotin_records (table_name, record_id, data) VALUES (" +
			db.placeholder(1) + ", " + db.placeholder(2) + ", " + db.placeholder(3) + ")"
		_, err = db.sqlDB.Exec(query, table, fmt.Sprint(record["id"]), string(encoded))
		return err
	}
	db.data[table] = append(db.data[table], cloneRecord(record))
	return nil
}

func (db *runtimeDB) update(table, field string, value interface{}, record map[string]interface{}) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.sqlDB != nil {
		encoded, err := json.Marshal(record)
		if err != nil {
			return false, fmt.Errorf("encode record: %w", err)
		}
		query := "UPDATE jokotin_records SET data = " + db.placeholder(1) + " WHERE table_name = " +
			db.placeholder(2) + " AND record_id = " + db.placeholder(3)
		result, err := db.sqlDB.Exec(query, string(encoded), table, fmt.Sprint(value))
		if err != nil {
			return false, err
		}
		rows, err := result.RowsAffected()
		return rows > 0, err
	}
	for i, existing := range db.data[table] {
		if valuesEqual(existing[field], value) {
			db.data[table][i] = cloneRecord(record)
			return true, nil
		}
	}
	return false, nil
}

func (db *runtimeDB) delete(table, field string, value interface{}) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.sqlDB != nil {
		query := "DELETE FROM jokotin_records WHERE table_name = " + db.placeholder(1) +
			" AND record_id = " + db.placeholder(2)
		result, err := db.sqlDB.Exec(query, table, fmt.Sprint(value))
		if err != nil {
			return false, err
		}
		rows, err := result.RowsAffected()
		return rows > 0, err
	}
	for i, record := range db.data[table] {
		if valuesEqual(record[field], value) {
			db.data[table] = append(db.data[table][:i], db.data[table][i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (db *runtimeDB) placeholder(index int) string {
	if db.dialect == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func cloneRecord(record map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(record))
	for key, value := range record {
		cloned[key] = value
	}
	return cloned
}

func valuesEqual(left, right interface{}) bool {
	switch leftValue := left.(type) {
	case string:
		switch rightValue := right.(type) {
		case string:
			return leftValue == rightValue
		case float64:
			return leftValue == strconv.FormatFloat(rightValue, 'f', -1, 64)
		default:
			return false
		}
	case float64:
		switch rightValue := right.(type) {
		case float64:
			return leftValue == rightValue
		case string:
			parsed, err := strconv.ParseFloat(rightValue, 64)
			return err == nil && leftValue == parsed
		default:
			return false
		}
	case bool:
		rightValue, ok := right.(bool)
		return ok && leftValue == rightValue
	case nil:
		return right == nil
	default:
		return fmt.Sprint(left) == fmt.Sprint(right)
	}
}

// RunJokFile interprets a Jokotin entry point without invoking a compiler or
// external runtime to serve its backend.
func RunJokFile(filename string) error {
	source, err := LoadJokFile(filename)
	if err != nil {
		return err
	}
	program, err := parseRuntimeProgram(source)
	if err != nil {
		return err
	}
	entryPath, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("resolve entry file %q: %w", filename, err)
	}
	program.entryDirectory = filepath.Dir(entryPath)
	if program.usesJWT {
		secret := os.Getenv("JOKOTIN_JWT_SECRET")
		if len(secret) < 32 {
			return errors.New("JOKOTIN_JWT_SECRET must contain at least 32 characters when JWT is used")
		}
		program.jwtSecret = []byte(secret)
	}
	connection := program.databaseURL
	if program.databaseEnv != "" {
		connection = os.Getenv(program.databaseEnv)
		if connection == "" {
			return fmt.Errorf("database environment variable %s is not set", program.databaseEnv)
		}
	}
	db, err := openRuntimeDB(connection, program.entryDirectory)
	if err != nil {
		return err
	}
	if db.sqlDB != nil {
		defer db.sqlDB.Close()
	}
	for _, message := range program.logs {
		fmt.Println(message)
	}
	fmt.Println("Swagger UI: http://localhost:" + strconv.Itoa(program.port) + "/docs")
	fmt.Printf("Jokotin server listening on http://localhost:%d\n", program.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", program.port), program.handlerWithDB(db))
}

func parseRuntimeProgram(source string) (runtimeProgram, error) {
	program := runtimeProgram{port: 3000}
	lines := strings.Split(source, "\n")
	var current *runtimeRoute
	var branchDepth int

	for lineNumber, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if current == nil {
			if matches := runtimeRouteDeclaration.FindStringSubmatch(trimmed); matches != nil {
				method := strings.ToUpper(matches[1])
				current = &runtimeRoute{
					method: method,
					path:   routePattern(matches[2]),
				}
				if (matches[2] == "/docs" && method == "GET") || (matches[2] == "/swagger.json" && method == "GET") {
					return runtimeProgram{}, fmt.Errorf("line %d: %s is reserved for automatic Swagger documentation", lineNumber+1, matches[2])
				}
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "require "):
				continue
			case strings.HasPrefix(trimmed, "server "):
				port, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "server ")))
				if err != nil || port < 1 || port > 65535 {
					return runtimeProgram{}, fmt.Errorf("line %d: server port must be between 1 and 65535", lineNumber+1)
				}
				program.port = port
			case strings.HasPrefix(trimmed, "jk "):
				message, err := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "jk ")))
				if err != nil {
					return runtimeProgram{}, fmt.Errorf("line %d: jk expects a quoted message", lineNumber+1)
				}
				program.logs = append(program.logs, message)
			case runtimeDatabaseEnv.MatchString(trimmed):
				matches := runtimeDatabaseEnv.FindStringSubmatch(trimmed)
				program.databaseEnv = matches[1]
				program.databaseURL = ""
			case strings.HasPrefix(trimmed, "db connect "):
				connection, err := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "db connect ")))
				if err != nil || connection == "" {
					return runtimeProgram{}, fmt.Errorf("line %d: db connect expects a quoted connection string", lineNumber+1)
				}
				program.databaseURL = connection
				program.databaseEnv = ""
			default:
				return runtimeProgram{}, fmt.Errorf("line %d: unsupported statement %q", lineNumber+1, trimmed)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "if ") {
			condition := strings.TrimSpace(strings.TrimPrefix(trimmed, "if "))
			program.usesJWT = program.usesJWT || strings.Contains(condition, "jwt.")
			current.statements = append(current.statements, runtimeStatement{kind: "if", value: condition})
			branchDepth++
			continue
		}
		if trimmed == "else" {
			if branchDepth == 0 {
				return runtimeProgram{}, fmt.Errorf("line %d: else without matching if", lineNumber+1)
			}
			current.statements = append(current.statements, runtimeStatement{kind: "else"})
			continue
		}
		if trimmed == "end" {
			if branchDepth > 0 {
				current.statements = append(current.statements, runtimeStatement{kind: "end_if"})
				branchDepth--
				continue
			}
			program.routes = append(program.routes, *current)
			current = nil
			continue
		}

		statement, err := parseRuntimeStatement(trimmed)
		if err != nil {
			return runtimeProgram{}, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if strings.Contains(trimmed, "jwt.") {
			program.usesJWT = true
		}
		if strings.Contains(trimmed, "jwt.verify(") {
			current.secured = true
		}
		current.statements = append(current.statements, statement)
	}
	if current != nil {
		return runtimeProgram{}, errors.New("route is missing end")
	}
	if len(program.routes) == 0 {
		return runtimeProgram{}, errors.New("backend must define at least one api route")
	}
	return program, nil
}

func parseRuntimeStatement(line string) (runtimeStatement, error) {
	if matches := runtimeJSONReturn.FindStringSubmatch(line); matches != nil {
		return runtimeStatement{kind: "json", value: strings.TrimSpace(matches[1])}, nil
	}
	if matches := runtimeStatusReturn.FindStringSubmatch(line); matches != nil {
		status, err := strconv.Atoi(matches[2])
		if err != nil || status < 100 || status > 599 {
			return runtimeStatement{}, fmt.Errorf("invalid HTTP status code %q", matches[2])
		}
		return runtimeStatement{kind: "status", value: strings.TrimSpace(matches[1]), code: status}, nil
	}
	if matches := runtimeInsertCall.FindStringSubmatch(line); matches != nil {
		return runtimeStatement{kind: "insert", table: matches[1], value: strings.TrimSpace(matches[2])}, nil
	}
	if matches := runtimeUpdateCall.FindStringSubmatch(line); matches != nil {
		return runtimeStatement{kind: "update", table: matches[1], name: strings.TrimSpace(matches[2]), value: strings.TrimSpace(matches[3])}, nil
	}
	if matches := runtimeDeleteCall.FindStringSubmatch(line); matches != nil {
		return runtimeStatement{kind: "delete", table: matches[1], value: strings.TrimSpace(matches[2])}, nil
	}
	if matches := runtimeAssignment.FindStringSubmatch(line); matches != nil {
		return runtimeStatement{kind: "assign", name: matches[1], value: strings.TrimSpace(matches[2])}, nil
	}
	return runtimeStatement{}, fmt.Errorf("unsupported route statement %q", line)
}

func (program runtimeProgram) handler() http.Handler {
	return program.handlerWithDB(&runtimeDB{data: make(map[string][]map[string]interface{})})
}

func (program runtimeProgram) handlerWithDB(db *runtimeDB) http.Handler {
	mux := http.NewServeMux()
	for _, route := range program.routes {
		mux.HandleFunc(route.method+" "+route.path, program.routeHandler(db, route))
	}
	mux.HandleFunc("GET /swagger.json", program.swaggerHandler())
	mux.HandleFunc("GET /docs", swaggerUIHandler)
	mux.HandleFunc("GET /docs/", swaggerUIHandler)
	return mux
}

func (program runtimeProgram) swaggerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(program.openAPIDocument()); err != nil {
			fmt.Fprintln(os.Stderr, "encode OpenAPI document:", err)
		}
	}
}

func swaggerUIHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Jokotin API documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>SwaggerUIBundle({ url: "/swagger.json", dom_id: "#swagger-ui" });</script>
</body>
</html>`)
}

func (program runtimeProgram) openAPIDocument() map[string]interface{} {
	paths := make(map[string]interface{})
	for _, route := range program.routes {
		method := strings.ToLower(route.method)
		switch method {
		case "get", "put", "post", "delete", "options", "head", "patch", "trace":
		default:
			continue
		}

		path := regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`).ReplaceAllString(route.path, `{$1}`)
		pathItem, ok := paths[path].(map[string]interface{})
		if !ok {
			pathItem = make(map[string]interface{})
			paths[path] = pathItem
		}
		parameters := make([]map[string]interface{}, 0)
		pathParameters := regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`).FindAllStringSubmatch(path, -1)
		for _, match := range pathParameters {
			parameters = append(parameters, map[string]interface{}{
				"name": match[1], "in": "path", "required": true,
				"schema": map[string]interface{}{"type": "string"},
			})
		}
		responses := map[string]interface{}{
			"200": map[string]interface{}{"description": "Successful response"},
			"400": map[string]interface{}{"description": "Invalid request"},
			"404": map[string]interface{}{"description": "Resource not found"},
		}
		for _, statement := range route.statements {
			if statement.kind == "status" {
				code := strconv.Itoa(statement.code)
				responses[code] = map[string]interface{}{"description": http.StatusText(statement.code)}
			}
		}
		operation := map[string]interface{}{
			"operationId": method + strings.ReplaceAll(strings.Trim(path, "/{}"), "/", "_"),
			"summary":     strings.ToUpper(route.method) + " " + path,
			"parameters":  parameters,
			"responses":   responses,
		}
		if method == "post" || method == "put" || method == "patch" {
			operation["requestBody"] = map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{"type": "object", "additionalProperties": true},
					},
				},
			}
		}
		if route.secured {
			operation["security"] = []interface{}{map[string]interface{}{"BearerAuth": []string{}}}
		}
		pathItem[method] = operation
	}
	document := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "Jokotin API",
			"version":     "1.0.0",
			"description": "OpenAPI documentation generated automatically from Jokotin routes.",
		},
		"paths": paths,
	}
	if program.usesJWT {
		document["components"] = map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"BearerAuth": map[string]interface{}{
					"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
				},
			},
		}
	}
	return document
}

func openRuntimeDB(connection, baseDirectory string) (*runtimeDB, error) {
	if connection == "" {
		return &runtimeDB{data: make(map[string][]map[string]interface{})}, nil
	}
	var driver, dialect, dataSource string
	switch {
	case strings.HasPrefix(connection, "sqlite:"):
		driver = "sqlite"
		dialect = "sqlite"
		dataSource = strings.TrimPrefix(connection, "sqlite:")
		if dataSource == "" {
			return nil, errors.New("SQLite connection must use sqlite:./path/to/database.db or sqlite::memory:")
		}
		if dataSource != ":memory:" {
			if !filepath.IsAbs(dataSource) {
				dataSource = filepath.Join(baseDirectory, filepath.FromSlash(dataSource))
			}
			absolutePath, err := filepath.Abs(dataSource)
			if err != nil {
				return nil, fmt.Errorf("resolve SQLite database path: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(absolutePath), 0700); err != nil {
				return nil, fmt.Errorf("create SQLite database directory: %w", err)
			}
			dataSource = absolutePath
		}
	case strings.HasPrefix(connection, "postgres://"), strings.HasPrefix(connection, "postgresql://"):
		parsed, err := url.Parse(connection)
		if err != nil || parsed.Host == "" || parsed.User == nil {
			return nil, errors.New("PostgreSQL connection must include a host and username")
		}
		driver = "pgx"
		dialect = "postgres"
		dataSource = connection
	default:
		return nil, errors.New("unsupported database connection; use sqlite:./path.db or a postgres:// URL")
	}

	sqlDB, err := sql.Open(driver, dataSource)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dialect, err)
	}
	if dialect == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connect to %s database: %w", dialect, err)
	}
	schema := `CREATE TABLE IF NOT EXISTS jokotin_records (
		table_name TEXT NOT NULL,
		record_id TEXT NOT NULL,
		data TEXT NOT NULL,
		PRIMARY KEY (table_name, record_id)
	)`
	if _, err := sqlDB.ExecContext(ctx, schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("initialize %s database: %w", dialect, err)
	}
	return &runtimeDB{sqlDB: sqlDB, dialect: dialect}, nil
}

func (program runtimeProgram) routeHandler(db *runtimeDB, route runtimeRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]interface{})
		if r.Body != nil && r.ContentLength != 0 {
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
			if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
				var maxBytesError *http.MaxBytesError
				if errors.As(err, &maxBytesError) {
					http.Error(w, "Request body is too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}
			var extra interface{}
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				http.Error(w, "Request must contain one JSON value", http.StatusBadRequest)
				return
			}
		}
		variables := make(map[string]interface{})
		var branches []runtimeBranch

		for _, statement := range route.statements {
			switch statement.kind {
			case "if":
				parentActive := activeBranches(branches)
				condition := false
				if parentActive {
					value, err := evaluateCondition(statement.value, variables, body, r, db, program.jwtSecret)
					if err != nil {
						writeRuntimeError(w, err)
						return
					}
					condition = value
				}
				branches = append(branches, runtimeBranch{parentActive: parentActive, condition: condition})
				continue
			case "else":
				if len(branches) > 0 {
					branches[len(branches)-1].inElse = true
				}
				continue
			case "end_if":
				if len(branches) > 0 {
					branches = branches[:len(branches)-1]
				}
				continue
			}
			if !activeBranches(branches) {
				continue
			}

			switch statement.kind {
			case "assign":
				value, err := evaluateExpression(statement.value, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				if err := assignRuntimeValue(statement.name, value, variables, body); err != nil {
					writeRuntimeError(w, err)
					return
				}
			case "insert":
				value, err := evaluateExpression(statement.value, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				record, ok := value.(map[string]interface{})
				if !ok {
					http.Error(w, "db.insert expects a JSON object", http.StatusBadRequest)
					return
				}
				if err := db.insert(statement.table, record); err != nil {
					writeRuntimeError(w, fmt.Errorf("insert record: %w", err))
					return
				}
			case "update":
				id, err := evaluateExpression(statement.name, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				value, err := evaluateExpression(statement.value, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				record, ok := value.(map[string]interface{})
				if !ok {
					http.Error(w, "db.update expects a JSON object", http.StatusBadRequest)
					return
				}
				updated, err := db.update(statement.table, "id", id, record)
				if err != nil {
					writeRuntimeError(w, fmt.Errorf("update record: %w", err))
					return
				}
				if !updated {
					http.Error(w, "Record not found", http.StatusNotFound)
					return
				}
			case "delete":
				id, err := evaluateExpression(statement.value, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				deleted, err := db.delete(statement.table, "id", id)
				if err != nil {
					writeRuntimeError(w, fmt.Errorf("delete record: %w", err))
					return
				}
				if !deleted {
					http.Error(w, "Record not found", http.StatusNotFound)
					return
				}
			case "json", "status":
				value, err := evaluateExpression(statement.value, variables, body, r, db, program.jwtSecret)
				if err != nil {
					writeRuntimeError(w, err)
					return
				}
				if statement.kind == "json" {
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(publicJSON(value)); err != nil {
						fmt.Fprintln(os.Stderr, "encode JSON response:", err)
					}
					return
				}
				writeStatusResponse(w, statement.code, value)
				return
			}
		}
		http.Error(w, "Route did not return a response", http.StatusInternalServerError)
	}
}

func activeBranches(branches []runtimeBranch) bool {
	for _, branch := range branches {
		active := branch.condition
		if branch.inElse {
			active = !active
		}
		if !branch.parentActive || !active {
			return false
		}
	}
	return true
}

func evaluateCondition(expression string, variables, body map[string]interface{}, r *http.Request, db *runtimeDB, secret []byte) (bool, error) {
	parts := splitExpression(expression, " or ")
	if len(parts) > 1 {
		for _, part := range parts {
			value, err := evaluateCondition(part, variables, body, r, db, secret)
			if err != nil || value {
				return value, err
			}
		}
		return false, nil
	}
	parts = splitExpression(expression, " and ")
	if len(parts) > 1 {
		for _, part := range parts {
			value, err := evaluateCondition(part, variables, body, r, db, secret)
			if err != nil || !value {
				return value, err
			}
		}
		return true, nil
	}
	expression = strings.TrimSpace(expression)
	if strings.HasPrefix(expression, "not ") {
		value, err := evaluateCondition(strings.TrimSpace(strings.TrimPrefix(expression, "not ")), variables, body, r, db, secret)
		return !value, err
	}
	if parts := splitExpression(expression, "!="); len(parts) == 2 {
		left, err := evaluateExpression(parts[0], variables, body, r, db, secret)
		if err != nil {
			return false, err
		}
		right, err := evaluateExpression(parts[1], variables, body, r, db, secret)
		return !valuesEqual(left, right), err
	}
	if parts := splitExpression(expression, "=="); len(parts) == 2 {
		left, err := evaluateExpression(parts[0], variables, body, r, db, secret)
		if err != nil {
			return false, err
		}
		right, err := evaluateExpression(parts[1], variables, body, r, db, secret)
		return valuesEqual(left, right), err
	}
	value, err := evaluateExpression(expression, variables, body, r, db, secret)
	if err != nil {
		return false, err
	}
	return truthy(value), nil
}

func splitExpression(expression, separator string) []string {
	var parts []string
	quoted := false
	escaped := false
	depth := 0
	start := 0
	for i := 0; i <= len(expression)-len(separator); i++ {
		char := expression[i]
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && quoted {
			escaped = true
			continue
		}
		if char == '"' {
			quoted = !quoted
			continue
		}
		if quoted {
			continue
		}
		switch char {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
		}
		if depth == 0 && strings.HasPrefix(expression[i:], separator) {
			parts = append(parts, strings.TrimSpace(expression[start:i]))
			i += len(separator) - 1
			start = i + 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	parts = append(parts, strings.TrimSpace(expression[start:]))
	return parts
}

func evaluateExpression(expression string, variables, body map[string]interface{}, r *http.Request, db *runtimeDB, secret []byte) (interface{}, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil, errors.New("empty expression")
	}
	if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
		result := make(map[string]interface{})
		for _, field := range splitList(expression[1:len(expression)-1], ",") {
			parts := splitExpression(field, ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid object field %q", field)
			}
			key, err := strconv.Unquote(strings.TrimSpace(parts[0]))
			if err != nil {
				key = strings.TrimSpace(parts[0])
			}
			value, err := evaluateExpression(parts[1], variables, body, r, db, secret)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		return result, nil
	}
	if strings.HasPrefix(expression, "db.all(") && strings.HasSuffix(expression, ")") {
		table, err := unquoteArgument(expression, "db.all")
		if err != nil {
			return nil, err
		}
		return db.all(table)
	}
	if strings.HasPrefix(expression, "db.find(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "db.find")
		if len(args) != 2 {
			return nil, errors.New(`db.find syntax: db.find("table", field: value)`)
		}
		table, err := strconv.Unquote(args[0])
		if err != nil {
			return nil, errors.New("db.find table must be a quoted string")
		}
		filter := splitExpression(args[1], ":")
		if len(filter) != 2 {
			return nil, errors.New(`db.find syntax: db.find("table", field: value)`)
		}
		value, err := evaluateExpression(filter[1], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		record, err := db.find(table, strings.TrimSpace(filter[0]), value)
		if err != nil {
			return nil, fmt.Errorf("find record: %w", err)
		}
		if record == nil {
			return nil, nil
		}
		return record, nil
	}
	if strings.HasPrefix(expression, "db.update(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "db.update")
		if len(args) != 3 {
			return nil, errors.New(`db.update syntax: db.update("table", id, record)`)
		}
		table, err := strconv.Unquote(args[0])
		if err != nil {
			return nil, errors.New("db.update table must be a quoted string")
		}
		id, err := evaluateExpression(args[1], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		value, err := evaluateExpression(args[2], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		record, ok := value.(map[string]interface{})
		if !ok {
			return nil, errors.New("db.update expects a JSON object")
		}
		return db.update(table, "id", id, record)
	}
	if strings.HasPrefix(expression, "db.delete(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "db.delete")
		if len(args) != 2 {
			return nil, errors.New(`db.delete syntax: db.delete("table", id)`)
		}
		table, err := strconv.Unquote(args[0])
		if err != nil {
			return nil, errors.New("db.delete table must be a quoted string")
		}
		id, err := evaluateExpression(args[1], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		return db.delete(table, "id", id)
	}
	if strings.HasPrefix(expression, "hash.make(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "hash.make")
		if len(args) != 1 {
			return nil, errors.New("hash.make expects one password")
		}
		value, err := evaluateExpression(args[0], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		password, ok := value.(string)
		if !ok || password == "" || len(password) > 1024 {
			return nil, errors.New("hash.make expects a non-empty password of at most 1024 bytes")
		}
		return makePasswordHash(password)
	}
	if expression == "uuid.generate()" {
		id, err := generateUUID()
		if err != nil {
			return nil, err
		}
		return id, nil
	}
	if strings.HasPrefix(expression, "hash.check(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "hash.check")
		if len(args) != 2 {
			return nil, errors.New("hash.check expects a password and a hash")
		}
		passwordValue, err := evaluateExpression(args[0], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		hashValue, err := evaluateExpression(args[1], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		password, passwordOK := passwordValue.(string)
		encodedHash, hashOK := hashValue.(string)
		return passwordOK && len(password) <= 1024 && hashOK && checkPasswordHash(password, encodedHash), nil
	}
	if strings.HasPrefix(expression, "jwt.create(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "jwt.create")
		if len(args) != 1 {
			return nil, errors.New("jwt.create expects one subject")
		}
		subject, err := evaluateExpression(args[0], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		return createJWT(subject, secret, time.Now())
	}
	if strings.HasPrefix(expression, "jwt.verify(") && strings.HasSuffix(expression, ")") {
		args := callArguments(expression, "jwt.verify")
		if len(args) != 1 {
			return nil, errors.New("jwt.verify expects one token or Authorization header")
		}
		tokenValue, err := evaluateExpression(args[0], variables, body, r, db, secret)
		if err != nil {
			return nil, err
		}
		token, ok := tokenValue.(string)
		if !ok {
			return nil, nil
		}
		claims := verifyJWT(token, secret, time.Now())
		if claims == nil {
			return nil, nil
		}
		return claims, nil
	}
	if expression == "req.method" {
		return r.Method, nil
	}
	if expression == "req.path" {
		return r.URL.Path, nil
	}
	if strings.HasPrefix(expression, "req.params.") {
		return r.PathValue(strings.TrimPrefix(expression, "req.params.")), nil
	}
	if strings.HasPrefix(expression, "req.query.") {
		return r.URL.Query().Get(strings.TrimPrefix(expression, "req.query.")), nil
	}
	if strings.HasPrefix(expression, "req.headers.") {
		return r.Header.Get(http.CanonicalHeaderKey(strings.TrimPrefix(expression, "req.headers."))), nil
	}
	if expression == "req.body" {
		return body, nil
	}
	if strings.HasPrefix(expression, "req.body.") {
		return resolvePath("body."+strings.TrimPrefix(expression, "req.body."), map[string]interface{}{"body": body})
	}
	if expression == "nil" {
		return nil, nil
	}
	if expression == "true" || expression == "false" {
		return expression == "true", nil
	}
	if strings.HasPrefix(expression, "\"") {
		value, err := strconv.Unquote(expression)
		return value, err
	}
	if number, err := strconv.ParseFloat(expression, 64); err == nil {
		return number, nil
	}
	return resolvePath(expression, variables)
}

func callArguments(expression, name string) []string {
	inside := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, name+"("), ")"))
	if inside == "" {
		return nil
	}
	return splitList(inside, ",")
}

func splitList(expression, separator string) []string {
	if parts := splitExpression(expression, separator); parts != nil {
		return parts
	}
	return []string{strings.TrimSpace(expression)}
}

func unquoteArgument(expression, name string) (string, error) {
	args := callArguments(expression, name)
	if len(args) != 1 {
		return "", fmt.Errorf("%s expects one quoted table name", name)
	}
	value, err := strconv.Unquote(args[0])
	if err != nil {
		return "", fmt.Errorf("%s table must be a quoted string", name)
	}
	return value, nil
}

func resolvePath(expression string, variables map[string]interface{}) (interface{}, error) {
	expression = strings.TrimSuffix(strings.TrimSpace(expression), "?")
	parts := strings.Split(expression, ".")
	value, ok := variables[parts[0]]
	if !ok {
		return nil, fmt.Errorf("unknown Jokotin value %q", expression)
	}
	for _, part := range parts[1:] {
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%q is not an object", strings.Join(parts[:len(parts)-1], "."))
		}
		value = object[part]
	}
	return value, nil
}

func assignRuntimeValue(target string, value interface{}, variables, body map[string]interface{}) error {
	parts := strings.Split(target, ".")
	if parts[0] == "req" || parts[0] == "db" || parts[0] == "jwt" || parts[0] == "hash" || parts[0] == "uuid" {
		return fmt.Errorf("cannot assign to built-in %q", target)
	}
	if len(parts) == 1 {
		variables[target] = value
		return nil
	}
	var object map[string]interface{}
	if parts[0] == "req" && len(parts) > 1 && parts[1] == "body" {
		object = body
		parts = parts[1:]
	} else {
		var ok bool
		object, ok = variables[parts[0]].(map[string]interface{})
		if !ok {
			return fmt.Errorf("cannot assign field on unknown or non-object value %q", parts[0])
		}
	}
	for _, part := range parts[1 : len(parts)-1] {
		next, ok := object[part].(map[string]interface{})
		if !ok {
			return fmt.Errorf("cannot assign nested field %q", target)
		}
		object = next
	}
	object[parts[len(parts)-1]] = value
	return nil
}

func truthy(value interface{}) bool {
	if value == nil {
		return false
	}
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	return true
}

func writeRuntimeError(w http.ResponseWriter, err error) {
	http.Error(w, "Jokotin runtime error: "+err.Error(), http.StatusInternalServerError)
	fmt.Fprintln(os.Stderr, err)
}

func writeStatusResponse(w http.ResponseWriter, status int, value interface{}) {
	if object, ok := value.(map[string]interface{}); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(publicJSON(object)); err != nil {
			fmt.Fprintln(os.Stderr, "encode JSON response:", err)
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, value)
}

func publicJSON(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, field := range typed {
			if strings.HasPrefix(key, "_") || strings.EqualFold(key, "password") {
				continue
			}
			result[key] = publicJSON(field)
		}
		return result
	case []map[string]interface{}:
		result := make([]map[string]interface{}, len(typed))
		for index, record := range typed {
			result[index] = publicJSON(record).(map[string]interface{})
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, item := range typed {
			result[index] = publicJSON(item)
		}
		return result
	default:
		return value
	}
}

func makePasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derived := pbkdf2SHA256([]byte(password), salt, passwordHashIterations, passwordHashLength)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		passwordHashIterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived)), nil
}

func generateUUID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(id)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func checkPasswordHash(password, encoded string) bool {
	matches := runtimePasswordHash.FindStringSubmatch(encoded)
	if matches == nil {
		return false
	}
	iterations, err := strconv.Atoi(matches[1])
	if err != nil || iterations < 100_000 || iterations > 1_000_000 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(matches[2])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(matches[3])
	if err != nil || len(expected) != passwordHashLength {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, length int) []byte {
	const hashSize = sha256.Size
	result := make([]byte, 0, length)
	for block := uint32(1); len(result) < length; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		current := mac.Sum(nil)
		derived := append([]byte(nil), current...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(current)
			current = mac.Sum(nil)
			for j := 0; j < hashSize; j++ {
				derived[j] ^= current[j]
			}
		}
		result = append(result, derived...)
	}
	return result[:length]
}

func createJWT(subject interface{}, secret []byte, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("JWT signing secret must contain at least 32 characters")
	}
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]interface{}{
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + signJWT(unsigned, secret), nil
}

func signJWT(unsigned string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyJWT(token string, secret []byte, now time.Time) map[string]interface{} {
	if len(secret) < 32 {
		return nil
	}
	token = strings.TrimSpace(token)
	if len(token) > 16*1024 {
		return nil
	}
	if scheme, value, found := strings.Cut(token, " "); found {
		if !strings.EqualFold(scheme, "Bearer") {
			return nil
		}
		token = strings.TrimSpace(value)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	expectedSignature, err := base64.RawURLEncoding.DecodeString(signJWT(parts[0]+"."+parts[1], secret))
	if err != nil {
		return nil
	}
	actualSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(actualSignature, expectedSignature) {
		return nil
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]interface{}
	if json.Unmarshal(headerBytes, &header) != nil || header["alg"] != "HS256" {
		return nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	claims := make(map[string]interface{})
	if json.Unmarshal(payloadBytes, &claims) != nil {
		return nil
	}
	expiry, ok := claims["exp"].(float64)
	if !ok || now.Unix() >= int64(expiry) {
		return nil
	}
	return claims
}

// LoadJokFile loads an entry point and expands relative require statements.
func LoadJokFile(filename string) (string, error) {
	root, err := filepath.Abs(filename)
	if err != nil {
		return "", fmt.Errorf("resolve entry file %q: %w", filename, err)
	}
	var source strings.Builder
	loaded := make(map[string]bool)
	visiting := make(map[string]bool)
	if err := appendJokFile(root, &source, loaded, visiting); err != nil {
		return "", err
	}
	return source.String(), nil
}

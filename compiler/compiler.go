package compiler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	apiDeclaration = regexp.MustCompile(`^api ([a-zA-Z]+) "([^"]+)" do$`)
	statusReturn   = regexp.MustCompile(`^return (.+) status ([0-9]+)$`)
	allAssignment  = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*db\.all\("([^"]+)"\)$`)
	bodyAssignment = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*req\.body$`)
	insertCall     = regexp.MustCompile(`^db\.insert\("([^"]+)",\s*([a-zA-Z_][a-zA-Z0-9_]*)\)$`)
)

// TranspileJokToGo converts the supported Jokotin backend syntax to a
// standalone Go HTTP server.
func TranspileJokToGo(jokCode string) string {
	var goCode strings.Builder
	goCode.WriteString(`package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

type JokDB struct {
	connStr string
	data    map[string][]map[string]interface{}
	mu      sync.Mutex
}

func (db *JokDB) Connect(connStr string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.connStr = connStr
	db.data = make(map[string][]map[string]interface{})
}

func (db *JokDB) All(table string) []map[string]interface{} {
	db.mu.Lock()
	defer db.mu.Unlock()
	list := db.data[table]
	result := make([]map[string]interface{}, len(list))
	copy(result, list)
	return result
}

func (db *JokDB) Insert(table string, record map[string]interface{}) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.data[table] = append(db.data[table], record)
}

var db = &JokDB{data: make(map[string][]map[string]interface{})}

type JokRequest struct {
	Body   map[string]interface{}
	Params map[string]string
}

func main() {
	mux := http.NewServeMux()
`)

	port := "3000"
	inRoute := false
	for _, line := range strings.Split(jokCode, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if matches := apiDeclaration.FindStringSubmatch(trimmed); matches != nil {
			inRoute = true
			method := strings.ToUpper(matches[1])
			path := routePattern(matches[2])
			fmt.Fprintf(&goCode, "\tmux.HandleFunc(%q, func(w http.ResponseWriter, r *http.Request) {\n", method+" "+path)
			goCode.WriteString("\t\treq := &JokRequest{Body: make(map[string]interface{}), Params: make(map[string]string)}\n")
			goCode.WriteString("\t\tif r.Body != nil && r.ContentLength != 0 {\n")
			goCode.WriteString("\t\t\tif err := json.NewDecoder(r.Body).Decode(&req.Body); err != nil {\n")
			goCode.WriteString("\t\t\t\thttp.Error(w, \"Invalid JSON body\", http.StatusBadRequest)\n")
			goCode.WriteString("\t\t\t\treturn\n\t\t\t}\n\t\t}\n")
			continue
		}

		if trimmed == "end" && inRoute {
			inRoute = false
			goCode.WriteString("\t})\n\n")
			continue
		}

		if !inRoute {
			switch {
			case strings.HasPrefix(trimmed, "server "):
				port = strings.TrimSpace(strings.TrimPrefix(trimmed, "server "))
			case strings.HasPrefix(trimmed, "db connect "):
				fmt.Fprintf(&goCode, "\tdb.Connect(%s)\n", strings.TrimSpace(strings.TrimPrefix(trimmed, "db connect ")))
			case strings.HasPrefix(trimmed, "jk "):
				fmt.Fprintf(&goCode, "\tfmt.Println(%s)\n", strings.TrimSpace(strings.TrimPrefix(trimmed, "jk ")))
			case strings.HasPrefix(trimmed, "require "):
				// Relative requires are expanded by TranspileJokFile.
			default:
				writeUnsupported(&goCode, trimmed)
			}
			continue
		}

		if matches := statusReturn.FindStringSubmatch(trimmed); matches != nil {
			status := matches[2]
			body := matches[1]
			fmt.Fprintf(&goCode, "\t\tw.Header().Set(\"Content-Type\", \"text/plain; charset=utf-8\")\n")
			fmt.Fprintf(&goCode, "\t\tw.WriteHeader(%s)\n", status)
			fmt.Fprintf(&goCode, "\t\t_, _ = fmt.Fprint(w, %s)\n", body)
			goCode.WriteString("\t\treturn\n")
			continue
		}

		if strings.HasPrefix(trimmed, "return ") && strings.HasSuffix(trimmed, " json") {
			value := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "return "), " json"))
			goCode.WriteString("\t\tw.Header().Set(\"Content-Type\", \"application/json\")\n")
			fmt.Fprintf(&goCode, "\t\tif err := json.NewEncoder(w).Encode(%s); err != nil {\n", value)
			goCode.WriteString("\t\t\thttp.Error(w, \"Could not encode JSON response\", http.StatusInternalServerError)\n")
			goCode.WriteString("\t\t}\n\t\treturn\n")
			continue
		}

		if matches := allAssignment.FindStringSubmatch(trimmed); matches != nil {
			fmt.Fprintf(&goCode, "\t\t%s := db.All(%q)\n", matches[1], matches[2])
			continue
		}
		if matches := bodyAssignment.FindStringSubmatch(trimmed); matches != nil {
			fmt.Fprintf(&goCode, "\t\t%s := req.Body\n", matches[1])
			continue
		}
		if matches := insertCall.FindStringSubmatch(trimmed); matches != nil {
			fmt.Fprintf(&goCode, "\t\tdb.Insert(%q, %s)\n", matches[1], matches[2])
			continue
		}

		writeUnsupported(&goCode, trimmed)
	}

	if inRoute {
		writeUnsupported(&goCode, "route is missing end")
		goCode.WriteString("\t})\n")
	}
	fmt.Fprintf(&goCode, "\tif err := http.ListenAndServe(%q, mux); err != nil {\n", ":"+port)
	goCode.WriteString("\t\tfmt.Println(err)\n\t}\n}\n")
	return goCode.String()
}

func routePattern(path string) string {
	re := regexp.MustCompile(`:([a-zA-Z0-9_]+)`)
	return re.ReplaceAllString(path, "{$1}")
}

func writeUnsupported(goCode *strings.Builder, statement string) {
	fmt.Fprintf(goCode, "\t panic(%s)\n", strconv.Quote("Unsupported Jokotin statement: "+statement))
}

package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTranspileJokFileExpandsRelativeRequire(t *testing.T) {
	project := t.TempDir()
	routesDir := filepath.Join(project, "routes")
	if err := os.MkdirAll(routesDir, 0755); err != nil {
		t.Fatal(err)
	}

	routes := "api get \"/users\" do\n  return \"[]\" status 200\nend\n"
	if err := os.WriteFile(filepath.Join(routesDir, "users.jok"), []byte(routes), 0600); err != nil {
		t.Fatal(err)
	}
	entry := "require \"./routes/users\"\nserver 3000\n"
	entryFile := filepath.Join(project, "main.jok")
	if err := os.WriteFile(entryFile, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}

	goCode, err := TranspileJokFile(entryFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(goCode, `mux.HandleFunc("GET /users"`) {
		t.Fatalf("generated Go code did not include imported route:\n%s", goCode)
	}
	if !strings.Contains(goCode, `http.ListenAndServe(":3000", mux)`) {
		t.Fatalf("generated Go code did not include entry-point server:\n%s", goCode)
	}
}

func TestTranspileJokFileReportsRequireCycles(t *testing.T) {
	project := t.TempDir()
	first := filepath.Join(project, "first.jok")
	second := filepath.Join(project, "second.jok")
	if err := os.WriteFile(first, []byte("require \"./second\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("require \"./first\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := TranspileJokFile(first); err == nil || !strings.Contains(err.Error(), "cyclic require") {
		t.Fatalf("expected a cycle error, got %v", err)
	}
}

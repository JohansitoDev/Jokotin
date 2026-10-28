package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TranspileJokFile loads a .jok entry point, expands its relative require
// statements, and transpiles the combined source.
func TranspileJokFile(filename string) (string, error) {
	source, err := LoadJokFile(filename)
	if err != nil {
		return "", err
	}
	return TranspileJokToGo(source), nil
}

func appendJokFile(filename string, source *strings.Builder, loaded, visiting map[string]bool) error {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("resolve imported file %q: %w", filename, err)
	}
	filename = filepath.Clean(filename)

	if visiting[filename] {
		return fmt.Errorf("cyclic require detected at %q", filename)
	}
	if loaded[filename] {
		return nil
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read Jokotin file %q: %w", filename, err)
	}

	visiting[filename] = true
	defer delete(visiting, filename)

	for lineNumber, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "require") {
			source.WriteString(line)
			source.WriteByte('\n')
			continue
		}

		fields := strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
		importPath, err := strconv.Unquote(fields)
		if err != nil || importPath == "" {
			return fmt.Errorf("%s:%d: require must contain a quoted relative path, e.g. require \"./routes/users\"", filename, lineNumber+1)
		}
		if filepath.IsAbs(importPath) {
			return fmt.Errorf("%s:%d: require path must be relative to the importing file", filename, lineNumber+1)
		}

		importedFile := filepath.Join(filepath.Dir(filename), filepath.FromSlash(importPath))
		if filepath.Ext(importedFile) == "" {
			importedFile += ".jok"
		}
		if err := appendJokFile(importedFile, source, loaded, visiting); err != nil {
			return err
		}
	}

	loaded[filename] = true
	return nil
}

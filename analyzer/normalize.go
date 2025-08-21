package analyzer

import (
	"path/filepath"
	"strings"
)

// normalizeImportName converts raw import paths to normalized package names
func (va *VulnerabilityAnalyzer) normalizeImportName(importPath string, filePath string) string {
	ext := filepath.Ext(filePath)

	switch ext {
	case ".js":
		return va.normalizeJSImport(importPath)
	case ".py":
		return va.normalizePythonImport(importPath)
	case ".go":
		return va.normalizeGoImport(importPath)
	default:
		return importPath
	}
}

// normalizeJSImport converts JavaScript import paths to package names
func (va *VulnerabilityAnalyzer) normalizeJSImport(importPath string) string {
	// Skip relative imports
	if strings.HasPrefix(importPath, ".") || strings.HasPrefix(importPath, "/") {
		return ""
	}

	// Scoped packages start with @
	if strings.HasPrefix(importPath, "@") {
		return importPath
	}

	// Extract base package name from path
	parts := strings.Split(importPath, "/")
	return parts[0]
}

// normalizePythonImport filters out standard library imports and normalizes package names
func (va *VulnerabilityAnalyzer) normalizePythonImport(importPath string) string {
	// Python standard library modules
	stdlib := []string{"os", "sys", "json", "re", "time", "datetime", "collections", "itertools", "functools", "operator", "pathlib", "urllib", "http", "email", "html", "xml", "csv", "sqlite3", "threading", "multiprocessing", "subprocess", "shutil", "glob", "pickle", "base64", "hashlib", "hmac", "secrets", "ssl", "socket", "logging", "unittest", "argparse", "configparser", "io", "math", "random", "statistics", "decimal", "fractions", "enum", "types", "copy", "pprint", "textwrap", "string", "bytes", "bytearray", "memoryview", "array"}

	for _, std := range stdlib {
		if importPath == std {
			return ""
		}
	}

	// Extract top-level package name
	parts := strings.Split(importPath, ".")
	return parts[0]
}

// normalizeGoImport - let go.mod do the filtering
func (va *VulnerabilityAnalyzer) normalizeGoImport(importPath string) string {
	if strings.Contains(importPath, "github.com/hannajonsd/reachability-analysis") {
		return ""
	}

	if strings.Contains(importPath, "github.com/smacker/go-tree-sitter") {
		return ""
	}

	if strings.HasPrefix(importPath, "./") || strings.HasPrefix(importPath, "../") {
		return ""
	}

	return importPath
}

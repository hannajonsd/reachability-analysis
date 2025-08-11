// parser/factory.go - Updated
package parser

import (
	"fmt"
	"path/filepath"
	"strings"
)

func CreateParser(filePath string) (Parser, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return NewJavaScriptParser()
	// case ".py":
	// 	return NewPythonParser()
	// case ".go":
	// 	return NewGoParser()
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

func deduplicateImports(imports []PackageImport) []PackageImport {
	seen := make(map[string]bool)
	var result []PackageImport

	for _, imp := range imports {
		key := fmt.Sprintf("%s|%s|%s", imp.PackageName, imp.Alias, imp.ImportType)
		if !seen[key] {
			seen[key] = true
			result = append(result, imp)
		}
	}

	return result
}

func deduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

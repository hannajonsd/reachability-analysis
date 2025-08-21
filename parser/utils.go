package parser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// CreateParser creates the appropriate parser based on file extension
func CreateParser(filePath string) (Parser, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return NewJavaScriptParser()
	case ".py":
		return NewPythonParser()
	case ".go":
		return NewGoParser()
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

// DeduplicateImports removes duplicate imports based on package name, alias, and import type
func DeduplicateImports(imports []PackageImport) []PackageImport {
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

// DeduplicateStrings removes duplicate strings from a slice
func DeduplicateStrings(strs []string) []string {
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

// ExtractStringValue removes quotes from string literals in AST nodes
func ExtractStringValue(node *sitter.Node, source []byte) string {
	text := string(source[node.StartByte():node.EndByte()])
	if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') {
		text = text[1 : len(text)-1] // Remove surrounding quotes
	}
	return text
}

// WalkAST recursively traverses an AST and applies a visitor function to each node
func WalkAST(node *sitter.Node, source []byte, visitor func(*sitter.Node)) {
	visitor(node)

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		WalkAST(child, source, visitor)
	}
}

// ParseFileGeneric provides common file parsing functionality for all language parsers
func (bp *BaseParser) ParseFileGeneric(filePath string) (*ParseResult, error) {
	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	tree, err := bp.parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}
	if tree == nil {
		return nil, fmt.Errorf("failed to parse file %s", filePath)
	}

	return &ParseResult{
		Tree:     tree,
		Source:   source,
		Language: bp.langName,
		FilePath: filePath,
	}, nil
}

// GetLanguage returns the language name for this parser
func (bp *BaseParser) GetLanguage() string {
	return bp.langName
}

func (bp *BaseParser) Close() {
}

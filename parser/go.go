package parser

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

type GoParser struct {
	BaseParser
}

// NewGoParser creates a new Go language parser using tree-sitter
func NewGoParser() (*GoParser, error) {
	parser := sitter.NewParser()
	language := golang.GetLanguage()
	parser.SetLanguage(language)

	return &GoParser{
		BaseParser: BaseParser{
			parser:   parser,
			language: language,
			langName: "go",
		},
	}, nil
}

func (p *GoParser) Close() {
}

// ParseFile parses a Go source file and returns the parse result
func (p *GoParser) ParseFile(filePath string) (*ParseResult, error) {
	return p.ParseFileGeneric(filePath)
}

// ExtractImports finds all import statements in a Go AST
func (p *GoParser) ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error) {
	var imports []PackageImport

	WalkAST(node, source, func(n *sitter.Node) {
		switch n.Type() {
		case "import_declaration":
			imps := p.processImportDeclaration(n, source)
			imports = append(imports, imps...)
		}
	})

	return DeduplicateImports(imports), nil
}

// processImportDeclaration handles both single and grouped import declarations
func (p *GoParser) processImportDeclaration(node *sitter.Node, source []byte) []PackageImport {
	var imports []PackageImport

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "import_spec":
			imp := p.processImportSpec(child, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		case "import_spec_list":
			imports = append(imports, p.processImportSpecList(child, source)...)
		}
	}

	return imports
}

// processImportSpec extracts package path and alias from a single import specification
func (p *GoParser) processImportSpec(node *sitter.Node, source []byte) *PackageImport {
	var packagePath, alias string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "interpreted_string_literal":
			packagePath = ExtractStringValue(child, source)
		case "package_identifier":
			alias = string(source[child.StartByte():child.EndByte()])
		case "identifier":
			alias = string(source[child.StartByte():child.EndByte()])
		case "dot":
			alias = "."
		}
	}

	if packagePath == "" {
		return nil
	}

	packageName := packagePath

	// Handle dot imports (import . "package")
	if alias == "." {
		return &PackageImport{
			PackageName: packageName,
			Alias:       ".",
			ImportType:  "dot_import",
			Symbols:     []string{"*"},
		}
	}

	// Handle blank imports (import _ "package")
	if alias == "_" {
		return &PackageImport{
			PackageName: packageName,
			Alias:       "_",
			ImportType:  "blank_import",
			Symbols:     nil,
		}
	}

	// If no alias specified, use last part of package path
	if alias == "" {
		parts := strings.Split(packagePath, "/")
		alias = parts[len(parts)-1]
	}

	return &PackageImport{
		PackageName: packageName,
		Alias:       alias,
		ImportType:  "import",
		Symbols:     nil,
	}
}

// processImportSpecList handles grouped imports within parentheses
func (p *GoParser) processImportSpecList(node *sitter.Node, source []byte) []PackageImport {
	var imports []PackageImport

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		if child.Type() == "import_spec" {
			imp := p.processImportSpec(child, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		}
	}

	return imports
}

// ExtractCalls finds all function and method calls in a Go AST
func (p *GoParser) ExtractCalls(node *sitter.Node, source []byte) ([]string, error) {
	var calls []string

	WalkAST(node, source, func(n *sitter.Node) {
		if n.Type() == "call_expression" {
			call := p.processCall(n, source)
			if call != "" {
				calls = append(calls, call)
			}
		}
	})

	return DeduplicateStrings(calls), nil
}

// processCall extracts function name from call expressions
func (p *GoParser) processCall(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Direct function call: func()
			return string(source[child.StartByte():child.EndByte()])
		case "selector_expression":
			// Method call: obj.Method()
			return p.processAttribute(child, source)
		}
	}

	return ""
}

// processAttribute handles method calls and field access expressions
func (p *GoParser) processAttribute(node *sitter.Node, source []byte) string {
	var object, field string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			if object == "" {
				object = string(source[child.StartByte():child.EndByte()])
			}
		case "field_identifier":
			field = string(source[child.StartByte():child.EndByte()])
		}
	}

	if object != "" && field != "" {
		return fmt.Sprintf("%s.%s", object, field)
	}

	return ""
}

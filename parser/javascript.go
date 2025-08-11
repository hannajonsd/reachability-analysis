// parser/javascript.go - Proper Tree-sitter implementation (NO REGEX)
package parser

import (
	"context"
	"fmt"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

type JavaScriptParser struct {
	parser   *sitter.Parser
	language *sitter.Language
}

func NewJavaScriptParser() (*JavaScriptParser, error) {
	parser := sitter.NewParser()
	language := javascript.GetLanguage()

	parser.SetLanguage(language)

	return &JavaScriptParser{
		parser:   parser,
		language: language,
	}, nil
}

func (p *JavaScriptParser) GetLanguage() string {
	return "javascript"
}

func (p *JavaScriptParser) Close() {
}

func (p *JavaScriptParser) ParseFile(filePath string) (*ParseResult, error) {
	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	tree, err := p.parser.ParseCtx(context.Background(), nil, source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}
	if tree == nil {
		return nil, fmt.Errorf("failed to parse file %s", filePath)
	}

	return &ParseResult{
		Tree:     tree,
		Source:   source,
		Language: "javascript",
		FilePath: filePath,
	}, nil
}

func (p *JavaScriptParser) ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error) {
	var imports []PackageImport

	p.walkAST(node, source, func(n *sitter.Node) {
		switch n.Type() {
		case "import_statement":
			imp := p.processImportStatement(n, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		case "variable_declarator":
			imp := p.processVariableDeclarator(n, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		}
	})

	return deduplicateImports(imports), nil
}

func (p *JavaScriptParser) processImportStatement(node *sitter.Node, source []byte) *PackageImport {
	var packageName, alias string
	var symbols []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "import_clause":
			alias, symbols = p.processImportClause(child, source)
		case "string":
			packageName = p.extractStringValue(child, source)
		}
	}

	if packageName == "" {
		return nil
	}

	importType := "import"
	if len(symbols) > 0 {
		importType = "destructured"
		if len(symbols) > 0 {
			return &PackageImport{
				PackageName: packageName,
				Alias:       symbols[0],
				ImportType:  importType,
				Symbols:     symbols,
			}
		}
	}

	if alias != "" {
		return &PackageImport{
			PackageName: packageName,
			Alias:       alias,
			ImportType:  importType,
			Symbols:     symbols,
		}
	}

	return nil
}

func (p *JavaScriptParser) processImportClause(node *sitter.Node, source []byte) (string, []string) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Default import: import foo from "module"
			return string(source[child.StartByte():child.EndByte()]), nil
		case "namespace_import":
			// Namespace import: import * as foo from "module"
			return p.processNamespaceImport(child, source), nil
		case "named_imports":
			// Named imports: import { a, b, c } from "module"
			return "", p.processNamedImports(child, source)
		}
	}
	return "", nil
}

func (p *JavaScriptParser) processNamespaceImport(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			return string(source[child.StartByte():child.EndByte()])
		}
	}
	return ""
}

func (p *JavaScriptParser) processNamedImports(node *sitter.Node, source []byte) []string {
	var symbols []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "import_specifier":
			symbol := p.processImportSpecifier(child, source)
			if symbol != "" {
				symbols = append(symbols, symbol)
			}
		}
	}

	return symbols
}

func (p *JavaScriptParser) processImportSpecifier(node *sitter.Node, source []byte) string {
	var name, alias string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			if name == "" {
				name = string(source[child.StartByte():child.EndByte()])
			} else {
				alias = string(source[child.StartByte():child.EndByte()])
			}
		}
	}

	if alias != "" {
		return alias
	}
	return name
}

func (p *JavaScriptParser) processVariableDeclarator(node *sitter.Node, source []byte) *PackageImport {
	var alias, packageName string
	var symbols []string
	var isRequire bool

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			alias = string(source[child.StartByte():child.EndByte()])
		case "object_pattern":
			symbols = p.processObjectPattern(child, source)
		case "call_expression":
			pkg, isReq := p.processCallExpression(child, source)
			packageName = pkg
			isRequire = isReq
		}
	}

	if !isRequire || packageName == "" {
		return nil
	}

	importType := "require"
	if len(symbols) > 0 {
		importType = "destructured"
		if len(symbols) > 0 {
			return &PackageImport{
				PackageName: packageName,
				Alias:       symbols[0],
				ImportType:  importType,
				Symbols:     symbols,
			}
		}
	}

	if alias != "" {
		return &PackageImport{
			PackageName: packageName,
			Alias:       alias,
			ImportType:  importType,
			Symbols:     symbols,
		}
	}

	return nil
}

func (p *JavaScriptParser) processObjectPattern(node *sitter.Node, source []byte) []string {
	var symbols []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "shorthand_property_identifier":
			symbol := string(source[child.StartByte():child.EndByte()])
			symbols = append(symbols, symbol)
		case "pair":
			symbol := p.processPair(child, source)
			if symbol != "" {
				symbols = append(symbols, symbol)
			}
		}
	}

	return symbols
}

func (p *JavaScriptParser) processPair(node *sitter.Node, source []byte) string {
	var alias string

	for i := int(node.ChildCount()) - 1; i >= 0; i-- {
		child := node.Child(i)
		if child.Type() == "identifier" {
			alias = string(source[child.StartByte():child.EndByte()])
			break
		}
	}

	return alias
}

func (p *JavaScriptParser) processCallExpression(node *sitter.Node, source []byte) (string, bool) {
	var functionName, packageName string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			functionName = string(source[child.StartByte():child.EndByte()])
		case "arguments":
			packageName = p.processArguments(child, source)
		}
	}

	isRequire := functionName == "require"
	return packageName, isRequire
}

func (p *JavaScriptParser) processArguments(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "string" {
			return p.extractStringValue(child, source)
		}
	}
	return ""
}

func (p *JavaScriptParser) extractStringValue(node *sitter.Node, source []byte) string {
	text := string(source[node.StartByte():node.EndByte()])
	if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') {
		text = text[1 : len(text)-1]
	}
	return text
}

func (p *JavaScriptParser) ExtractCalls(node *sitter.Node, source []byte) ([]string, error) {
	var calls []string

	p.walkAST(node, source, func(n *sitter.Node) {
		if n.Type() == "call_expression" {
			call := p.processCallExpressionForCalls(n, source)
			if call != "" {
				calls = append(calls, call)
			}
		}
	})

	return deduplicateStrings(calls), nil
}

func (p *JavaScriptParser) processCallExpressionForCalls(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Direct function call: foo()
			return string(source[child.StartByte():child.EndByte()])
		case "member_expression":
			// Method call: obj.method()
			return p.processMemberExpression(child, source)
		}
	}

	return ""
}

func (p *JavaScriptParser) processMemberExpression(node *sitter.Node, source []byte) string {
	// Extract object.property
	var object, property string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			if object == "" {
				object = string(source[child.StartByte():child.EndByte()])
			}
		case "property_identifier":
			property = string(source[child.StartByte():child.EndByte()])
		}
	}

	if object != "" && property != "" {
		return fmt.Sprintf("%s.%s", object, property)
	}

	return ""
}

func (p *JavaScriptParser) walkAST(node *sitter.Node, source []byte, visitor func(*sitter.Node)) {
	visitor(node)

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		p.walkAST(child, source, visitor)
	}
}

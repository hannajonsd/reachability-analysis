// parser/javascript.go - Proper Tree-sitter implementation (NO REGEX)
package parser

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

type JavaScriptParser struct {
	BaseParser
}

func NewJavaScriptParser() (*JavaScriptParser, error) {
	parser := sitter.NewParser()
	language := javascript.GetLanguage()
	parser.SetLanguage(language)

	return &JavaScriptParser{
		BaseParser: BaseParser{
			parser:   parser,
			language: language,
			langName: "javascript",
		},
	}, nil
}

func (p *JavaScriptParser) Close() {
}

func (p *JavaScriptParser) ParseFile(filePath string) (*ParseResult, error) {
	return p.ParseFileGeneric(filePath)
}

func (p *JavaScriptParser) ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error) {
	var imports []PackageImport

	WalkAST(node, source, func(n *sitter.Node) {
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

	return DeduplicateImports(imports), nil
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
			packageName = ExtractStringValue(child, source)
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
			return ExtractStringValue(child, source)
		}
	}
	return ""
}

func (p *JavaScriptParser) ExtractCalls(node *sitter.Node, source []byte) ([]string, error) {
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

func (p *JavaScriptParser) processCall(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Direct function call: foo()
			return string(source[child.StartByte():child.EndByte()])
		case "member_expression":
			// Method call: obj.method()
			return p.processAttribute(child, source)
		}
	}

	return ""
}

func (p *JavaScriptParser) processAttribute(node *sitter.Node, source []byte) string {
	// Extract object.attribute
	var object, attribute string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			if object == "" {
				object = string(source[child.StartByte():child.EndByte()])
			}
		case "property_identifier":
			attribute = string(source[child.StartByte():child.EndByte()])
		}
	}

	if object != "" && attribute != "" {
		return fmt.Sprintf("%s.%s", object, attribute)
	}

	return ""
}

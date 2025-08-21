package parser

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

type JavaScriptParser struct {
	BaseParser
}

// NewJavaScriptParser creates a new JavaScript language parser using tree-sitter
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

// ParseFile parses a JavaScript source file and returns the parse result
func (p *JavaScriptParser) ParseFile(filePath string) (*ParseResult, error) {
	return p.ParseFileGeneric(filePath)
}

// ExtractImports finds all import statements and require calls in a JavaScript AST
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

// processImportStatement handles ES6 import statements (import ... from "module")
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

// processImportClause handles different types of import clauses (default, namespace, named)
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

// processNamespaceImport handles namespace imports (import * as alias from "module")
func (p *JavaScriptParser) processNamespaceImport(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			return string(source[child.StartByte():child.EndByte()])
		}
	}
	return ""
}

// processNamedImports handles named imports (import { a, b, c } from "module")
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

// processImportSpecifier handles individual named import specifiers with potential aliases
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

// processVariableDeclarator handles CommonJS require statements (const x = require("module"))
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

// processObjectPattern handles destructuring in require statements (const { a, b } = require("module"))
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

// processPair handles aliased destructuring (const { original: alias } = require("module"))
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

// processCallExpression identifies require() calls and extracts the module name
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

// processArguments extracts string arguments from function calls
func (p *JavaScriptParser) processArguments(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "string" {
			return ExtractStringValue(child, source)
		}
	}
	return ""
}

// ExtractCalls finds all function and method calls in a JavaScript AST
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

// processCall extracts function name from call expressions
func (p *JavaScriptParser) processCall(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Direct function call: func()
			return string(source[child.StartByte():child.EndByte()])
		case "member_expression":
			// Method call: obj.method()
			return p.processAttribute(child, source)
		}
	}

	return ""
}

// processAttribute handles method calls and property access expressions
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

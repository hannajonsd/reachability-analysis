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

func (p *GoParser) ParseFile(filePath string) (*ParseResult, error) {
	return p.ParseFileGeneric(filePath)
}

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

	if alias == "." {
		return &PackageImport{
			PackageName: packageName,
			Alias:       ".",
			ImportType:  "dot_import",
			Symbols:     []string{"*"},
		}
	}

	if alias == "_" {
		return &PackageImport{
			PackageName: packageName,
			Alias:       "_",
			ImportType:  "blank_import",
			Symbols:     nil,
		}
	}

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

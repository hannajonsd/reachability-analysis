package parser

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

type PythonParser struct {
	BaseParser
}

func NewPythonParser() (*PythonParser, error) {
	parser := sitter.NewParser()
	language := python.GetLanguage()
	parser.SetLanguage(language)

	return &PythonParser{
		BaseParser: BaseParser{
			parser:   parser,
			language: language,
			langName: "python",
		},
	}, nil
}

func (p *PythonParser) Close() {
}

func (p *PythonParser) ParseFile(filePath string) (*ParseResult, error) {
	return p.ParseFileGeneric(filePath)
}

func (p *PythonParser) ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error) {
	var imports []PackageImport

	WalkAST(node, source, func(n *sitter.Node) {
		switch n.Type() {
		case "import_statement":
			imps := p.processImportStatement(n, source)
			imports = append(imports, imps...)
		case "import_from_statement":
			imps := p.processImportFromStatement(n, source)
			imports = append(imports, imps...)
		}
	})

	return DeduplicateImports(imports), nil
}

func (p *PythonParser) processImportStatement(node *sitter.Node, source []byte) []PackageImport {
	var imports []PackageImport

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "dotted_as_names":
			imports = append(imports, p.processDottedAsNames(child, source)...)
		case "dotted_name":
			moduleName := string(source[child.StartByte():child.EndByte()])
			if moduleName != "" {
				imports = append(imports, PackageImport{
					PackageName: moduleName,
					Alias:       moduleName,
					ImportType:  "import",
					Symbols:     nil,
				})
			}
		case "aliased_import":
			imp := p.processAliasedImportDirect(child, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		}
	}

	return imports
}

func (p *PythonParser) processImportFromStatement(node *sitter.Node, source []byte) []PackageImport {
	var imports []PackageImport
	var moduleName string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "dotted_name":
			if moduleName == "" {
				moduleName = string(source[child.StartByte():child.EndByte()])
			} else {
				if moduleName != "" {
					symbolName := string(source[child.StartByte():child.EndByte()])
					imports = append(imports, PackageImport{
						PackageName: moduleName,
						Alias:       symbolName,
						ImportType:  "from_import",
						Symbols:     []string{symbolName},
					})
				}
			}
		case "import_list":
			if moduleName != "" {
				imports = append(imports, p.processImportList(child, source, moduleName)...)
			}
		case "wildcard_import":
			if moduleName != "" {
				imports = append(imports, PackageImport{
					PackageName: moduleName,
					Alias:       "*",
					ImportType:  "from_import_wildcard",
					Symbols:     []string{"*"},
				})
			}
		case "aliased_import":
			if moduleName != "" {
				imp := p.processAliasedImport(child, source, moduleName)
				if imp != nil {
					imports = append(imports, *imp)
				}
			}
		case "identifier":
			if moduleName != "" {
				symbolName := string(source[child.StartByte():child.EndByte()])
				if symbolName != "import" && symbolName != "from" {
					imports = append(imports, PackageImport{
						PackageName: moduleName,
						Alias:       symbolName,
						ImportType:  "from_import",
						Symbols:     []string{symbolName},
					})
				}
			}
		}
	}

	return imports
}

func (p *PythonParser) processDottedAsNames(node *sitter.Node, source []byte) []PackageImport {
	var imports []PackageImport

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "dotted_name":
			moduleName := string(source[child.StartByte():child.EndByte()])
			if moduleName != "" {
				imports = append(imports, PackageImport{
					PackageName: moduleName,
					Alias:       moduleName,
					ImportType:  "import",
					Symbols:     nil,
				})
			}
		case "aliased_import":
			imp := p.processAliasedImportDirect(child, source)
			if imp != nil {
				imports = append(imports, *imp)
			}
		}
	}

	return imports
}

func (p *PythonParser) processImportList(node *sitter.Node, source []byte, moduleName string) []PackageImport {
	var imports []PackageImport

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			symbolName := string(source[child.StartByte():child.EndByte()])
			imports = append(imports, PackageImport{
				PackageName: moduleName,
				Alias:       symbolName,
				ImportType:  "from_import",
				Symbols:     []string{symbolName},
			})
		case "aliased_import":
			fmt.Printf("        Processing aliased import\n")
			imp := p.processAliasedImport(child, source, moduleName)
			if imp != nil {
				fmt.Printf("        Created aliased import: %s -> %s\n", imp.PackageName, imp.Alias)
				imports = append(imports, *imp)
			}
		}
	}

	return imports
}

func (p *PythonParser) processAliasedImport(node *sitter.Node, source []byte, moduleName string) *PackageImport {
	var symbolName, aliasName string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		if child.Type() == "identifier" {
			aliasName = string(source[child.StartByte():child.EndByte()])
		} else if child.Type() == "dotted_name" {
			symbolName = string(source[child.StartByte():child.EndByte()])
		}
	}

	if symbolName != "" && aliasName != "" {
		return &PackageImport{
			PackageName: moduleName,
			Alias:       aliasName,
			ImportType:  "from_import_as",
			Symbols:     []string{symbolName},
		}
	}

	return nil
}

func (p *PythonParser) processAliasedImportDirect(node *sitter.Node, source []byte) *PackageImport {
	var moduleName, aliasName string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "dotted_name":
			moduleName = string(source[child.StartByte():child.EndByte()])
		case "identifier":
			aliasName = string(source[child.StartByte():child.EndByte()])
		}
	}

	if moduleName != "" && aliasName != "" {
		return &PackageImport{
			PackageName: moduleName,
			Alias:       aliasName,
			ImportType:  "import_as",
			Symbols:     nil,
		}
	}

	return nil
}

func (p *PythonParser) ExtractCalls(node *sitter.Node, source []byte) ([]string, error) {
	var calls []string

	WalkAST(node, source, func(n *sitter.Node) {
		if n.Type() == "call" {
			call := p.processCall(n, source)
			if call != "" {
				calls = append(calls, call)
			}
		}
	})

	return DeduplicateStrings(calls), nil
}

func (p *PythonParser) processCall(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			// Direct function call: func()
			return string(source[child.StartByte():child.EndByte()])
		case "attribute":
			// Method call: obj.method()
			return p.processAttribute(child, source)
		}
	}

	return ""
}

func (p *PythonParser) processAttribute(node *sitter.Node, source []byte) string {
	// Extract object.attribute
	var object, attribute string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)

		switch child.Type() {
		case "identifier":
			if object == "" {
				object = string(source[child.StartByte():child.EndByte()])
			} else {
				attribute = string(source[child.StartByte():child.EndByte()])
			}
		}
	}

	if object != "" && attribute != "" {
		return fmt.Sprintf("%s.%s", object, attribute)
	}

	return ""
}

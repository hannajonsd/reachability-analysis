package parser

import sitter "github.com/smacker/go-tree-sitter"

type Parser interface {
	ParseFile(filePath string) (*ParseResult, error)
	ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error)
	ExtractCalls(node *sitter.Node, source []byte) ([]string, error)
	GetLanguage() string
	Close()
}

type ParseResult struct {
	Tree     *sitter.Tree
	Source   []byte
	Language string
	FilePath string
}

type PackageImport struct {
	PackageName string   // "lodash", "react", etc.
	Alias       string   // "lod", "_", "React", etc.
	ImportType  string   // "require", "import", "destructured"
	Symbols     []string // For destructured imports: ["forEach", "map"]
}

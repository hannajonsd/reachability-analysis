package parser

import sitter "github.com/smacker/go-tree-sitter"

// Parser defines the interface for language-specific source code parsers
type Parser interface {
	GetLanguage() string
	Close()
	ParseFile(filePath string) (*ParseResult, error)
	ExtractImports(node *sitter.Node, source []byte) ([]PackageImport, error)
	ExtractCalls(node *sitter.Node, source []byte) ([]string, error)
}

// BaseParser provides common functionality for all language parsers
type BaseParser struct {
	parser   *sitter.Parser
	language *sitter.Language
	langName string
}

// ParseResult contains the parsed AST and metadata for a source file
type ParseResult struct {
	Tree     *sitter.Tree
	Source   []byte
	Language string
	FilePath string
}

// PackageImport represents an import statement with its type and imported symbols
type PackageImport struct {
	PackageName string   // "lodash", "react", etc.
	Alias       string   // "lod", "_", "React", etc.
	ImportType  string   // "require", "import", "destructured"
	Symbols     []string // For destructured imports: ["forEach", "map"]
}

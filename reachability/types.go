package reachability

import "github.com/hannajonsd/reachability-analysis/parser"

// PackageImport represents an imported package with its alias and symbols
type PackageImport struct {
	PackageName string   // "lodash", "react", etc.
	Alias       string   // "lod", "_", "React", etc.
	ImportType  string   // "require", "import", "destructured"
	Symbols     []string // For destructured imports: ["forEach", "map"]
}

// AnalysisResult contains the basic vulnerability analysis results for a file
type AnalysisResult struct {
	Imports         []PackageImport
	FunctionCalls   []string
	VulnerableCalls []string
	PackageAliases  []string
}

// EnhancedAnalysisResult extends basic analysis with detailed parser information
type EnhancedAnalysisResult struct {
	Basic           AnalysisResult
	ImportDetails   []parser.PackageImport
	Language        string
	ParseSuccessful bool
}

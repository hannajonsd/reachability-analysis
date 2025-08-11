package reachability

import "github.com/hannajonsd/reachability-analysis/parser"

type PackageImport struct {
	PackageName string   // "lodash", "react", etc.
	Alias       string   // "lod", "_", "React", etc.
	ImportType  string   // "require", "import", "destructured"
	Symbols     []string // For destructured imports: ["forEach", "map"]
}

type AnalysisResult struct {
	Imports         []PackageImport
	FunctionCalls   []string
	VulnerableCalls []string
	PackageAliases  []string
}

type EnhancedAnalysisResult struct {
	Basic           AnalysisResult
	ImportDetails   []parser.PackageImport
	CallDetails     []CallDetail
	Language        string
	ParseSuccessful bool
}

type CallDetail struct {
	FunctionCall string
	Line         int
	Column       int
	Context      string
}

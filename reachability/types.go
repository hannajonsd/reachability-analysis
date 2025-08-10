package reachability

type PackageImport struct {
	PackageName string // "lodash", "react", etc.
	Alias       string // "lod", "_", "React", etc.
	ImportType  string // "require", "import", "destructured"
}

type AnalysisResult struct {
	Imports         []PackageImport
	FunctionCalls   []string
	VulnerableCalls []string
	PackageAliases  []string
}

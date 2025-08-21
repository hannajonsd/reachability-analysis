// reachability/analyzer_treesitter.go
package reachability

import (
	"strings"

	"github.com/hannajonsd/reachability-analysis/parser"
)

type TreeSitterAnalyzer struct {
	useTreeSitter bool
}

// NewTreeSitterAnalyzer creates a new analyzer that uses tree-sitter for code parsing
func NewTreeSitterAnalyzer() *TreeSitterAnalyzer {
	return &TreeSitterAnalyzer{
		useTreeSitter: true,
	}
}

// AnalyzeFileForVulnerabilities analyzes a source file to find calls to vulnerable functions
func (a *TreeSitterAnalyzer) AnalyzeFileForVulnerabilities(filePath string, targetPackage string, osvSymbols []string) (EnhancedAnalysisResult, error) {
	fileParser, err := parser.CreateParser(filePath)
	if err != nil {
		return EnhancedAnalysisResult{}, err
	}
	defer fileParser.Close()

	parseResult, err := fileParser.ParseFile(filePath)
	if err != nil {
		return EnhancedAnalysisResult{}, err
	}
	defer parseResult.Tree.Close()

	imports, err := fileParser.ExtractImports(parseResult.Tree.RootNode(), parseResult.Source)
	if err != nil {
		return EnhancedAnalysisResult{}, err
	}

	calls, err := fileParser.ExtractCalls(parseResult.Tree.RootNode(), parseResult.Source)
	if err != nil {
		return EnhancedAnalysisResult{}, err
	}

	vulnerableCalls := a.findVulnerableCalls(osvSymbols, imports, calls, targetPackage)

	return EnhancedAnalysisResult{
		Basic: AnalysisResult{
			Imports:         convertToLegacyImports(imports),
			FunctionCalls:   calls,
			VulnerableCalls: vulnerableCalls,
			PackageAliases:  getPackageAliasesFromImports(imports, targetPackage),
		},
		ImportDetails:   imports,
		Language:        parseResult.Language,
		ParseSuccessful: true,
	}, nil
}

// findVulnerableCalls identifies function calls that may be vulnerable based on imports and OSV symbols
func (a *TreeSitterAnalyzer) findVulnerableCalls(osvSymbols []string, imports []parser.PackageImport, calls []string, targetPackage string) []string {
	var vulnerable []string

	// Create lookup map for OSV symbols if provided
	var osvMap map[string]bool
	if len(osvSymbols) > 0 {
		osvMap = make(map[string]bool)
		for _, sym := range osvSymbols {
			osvMap[strings.ToLower(sym)] = true
		}
	}

	// Track different import patterns for the target package
	packageAliases := make(map[string]bool)      // import pkg as alias
	destructuredMethods := make(map[string]bool) // from pkg import method
	dotImportPackages := make(map[string]bool)   // import . "pkg" (Go only)

	// Categorize imports based on how they bring in the target package
	for _, imp := range imports {
		if strings.EqualFold(imp.PackageName, targetPackage) || strings.HasPrefix(strings.ToLower(imp.PackageName), strings.ToLower(targetPackage)+"/") || strings.HasPrefix(strings.ToLower(imp.PackageName), strings.ToLower(targetPackage)+".") {
			if imp.ImportType == "destructured" || imp.ImportType == "from_import" || imp.ImportType == "from_import_as" {
				destructuredMethods[strings.ToLower(imp.Alias)] = true
			} else if imp.Alias == "." {
				dotImportPackages[imp.PackageName] = true
			} else {
				packageAliases[imp.Alias] = true
			}
		}
	}

	// Check each function call for vulnerability
	for _, call := range calls {
		isVulnerable := false

		if strings.Contains(call, ".") {
			// Method calls: object.method()
			parts := strings.Split(call, ".")
			if len(parts) >= 2 {
				object := parts[0]
				methodName := strings.ToLower(parts[len(parts)-1])

				if packageAliases[object] {
					if osvMap != nil {
						if osvMap[methodName] {
							isVulnerable = true
						}
					} else {
						isVulnerable = true
					}
				}
			}
		} else {
			// Direct function calls: method()
			callLower := strings.ToLower(call)

			// Check destructured imports
			if destructuredMethods[callLower] {
				if osvMap != nil {
					if osvMap[callLower] {
						isVulnerable = true
					}
				} else {
					isVulnerable = true
				}
			}

			// Check dot imports (Go style)
			if dotImportPackages[targetPackage] {
				if osvMap != nil {
					if osvMap[callLower] {
						isVulnerable = true
					}
				} else {
					isVulnerable = true
				}
			}
		}

		if isVulnerable {
			vulnerable = append(vulnerable, call)
		}
	}

	// Fallback: if no specific OSV symbols found, try broader analysis
	if osvMap != nil && len(vulnerable) == 0 {
		vulnerable = a.findVulnerableCalls(nil, imports, calls, targetPackage)
		return DeduplicateSlice(vulnerable)
	}

	return DeduplicateSlice(vulnerable)
}

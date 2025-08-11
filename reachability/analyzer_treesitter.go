// reachability/analyzer_treesitter.go
package reachability

import (
	"strings"

	"github.com/hannajonsd/reachability-analysis/parser"
)

type TreeSitterAnalyzer struct {
	useTreeSitter bool
}

func NewTreeSitterAnalyzer() *TreeSitterAnalyzer {
	return &TreeSitterAnalyzer{
		useTreeSitter: true,
	}
}

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

func (a *TreeSitterAnalyzer) findVulnerableCalls(osvSymbols []string, imports []parser.PackageImport, calls []string, targetPackage string) []string {
	var vulnerable []string

	osvMap := make(map[string]bool)
	for _, sym := range osvSymbols {
		osvMap[strings.ToLower(sym)] = true
	}

	packageAliases := make(map[string]bool)
	destructuredMethods := make(map[string]bool)

	for _, imp := range imports {
		if strings.EqualFold(imp.PackageName, targetPackage) {
			if imp.ImportType == "destructured" {
				destructuredMethods[strings.ToLower(imp.Alias)] = true
			} else {
				packageAliases[imp.Alias] = true
			}
		}
	}

	for _, call := range calls {
		if strings.Contains(call, ".") {
			parts := strings.Split(call, ".")
			if len(parts) >= 2 {
				object := parts[0]
				methodName := strings.ToLower(parts[len(parts)-1])

				if packageAliases[object] && osvMap[methodName] {
					vulnerable = append(vulnerable, call)
				}
			}
		} else {
			if destructuredMethods[strings.ToLower(call)] && osvMap[strings.ToLower(call)] {
				vulnerable = append(vulnerable, call)
			}
		}
	}

	return DeduplicateSlice(vulnerable)
}

func convertToLegacyImports(imports []parser.PackageImport) []PackageImport {
	var legacy []PackageImport

	for _, imp := range imports {
		legacy = append(legacy, PackageImport{
			PackageName: imp.PackageName,
			Alias:       imp.Alias,
			ImportType:  imp.ImportType,
		})
	}

	return legacy
}

func getPackageAliasesFromImports(imports []parser.PackageImport, targetPackage string) []string {
	var aliases []string
	seen := make(map[string]bool)

	for _, imp := range imports {
		if strings.EqualFold(imp.PackageName, targetPackage) {
			if !seen[imp.Alias] {
				seen[imp.Alias] = true
				aliases = append(aliases, imp.Alias)
			}
		}
	}

	return aliases
}

func DeduplicateSlice(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

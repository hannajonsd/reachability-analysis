// reachability/analyzer_treesitter.go
package reachability

import (
	"fmt"
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

	var osvMap map[string]bool
	if len(osvSymbols) > 0 {
		osvMap = make(map[string]bool)
		for _, sym := range osvSymbols {
			osvMap[strings.ToLower(sym)] = true
		}
	}

	packageAliases := make(map[string]bool)
	destructuredMethods := make(map[string]bool)

	for _, imp := range imports {
		if strings.EqualFold(imp.PackageName, targetPackage) || strings.HasPrefix(strings.ToLower(imp.PackageName), strings.ToLower(targetPackage)+".") {
			if imp.ImportType == "destructured" || imp.ImportType == "from_import" || imp.ImportType == "from_import_as" {
				destructuredMethods[strings.ToLower(imp.Alias)] = true
			} else {
				packageAliases[imp.Alias] = true
			}
		}
	}

	for _, call := range calls {
		isVulnerable := false

		if strings.Contains(call, ".") {
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
			if destructuredMethods[strings.ToLower(call)] {
				if osvMap != nil {
					if osvMap[strings.ToLower(call)] {
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

	if osvMap != nil && len(vulnerable) == 0 {
		return a.findVulnerableCalls(nil, imports, calls, targetPackage)
	}

	if osvMap == nil && len(vulnerable) > 0 {
		fmt.Println("Using package-level vulnerability detection (no specific symbols matched)")
	}

	return DeduplicateSlice(vulnerable)
}

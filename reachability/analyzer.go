package reachability

import (
	"fmt"
	"os"
)

func ExtractImportsAndCalls(path string) ([]PackageImport, []string, error) {
	sourceCode, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	content := string(sourceCode)

	content = removeJSComments(content)

	imports := extractJSImports(content)

	calls := extractMethodCalls(content)

	return imports, calls, nil
}

func AnalyzeFileForVulnerabilities(filePath string, targetPackage string, osvSymbols []string) (AnalysisResult, error) {
	imports, calls, err := ExtractImportsAndCalls(filePath)
	if err != nil {
		return AnalysisResult{}, err
	}

	vulnerableCalls := FindVulnerableCallsWithImports(osvSymbols, imports, calls, targetPackage)

	return AnalysisResult{
		Imports:         imports,
		FunctionCalls:   calls,
		VulnerableCalls: vulnerableCalls,
		PackageAliases:  getPackageAliases(imports, targetPackage),
	}, nil
}

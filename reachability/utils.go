package reachability

import (
	"strings"

	"github.com/hannajonsd/reachability-analysis/parser"
)

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

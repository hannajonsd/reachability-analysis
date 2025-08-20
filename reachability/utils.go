package reachability

import (
	"strings"

	"github.com/hannajonsd/reachability-analysis/parser"
)

// convertToLegacyImports converts parser.PackageImport to legacy PackageImport format
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

// getPackageAliasesFromImports extracts all aliases used for a specific target package
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

// DeduplicateSlice removes duplicate strings from a slice while preserving order
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

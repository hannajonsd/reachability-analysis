package reachability

import "strings"

func FindVulnerableCallsWithImports(osvSymbols []string, imports []PackageImport, calls []string, targetPackage string) []string {
	var vulnerable []string

	osvMap := make(map[string]bool)
	for _, sym := range osvSymbols {
		osvMap[strings.ToLower(sym)] = true
	}

	packageAliases := make(map[string]bool)
	for _, imp := range imports {
		if strings.EqualFold(imp.PackageName, targetPackage) {
			packageAliases[imp.Alias] = true
		}
	}

	for _, call := range calls {
		parts := strings.Split(call, ".")
		if len(parts) >= 2 {
			object := parts[0]
			methodName := strings.ToLower(parts[len(parts)-1])

			if packageAliases[object] && osvMap[methodName] {
				vulnerable = append(vulnerable, call)
			}
		}

		if osvMap[strings.ToLower(call)] {
			for _, imp := range imports {
				if strings.EqualFold(imp.PackageName, targetPackage) &&
					imp.ImportType == "destructured" &&
					strings.EqualFold(imp.Alias, call) {
					vulnerable = append(vulnerable, call)
					break
				}
			}
		}
	}

	return DeduplicateSlice(vulnerable)
}

func getPackageAliases(imports []PackageImport, targetPackage string) []string {
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

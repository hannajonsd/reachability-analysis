package analyzer

import (
	"fmt"
	"strings"

	"github.com/hannajonsd/reachability-analysis/osv"
	"github.com/hannajonsd/reachability-analysis/reachability"
)

// AnalyzeDependency analyzes a specific dependency for vulnerabilities across all files
func (va *VulnerabilityAnalyzer) AnalyzeDependency(dep SimpleDependency, sourceFiles []string, verbose bool) (int, []FileVulnerability, error) {
	if dep.Name == "" {
		return 0, nil, fmt.Errorf("dependency name cannot be empty")
	}

	hierarchicalPaths := va.getHierarchicalPaths(dep.Name, dep.Ecosystem)

	queryVersion := va.getQueryVersion(dep.Version, dep.Ecosystem)

	isUnknownVersion := dep.Version == "" || dep.Version == "*" || dep.Version == "latest" ||
		strings.Contains(dep.Version, "^") || strings.Contains(dep.Version, "~")

	if isUnknownVersion && verbose {
		fmt.Printf("  %s (unknown version: '%s') - checking all known vulnerabilities for package\n", dep.Name, dep.Version)
	}

	var allFileVulnerabilities []FileVulnerability
	totalAdvisories := 0

	// Check each hierarchical level
	for _, modulePath := range hierarchicalPaths {
		if verbose {
			fmt.Printf("  Checking %s...\n", modulePath)
		}

		advisories, err := osv.QueryOSV(modulePath, queryVersion, dep.Ecosystem)
		if err != nil {
			if verbose {
				fmt.Printf("    OSV query failed for %s: %v, skipping package\n", dep.Name, err)
			}
			continue
		}

		if len(advisories) == 0 {
			if verbose {
				fmt.Printf("    No advisories found for %s\n", modulePath)
			}
			continue
		}

		if verbose {
			if isUnknownVersion {
				fmt.Printf("    Found %d advisories for %s (all versions - may not all apply)\n", len(advisories), modulePath)
			} else {
				fmt.Printf("    Found %d advisories for %s\n", len(advisories), modulePath)
			}
		}

		totalAdvisories += len(advisories)

		// Process each advisory
		for i, adv := range advisories {
			if verbose {
				fmt.Printf("    Advisory %d: %s\n", i+1, adv.ID)
			}

			// Extract vulnerable symbols from advisory
			var allOSVSymbols []string
			for _, affected := range adv.Affected {
				for _, imp := range affected.EcosystemSpecific.Imports {
					allOSVSymbols = append(allOSVSymbols, imp.Symbols...)
				}
			}

			// Extract additional symbols from advisory text
			extractedSymbols := osv.ExtractPossibleSymbols(modulePath, adv.Summary, adv.Details)
			allOSVSymbols = append(allOSVSymbols, extractedSymbols...)
			uniqueOSVSymbols := reachability.DeduplicateSlice(allOSVSymbols)

			// Check each source file for vulnerable calls
			for _, filePath := range sourceFiles {
				result, err := va.treeSitterAnalyzer.AnalyzeFileForVulnerabilities(filePath, modulePath, uniqueOSVSymbols)
				if err != nil {
					continue
				}

				if len(result.Basic.VulnerableCalls) > 0 {
					advisoryDetail := AdvisoryDetail{
						ID:                adv.ID,
						Summary:           va.formatAdvisorySummary(adv.Summary, dep, modulePath, isUnknownVersion),
						Symbols:           uniqueOSVSymbols,
						HasReachableCalls: true,
						VulnerableFiles: []VulnerableFile{{
							FilePath:        filePath,
							VulnerableCalls: result.Basic.VulnerableCalls,
						}},
					}

					fileVuln := va.findOrCreateFileVulnerability(&allFileVulnerabilities, filePath, dep)
					fileVuln.VulnerableCalls = append(fileVuln.VulnerableCalls, result.Basic.VulnerableCalls...)
					fileVuln.Advisories = append(fileVuln.Advisories, advisoryDetail)

					if verbose {
						if isUnknownVersion {
							fmt.Printf("      File %s: %v (unknown version)\n", filePath, result.Basic.VulnerableCalls)
						} else {
							fmt.Printf("      File %s: %v (via %s)\n", filePath, result.Basic.VulnerableCalls, modulePath)
						}
					}
				}
			}
		}
	}

	// Deduplicate vulnerable calls in each file
	for i := range allFileVulnerabilities {
		allFileVulnerabilities[i].VulnerableCalls = reachability.DeduplicateSlice(allFileVulnerabilities[i].VulnerableCalls)
	}

	return totalAdvisories, allFileVulnerabilities, nil
}

// getHierarchicalPaths returns appropriate hierarchical paths based on ecosystem
func (va *VulnerabilityAnalyzer) getHierarchicalPaths(name, ecosystem string) []string {
	switch ecosystem {
	case "Go":
		return generateHierarchicalPaths(name)
	case "npm":
		return va.generateJavaScriptHierarchicalPaths(name)
	case "PyPI":
		return va.generatePythonHierarchicalPaths(name)
	default:
		return []string{name}
	}
}

// getQueryVersion determines the version string to use for OSV queries
func (va *VulnerabilityAnalyzer) getQueryVersion(version, ecosystem string) string {
	if ecosystem == "Go" {
		return ""
	}

	isUnknownVersion := version == "" || version == "*" || version == "latest" ||
		strings.Contains(version, "^") || strings.Contains(version, "~")

	if isUnknownVersion {
		return ""
	}
	return version
}

// formatAdvisorySummary formats the advisory summary with appropriate prefixes
func (va *VulnerabilityAnalyzer) formatAdvisorySummary(summary string, dep SimpleDependency, modulePath string, isUnknownVersion bool) string {
	result := summary

	if modulePath != dep.Name {
		result = fmt.Sprintf("[HIERARCHICAL: %s->%s] %s", dep.Name, modulePath, result)
	}

	if isUnknownVersion {
		result = "[UNKNOWN VERSION] " + result
	}

	return result
}

// findOrCreateFileVulnerability finds existing or creates new FileVulnerability for a file
func (va *VulnerabilityAnalyzer) findOrCreateFileVulnerability(vulnerabilities *[]FileVulnerability, filePath string, dep SimpleDependency) *FileVulnerability {
	for i := range *vulnerabilities {
		if (*vulnerabilities)[i].FilePath == filePath {
			return &(*vulnerabilities)[i]
		}
	}

	*vulnerabilities = append(*vulnerabilities, FileVulnerability{
		FilePath:        filePath,
		PackageName:     dep.Name,
		PackageVersion:  dep.Version,
		VulnerableCalls: []string{},
		Advisories:      []AdvisoryDetail{},
	})

	return &(*vulnerabilities)[len(*vulnerabilities)-1]
}

// generateHierarchicalPaths creates all possible module paths from an import
func generateHierarchicalPaths(importPath string) []string {
	if importPath == "" {
		return []string{}
	}

	parts := strings.Split(importPath, "/")
	var paths []string

	for i := len(parts); i >= 1; i-- {
		path := strings.Join(parts[:i], "/")
		paths = append(paths, path)
	}

	return paths
}

// generateJavaScriptHierarchicalPaths creates hierarchical paths for npm packages
func (va *VulnerabilityAnalyzer) generateJavaScriptHierarchicalPaths(packageName string) []string {
	paths := []string{packageName}

	if strings.HasPrefix(packageName, "@") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			scopeOnly := parts[0]
			paths = append(paths, scopeOnly)

			if len(scopeOnly) > 1 {
				withoutAt := scopeOnly[1:]
				paths = append(paths, withoutAt)
			}
		}
	}

	if strings.Contains(packageName, "/") && !strings.HasPrefix(packageName, "@") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			basePkg := parts[0]
			paths = append(paths, basePkg)
		}
	}

	return paths
}

// generatePythonHierarchicalPaths creates hierarchical paths for Python packages
func (va *VulnerabilityAnalyzer) generatePythonHierarchicalPaths(packageName string) []string {
	paths := []string{packageName}

	if strings.Contains(packageName, "-") {
		paths = append(paths, strings.ReplaceAll(packageName, "-", "_"))
	}

	if strings.Contains(packageName, ".") {
		parts := strings.Split(packageName, ".")

		for i := len(parts) - 1; i >= 1; i-- {
			parentPath := strings.Join(parts[:i], ".")
			paths = append(paths, parentPath)
		}
	}

	if strings.Contains(packageName, "-") {
		parts := strings.Split(packageName, "-")
		for _, part := range parts {
			if len(part) > 2 {
				paths = append(paths, part)
			}
		}
	}

	return paths
}

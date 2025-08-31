package analyzer

import (
	"fmt"
	"strings"

	"github.com/hannajonsd/reachability-analysis/reachability"
)

// displayResults shows the final analysis results in a formatted output
func (va *VulnerabilityAnalyzer) displayResults(
	fileVulnerabilities map[string][]FileVulnerability,
	discoveredDeps []DiscoveredDependency,
	sourceFiles []string,
	vulnerablePackages int,
) {
	manifestCount := 0
	codeOnlyCount := 0
	unknownVersionCount := 0
	semverRangeCount := 0

	for _, dep := range discoveredDeps {
		if dep.IsInManifest {
			if dep.Version == "" || dep.Version == "*" || dep.Version == "latest" {
				unknownVersionCount++
			} else if va.isSemverRange(dep.ManifestVersion) {
				semverRangeCount++
			} else {
				manifestCount++
			}
		} else {
			codeOnlyCount++
		}
	}

	fmt.Printf("\nExternal dependencies discovered: %d\n", len(discoveredDeps))
	fmt.Printf("  - With exact versions (in manifests): %d\n", manifestCount)
	fmt.Printf("  - With semver ranges (in manifests): %d\n", semverRangeCount)
	fmt.Printf("  - Unknown versions (in manifests): %d\n", unknownVersionCount)
	fmt.Printf("  - Unknown versions (code-only): %d\n\n", codeOnlyCount)

	if len(fileVulnerabilities) == 0 {
		if len(sourceFiles) == 0 {
			fmt.Println("  No source files found to analyze")
		} else {
			fmt.Println("✅ No reachable vulnerabilities found!")
			fmt.Printf("   Analyzed %d source files across %d external dependencies\n", len(sourceFiles), len(discoveredDeps))
		}
		return
	}

	fileCount := 0
	for fp := range fileVulnerabilities {
		if fp != "" {
			fileCount++
		}
	}

	fmt.Printf("❌ Found vulnerabilities in %d %s, packages with vulnerabilities %d:\n\n",
		fileCount, pluralize("file", fileCount), vulnerablePackages)

	shownPkgLevel := make(map[string]map[string]bool)

	for filePath, vulns := range fileVulnerabilities {
		if filePath == "" {
			continue
		}
		fmt.Printf(" %s\n", filePath)

		// Group by packageKey
		packageVulns := make(map[string][]FileVulnerability)
		for _, vuln := range vulns {
			key := vuln.PackageName + "@"
			if vuln.PackageVersion == "" || vuln.PackageVersion == "*" {
				key += "unknown"
			} else {
				key += vuln.PackageVersion
			}
			packageVulns[key] = append(packageVulns[key], vuln)
		}

		for packageKey, packageVulnList := range packageVulns {
			advisoryCount := 0
			allCalls := []string{}
			hasUnknownVersion := false
			isCodeOnly := false
			isSemverRange := false
			originalVersion := ""

			uniqueSymbIDs := make(map[string]bool)

			for _, v := range packageVulnList {
				for _, s := range v.SymbollessAdvisories {
					uniqueSymbIDs[s.ID] = true
				}
			}

			for _, vuln := range packageVulnList {
				advisoryCount += len(vuln.Advisories)
				allCalls = append(allCalls, vuln.VulnerableCalls...)

				for _, advisory := range vuln.Advisories {
					if strings.Contains(advisory.Summary, "[UNKNOWN VERSION]") {
						hasUnknownVersion = true
					}
				}

				for _, discDep := range discoveredDeps {
					if discDep.Name == vuln.PackageName {
						if !discDep.IsInManifest {
							isCodeOnly = true
						} else {
							originalVersion = discDep.ManifestVersion
							isSemverRange = va.isSemverRange(originalVersion)
						}
					}
				}
			}

			uniqueCalls := reachability.DeduplicateSlice(allCalls)
			symbollessCount := len(uniqueSymbIDs)

			if hasUnknownVersion || isCodeOnly || isSemverRange {
				if symbollessCount > 0 {
					fmt.Printf("  %s (%d reachable %s + %d %s manual review)\n",
						packageKey,
						len(uniqueCalls), pluralize("vulnerability", len(uniqueCalls)),
						symbollessCount, pluralize("requires", symbollessCount))
				} else if isSemverRange {
					fmt.Printf("  %s@%s (%d potential %s used in code - semver range)\n",
						packageVulnList[0].PackageName, originalVersion,
						advisoryCount, pluralize("advisory", advisoryCount))
				} else if isCodeOnly {
					fmt.Printf("  %s (%d potential %s used in code - not in manifest)\n",
						packageKey, advisoryCount, pluralize("advisory", advisoryCount))
				} else {
					fmt.Printf("  %s (%d potential %s used in code - unknown version)\n",
						packageKey, advisoryCount, pluralize("advisory", advisoryCount))
				}

				if symbollessCount == 0 {
					fmt.Printf("     Specify exact version for precise analysis\n")
				}
			} else {
				if symbollessCount > 0 {
					fmt.Printf("  %s (%d vulnerable %s + %d %s manual review)\n",
						packageKey,
						len(uniqueCalls), pluralize("function", len(uniqueCalls)),
						symbollessCount, pluralize("requires", symbollessCount))
				} else {
					fmt.Printf("  %s (%d vulnerable %s)\n",
						packageKey, len(uniqueCalls), pluralize("function", len(uniqueCalls)))
				}
			}

			// Display vulnerable calls with advisory IDs
			for _, call := range uniqueCalls {
				var advisoryID string
				for _, vuln := range packageVulnList {
					for _, advisory := range vuln.Advisories {
						for _, vulnFile := range advisory.VulnerableFiles {
							for _, vulnCall := range vulnFile.VulnerableCalls {
								if vulnCall == call {
									advisoryID = advisory.ID
									break
								}
							}
							if advisoryID != "" {
								break
							}
						}
						if advisoryID != "" {
							break
						}
					}
					if advisoryID != "" {
						break
					}
				}
				if advisoryID != "" {
					fmt.Printf("    - %s (%s)\n", call, advisoryID)
				} else {
					fmt.Printf("    - %s\n", call)
				}
			}

			// Display manual review section
			if symbollessCount > 0 {
				fmt.Println()
				fmt.Println("   Advisories with no extracted symbols (package-wide):")
				seen := make(map[string]bool)

				for _, vuln := range packageVulnList {
					for _, symbolless := range vuln.SymbollessAdvisories {
						if !seen[symbolless.ID] {
							seen[symbolless.ID] = true
							fmt.Printf("    - %s: \"%s\"\n", symbolless.ID, symbolless.Summary)
							fmt.Printf("      https://osv.dev/vulnerability/%s\n", symbolless.ID)
						}
					}
				}
				fmt.Println()

				if shownPkgLevel[packageKey] == nil {
					shownPkgLevel[packageKey] = make(map[string]bool)
				}
				for id := range seen {
					shownPkgLevel[packageKey][id] = true
				}
			}
		}

		fmt.Println()
	}

}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}

	switch word {
	case "vulnerability":
		return "vulnerabilities"
	case "advisory":
		return "advisories"
	case "function":
		return "functions"
	case "file":
		return "files"
	}

	if word == "requires" {
		return "require"
	}

	return word + "s"
}

// displayDependencies shows discovered dependencies organized by manifest status
func (va *VulnerabilityAnalyzer) displayDependencies(deps []DiscoveredDependency) {
	manifestDeps := []DiscoveredDependency{}
	codeOnlyDeps := []DiscoveredDependency{}

	for _, dep := range deps {
		if dep.IsInManifest {
			manifestDeps = append(manifestDeps, dep)
		} else {
			codeOnlyDeps = append(codeOnlyDeps, dep)
		}
	}

	if len(manifestDeps) > 0 {
		fmt.Printf("\n With versions (%d):\n", len(manifestDeps))
		for _, dep := range manifestDeps {
			fmt.Printf("  - %s@%s [%s] (used in %d files)\n", dep.Name, dep.Version, dep.Ecosystem, len(dep.FoundInFiles))
		}
	}

	if len(codeOnlyDeps) > 0 {
		fmt.Printf("\n  Unknown Versions (%d):\n", len(codeOnlyDeps))
		for _, dep := range codeOnlyDeps {
			fmt.Printf("  - %s@unknown [%s] (used in %d files)\n", dep.Name, dep.Ecosystem, len(dep.FoundInFiles))
			for _, file := range dep.FoundInFiles {
				fmt.Printf("     %s\n", file)
			}
		}
	}
}

// isSemverRange checks if a version string represents a semver range
func (va *VulnerabilityAnalyzer) isSemverRange(version string) bool {
	if version == "" {
		return false
	}

	semverRangeIndicators := []string{"^", "~", ">=", "<=", ">", "<", " - ", "||", ","}

	for _, indicator := range semverRangeIndicators {
		if strings.Contains(version, indicator) {
			return true
		}
	}

	return false
}

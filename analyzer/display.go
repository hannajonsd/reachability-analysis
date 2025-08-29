package analyzer

import (
	"fmt"
	"strings"

	"github.com/hannajonsd/reachability-analysis/reachability"
)

// displayResults shows the final analysis results in a formatted output
func (va *VulnerabilityAnalyzer) displayResults(fileVulnerabilities map[string][]FileVulnerability, discoveredDeps []DiscoveredDependency, sourceFiles []string, vulnerablePackages, totalVulnerabilities int) {
	if len(fileVulnerabilities) == 0 {
		if len(sourceFiles) == 0 {
			fmt.Println("  No source files found to analyze")
		} else {
			fmt.Println("✅ No reachable vulnerabilities found!")
			fmt.Printf("   Analyzed %d source files across %d external dependencies\n", len(sourceFiles), len(discoveredDeps))
		}
	} else {
		fmt.Printf("\nFound vulnerabilities in %d files:\n\n", len(fileVulnerabilities))

		for filePath, vulns := range fileVulnerabilities {
			if filePath == "" {
				continue
			}
			fmt.Printf(" %s\n", filePath)

			// Group vulnerabilities by package
			packageVulns := make(map[string][]FileVulnerability)
			for _, vuln := range vulns {
				var key string
				if vuln.PackageVersion == "" || vuln.PackageVersion == "*" {
					key = fmt.Sprintf("%s@unknown", vuln.PackageName)
				} else {
					key = fmt.Sprintf("%s@%s", vuln.PackageName, vuln.PackageVersion)
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
				symbollessCount := 0

				for _, vuln := range packageVulnList {
					advisoryCount += len(vuln.Advisories)
					allCalls = append(allCalls, vuln.VulnerableCalls...)
					symbollessCount += len(vuln.SymbollessAdvisories)

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

				if hasUnknownVersion || isCodeOnly || isSemverRange {
					if symbollessCount > 0 {
						fmt.Printf("    %s (%d reachable vulnerability + %d requires manual review)\n",
							packageKey, len(uniqueCalls), symbollessCount)
					} else if isSemverRange {
						fmt.Printf("    %s@%s (%d potential advisories used in code - semver range)\n",
							packageVulnList[0].PackageName, originalVersion, advisoryCount)
					} else if isCodeOnly {
						fmt.Printf("    %s (%d potential advisories used in code - not in manifest)\n",
							packageKey, advisoryCount)
					} else {
						fmt.Printf("    %s (%d potential advisories used in code - unknown version)\n",
							packageKey, advisoryCount)
					}

					if symbollessCount == 0 {
						fmt.Printf("       Specify exact version for precise analysis\n")
					}
				} else {
					if symbollessCount > 0 {
						fmt.Printf("  ❌ %s (%d vulnerable functions + %d requires manual review)\n",
							packageKey, len(uniqueCalls), symbollessCount)
					} else {
						fmt.Printf("  ❌ %s (%d vulnerable functions)\n", packageKey, len(uniqueCalls))
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
						fmt.Printf("     - %s (%s)\n", call, advisoryID)
					} else {
						fmt.Printf("     - %s\n", call)
					}
				}

				// Display manual review section
				if symbollessCount > 0 {
					fmt.Println()
					fmt.Println("Manual Review Required:")
					seen := make(map[string]bool)
					for _, vuln := range packageVulnList {
						for _, symbolless := range vuln.SymbollessAdvisories {
							if !seen[symbolless.ID] {
								seen[symbolless.ID] = true
								fmt.Printf("     - %s: \"%s\"\n", symbolless.ID, symbolless.Summary)
								fmt.Printf("       https://osv.dev/vulnerability/%s\n", symbolless.ID)
							}
						}
					}
				}
			}
			fmt.Println()
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("SUMMARY")
	fmt.Printf("External dependencies discovered: %d\n", len(discoveredDeps))

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

	fmt.Printf("  - With exact versions (in manifests): %d\n", manifestCount)
	fmt.Printf("  - With semver ranges (in manifests): %d\n", semverRangeCount)
	fmt.Printf("  - Unknown versions (in manifests): %d\n", unknownVersionCount)
	fmt.Printf("  - Unknown versions (code-only): %d\n", codeOnlyCount)
	fmt.Printf("Packages with vulnerabilities: %d\n", vulnerablePackages)
	fmt.Printf("Total vulnerability advisories: %d\n", totalVulnerabilities)
	fmt.Printf("Files with reachable vulnerabilities: %d\n", len(fileVulnerabilities))
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
		fmt.Printf("\n With Versions (%d):\n", len(manifestDeps))
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

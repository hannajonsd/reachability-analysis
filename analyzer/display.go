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

				if hasUnknownVersion || isCodeOnly || isSemverRange {
					if isSemverRange {
						fmt.Printf("    %s@%s (%d potential advisories used in code - semver range)\n",
							packageVulnList[0].PackageName, originalVersion, advisoryCount)
						fmt.Printf("       Checking all versions for a comprehensive analysis\n")
					} else if isCodeOnly {
						fmt.Printf("    %s (%d potential advisories used in code - not in manifest)\n",
							packageKey, advisoryCount)
						fmt.Printf("       Add to manifest file for precise analysis\n")
					} else {
						fmt.Printf("    %s (%d potential advisories used in code - unknown version)\n",
							packageKey, advisoryCount)
						fmt.Printf("       Specify exact version for precise analysis\n")
					}
				} else {
					uniqueFunctionCount := len(uniqueCalls)
					fmt.Printf("  ❌ %s (%d vulnerable functions)\n", packageKey, uniqueFunctionCount)
				}

				for _, call := range uniqueCalls {
					fmt.Printf("     - %s\n", call)
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

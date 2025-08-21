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

				for _, vuln := range packageVulnList {
					advisoryCount += len(vuln.Advisories)
					allCalls = append(allCalls, vuln.VulnerableCalls...)

					for _, advisory := range vuln.Advisories {
						if strings.Contains(advisory.Summary, "[UNKNOWN VERSION]") {
							hasUnknownVersion = true
						}
					}

					for _, discDep := range discoveredDeps {
						if discDep.Name == vuln.PackageName && !discDep.IsInManifest {
							isCodeOnly = true
						}
					}
				}

				uniqueCalls := reachability.DeduplicateSlice(allCalls)

				if hasUnknownVersion || isCodeOnly {
					fmt.Printf("    %s (%d potential vulnerabilities", packageKey, advisoryCount)
					if isCodeOnly {
						fmt.Printf(" - not in manifest")
					} else {
						fmt.Printf(" - unknown version")
					}
					fmt.Printf(")\n")
					fmt.Printf("       ")
					if isCodeOnly {
						fmt.Printf("Add to manifest file for precise analysis\n")
					} else {
						fmt.Printf("Specify exact version for precise analysis\n")
					}
				} else {
					fmt.Printf("  ❌ %s (%d vulnerabilities)\n", packageKey, advisoryCount)
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

	for _, dep := range discoveredDeps {
		if dep.IsInManifest {
			if dep.Version == "" || dep.Version == "*" || dep.Version == "latest" ||
				strings.Contains(dep.Version, "^") || strings.Contains(dep.Version, "~") {
				unknownVersionCount++
			} else {
				manifestCount++
			}
		} else {
			codeOnlyCount++
		}
	}

	fmt.Printf("  - With versions (in manifests): %d\n", manifestCount)
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

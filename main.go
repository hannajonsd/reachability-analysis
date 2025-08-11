package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/hannajonsd/reachability-analysis/osv"
	"github.com/hannajonsd/reachability-analysis/reachability"
)

func main() {
	fmt.Println("=== Vulnerability Reachability Analysis with Tree-sitter ===")

	// packageName := "lodash"
	// packageVersion := "4.17.20"
	// ecosystem := "npm"
	// filePath := "testdata/example.js"
	// filePath := "testdata/example.py"
	// packageName := "requests"
	// ecosystem := "PyPI"
	// packageVersion := "2.30.0"
	filePath := "testdata/example.go"
	packageName := "golang.org/x/text"
	ecosystem := "Go"
	packageVersion := "0.3.7"

	analyzer := reachability.NewTreeSitterAnalyzer()

	fmt.Println("\nAnalyzing file structure...")
	result, err := analyzer.AnalyzeFileForVulnerabilities(filePath, packageName, []string{})
	if err != nil {
		log.Printf("Failed to analyze file: %v", err)
		return
	}

	displayImports(result)

	fmt.Println("\nQuerying OSV API...")
	advisories, err := osv.QueryOSV(packageName, packageVersion, ecosystem)
	if err != nil {
		log.Printf("Failed to query OSV: %v", err)
		return
	}

	fmt.Printf("Found %d advisories\n", len(advisories))
	fmt.Println(strings.Repeat("-", 60))

	for i, adv := range advisories {
		fmt.Printf("\nAdvisory %d: %s\n", i+1, adv.ID)
		fmt.Printf("Summary: %s\n", adv.Summary)

		var allOSVSymbols []string
		for _, affected := range adv.Affected {
			for _, imp := range affected.EcosystemSpecific.Imports {
				allOSVSymbols = append(allOSVSymbols, imp.Symbols...)
			}
		}

		extractedSymbols := osv.ExtractPossibleSymbols(packageName, adv.Summary, adv.Details)
		allOSVSymbols = append(allOSVSymbols, extractedSymbols...)
		uniqueOSVSymbols := reachability.DeduplicateSlice(allOSVSymbols)

		fmt.Printf("OSV Symbols (%d): %v\n", len(uniqueOSVSymbols), uniqueOSVSymbols)

		advisoryResult, err := analyzer.AnalyzeFileForVulnerabilities(filePath, packageName, uniqueOSVSymbols)
		if err != nil {
			log.Printf("Analysis failed for advisory %s: %v", adv.ID, err)
			continue
		}

		displayVulnerabilityResults(advisoryResult, packageName)
		fmt.Println(strings.Repeat("-", 60))
	}
}

func displayImports(result reachability.EnhancedAnalysisResult) {
	fmt.Printf("Detected Imports (%d):\n", len(result.ImportDetails))

	for _, imp := range result.ImportDetails {
		if len(imp.Symbols) > 0 {
			fmt.Printf("  - %s as '%s' (destructured: %v)\n", imp.PackageName, imp.Alias, imp.Symbols)
		} else {
			fmt.Printf("  - %s as '%s' (%s)\n", imp.PackageName, imp.Alias, imp.ImportType)
		}
	}
}

func displayVulnerabilityResults(result reachability.EnhancedAnalysisResult, packageName string) {
	if len(result.Basic.PackageAliases) > 0 {
		fmt.Printf("\nPackage aliases for %s: %v\n", packageName, result.Basic.PackageAliases)
	}

	fmt.Println("\nVulnerability Analysis:")
	if len(result.Basic.VulnerableCalls) > 0 {
		fmt.Printf("❌ VULNERABLE CALLS DETECTED (%d):\n", len(result.Basic.VulnerableCalls))
		for _, call := range result.Basic.VulnerableCalls {
			fmt.Printf("   %s\n", call)
		}

	} else {
		fmt.Println("✅ No vulnerable function calls detected for this advisory")
	}
}

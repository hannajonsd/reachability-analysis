package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/hannajonsd/reachability-analysis/osv"
	"github.com/hannajonsd/reachability-analysis/reachability"
)

func main() {
	fmt.Println("=== Vulnerability Reachability Analysis ===")

	packageName := "lodash"
	packageVersion := "4.17.20"
	ecosystem := "npm"
	filePath := "testdata/example.js"

	fmt.Println("\n1. Querying OSV API...")
	advisories, err := osv.QueryOSV(packageName, packageVersion, ecosystem)
	if err != nil {
		log.Printf("Failed to query OSV: %v", err)
		return
	}

	fmt.Printf("Found %d advisories\n", len(advisories))
	fmt.Println(strings.Repeat("-", 50))

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

		fmt.Println("\n2. Analyzing code with import detection...")

		result, err := reachability.AnalyzeFileForVulnerabilities(filePath, packageName, uniqueOSVSymbols)
		if err != nil {
			log.Printf("Analysis failed: %v", err)
			continue
		}

		fmt.Printf("Detected Imports (%d):\n", len(result.Imports))
		for _, imp := range result.Imports {
			fmt.Printf("  - %s as '%s' \n", imp.PackageName, imp.Alias)
		}

		if len(result.PackageAliases) > 0 {
			fmt.Printf("Package aliases for %s: %v\n", packageName, result.PackageAliases)
		}

		fmt.Printf("\nFunction Calls (%d):\n", len(result.FunctionCalls))
		for _, call := range result.FunctionCalls {
			fmt.Printf("  %s\n", call)
		}

		fmt.Println("\n3. Vulnerability Analysis:")
		if len(result.VulnerableCalls) > 0 {
			fmt.Printf("VULNERABLE CALLS DETECTED (%d):\n", len(result.VulnerableCalls))
			for _, call := range result.VulnerableCalls {
				fmt.Printf("  - %s\n", call)
			}
		} else {
			fmt.Println("No vulnerable function calls detected for this advisory")
		}

		fmt.Println(strings.Repeat("-", 50))
	}

}

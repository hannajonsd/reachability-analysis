package main

import (
	"fmt"

	"github.com/hannajonsd/reachability-analysis/osv"
)

func main() {
	advisories, err := osv.QueryOSV("lodash", "4.17.20", "npm")
	// advisories, err := osv.QueryOSV("golang.org/x/text", "0.3.8", "Go")
	if err != nil {
		fmt.Println("Failed to query OSV:", err)
		return
	}

	for _, adv := range advisories {
		fmt.Println("ID:", adv.ID)
		fmt.Println("Summary:", adv.Summary)
		fmt.Println("Details:", adv.Details)

		var combinedSymbols []string
		for _, aff := range adv.Affected {
			for _, imp := range aff.EcosystemSpecific.Imports {
				combinedSymbols = append(combinedSymbols, imp.Symbols...)
			}
		}

		extractedSymbols := osv.ExtractPossibleSymbols("lodash", adv.Summary, adv.Details)

		combinedSymbols = append(combinedSymbols, extractedSymbols...)

		uniqueMap := make(map[string]struct{})
		var uniqueSymbols []string
		for _, s := range combinedSymbols {
			if _, exists := uniqueMap[s]; !exists {
				uniqueMap[s] = struct{}{}
				uniqueSymbols = append(uniqueSymbols, s)
			}
		}

		fmt.Println("Combined Symbols:", uniqueSymbols)
	}
}

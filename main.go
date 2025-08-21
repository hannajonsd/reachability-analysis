package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hannajonsd/reachability-analysis/analyzer"
)

func main() {
	var (
		repoPath = flag.String("path", ".", "Path to repository to analyze")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)
	flag.Parse()

	fmt.Println("=== Vulnerability Reachability Analysis ===")

	vuln := analyzer.New()
	reachableVulnCount, err := vuln.AnalyzeRepository(*repoPath, *verbose)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	if reachableVulnCount > 0 {
		os.Exit(1)
	}

	os.Exit(0)
}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hannajonsd/reachability-analysis/osv"
	"github.com/hannajonsd/reachability-analysis/parser"
	"github.com/hannajonsd/reachability-analysis/reachability"
	"github.com/hannajonsd/reachability-analysis/version_lookup"
)

type VulnerabilityAnalyzer struct {
	treeSitterAnalyzer *reachability.TreeSitterAnalyzer
}

type SimpleDependency struct {
	Name      string
	Version   string
	Ecosystem string
}

type DiscoveredDependency struct {
	Name            string
	Version         string
	Ecosystem       string
	FoundInFiles    []string
	IsInManifest    bool
	ManifestVersion string
}

type FileVulnerability struct {
	FilePath        string
	PackageName     string
	PackageVersion  string
	VulnerableCalls []string
	Advisories      []AdvisoryDetail
}

type AdvisoryDetail struct {
	ID                string
	Summary           string
	Symbols           []string
	HasReachableCalls bool
	VulnerableFiles   []VulnerableFile
}

type VulnerableFile struct {
	FilePath        string
	VulnerableCalls []string
}

func VulnerabilityAnalyzerFunc() *VulnerabilityAnalyzer {
	return &VulnerabilityAnalyzer{
		treeSitterAnalyzer: reachability.NewTreeSitterAnalyzer(),
	}
}

func main() {
	var (
		repoPath = flag.String("path", ".", "Path to repository to analyze")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)
	flag.Parse()

	fmt.Println("=== Vulnerability Reachability Analysis ===")

	analyzer := VulnerabilityAnalyzerFunc()
	if err := analyzer.AnalyzeRepository(*repoPath, *verbose); err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
}

func (va *VulnerabilityAnalyzer) AnalyzeRepository(repoPath string, verbose bool) error {
	fmt.Printf("Analyzing repository: %s\n", repoPath)

	sourceFiles, err := va.findSourceFiles(repoPath)
	if err != nil {
		return fmt.Errorf("failed to find source files: %w", err)
	}
	fmt.Printf("Found %d source files for analysis\n", len(sourceFiles))

	discoveredDeps, err := va.DiscoverDependencies(sourceFiles, repoPath)
	if err != nil {
		return fmt.Errorf("failed to discover dependencies: %w", err)
	}

	if verbose {
		va.displayDependencies(discoveredDeps)
	}

	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("VULNERABILITY ANALYSIS BY FILE")

	fileVulnerabilities := make(map[string][]FileVulnerability)
	totalVulnerabilities := 0
	vulnerablePackages := 0

	for _, dep := range discoveredDeps {
		if verbose {
			if dep.IsInManifest {
				fmt.Printf("Analyzing %s@%s (%s) [found in manifest]...\n", dep.Name, dep.Version, dep.Ecosystem)
			} else {
				fmt.Printf("Analyzing %s@unknown (%s) ...\n", dep.Name, dep.Ecosystem)
			}
		}

		simpleDep := SimpleDependency{
			Name:      dep.Name,
			Version:   dep.Version,
			Ecosystem: dep.Ecosystem,
		}

		vulnCount, vulnerableFiles, err := va.analyzeDependencyByFile(simpleDep, sourceFiles, verbose)
		if err != nil {
			if verbose {
				log.Printf("Failed to analyze %s: %v", dep.Name, err)
			}
			continue
		}

		if vulnCount > 0 {
			vulnerablePackages++
			totalVulnerabilities += vulnCount

			for _, fileVuln := range vulnerableFiles {
				if fileVulnerabilities[fileVuln.FilePath] == nil {
					fileVulnerabilities[fileVuln.FilePath] = []FileVulnerability{}
				}
				fileVulnerabilities[fileVuln.FilePath] = append(fileVulnerabilities[fileVuln.FilePath], fileVuln)
			}
		}
	}

	va.displayResults(fileVulnerabilities, discoveredDeps, sourceFiles, vulnerablePackages, totalVulnerabilities)

	return nil
}

func (va *VulnerabilityAnalyzer) DiscoverDependencies(sourceFiles []string, rootDir string) ([]DiscoveredDependency, error) {
	codeImports := make(map[string][]string)

	for _, filePath := range sourceFiles {
		imports, err := va.extractImportsFromFile(filePath)
		if err != nil {
			continue
		}

		for _, imp := range imports {
			packageName := va.normalizeImportName(imp, filePath)
			if packageName != "" {
				codeImports[packageName] = append(codeImports[packageName], filePath)
			}
		}
	}

	lookup := version_lookup.SimpleVersionLookupFunc()

	packageEcosystems := make(map[string]string)
	for packageName, files := range codeImports {
		ecosystem := va.detectEcosystem(files[0])
		packageEcosystems[packageName] = ecosystem
	}

	versions := lookup.GetAllVersions(rootDir, packageEcosystems)

	var discovered []DiscoveredDependency

	for packageName, files := range codeImports {
		ecosystem := packageEcosystems[packageName]

		dep := DiscoveredDependency{
			Name:            packageName,
			Ecosystem:       ecosystem,
			FoundInFiles:    files,
			Version:         versions[packageName],
			IsInManifest:    versions[packageName] != "",
			ManifestVersion: versions[packageName],
		}

		discovered = append(discovered, dep)
	}

	return discovered, nil
}

func (va *VulnerabilityAnalyzer) analyzeDependencyByFile(dep SimpleDependency, sourceFiles []string, verbose bool) (int, []FileVulnerability, error) {
	queryVersion := dep.Version

	isUnknownVersion := queryVersion == "" || queryVersion == "*" || queryVersion == "latest" || strings.Contains(queryVersion, "^") || strings.Contains(queryVersion, "~")
	if isUnknownVersion {
		if verbose {
			fmt.Printf("  %s (unknown version: '%s') - checking all known vulnerabilities for package\n", dep.Name, dep.Version)
		}
		queryVersion = ""
	}

	advisories, err := osv.QueryOSV(dep.Name, queryVersion, dep.Ecosystem)
	if err != nil {
		return 0, []FileVulnerability{}, fmt.Errorf("OSV query failed: %w", err)
	}

	if len(advisories) == 0 {
		return 0, []FileVulnerability{}, nil
	}

	var fileVulnerabilities []FileVulnerability
	fileVulnMap := make(map[string]*FileVulnerability)

	if verbose {
		if isUnknownVersion {
			fmt.Printf("  Found %d advisories (all versions - may not all apply)\n", len(advisories))
		} else {
			fmt.Printf("  Found %d advisories\n", len(advisories))
		}
	}

	for i, adv := range advisories {
		if verbose {
			fmt.Printf("  Advisory %d: %s\n", i+1, adv.ID)
		}

		var allOSVSymbols []string
		for _, affected := range adv.Affected {
			for _, imp := range affected.EcosystemSpecific.Imports {
				allOSVSymbols = append(allOSVSymbols, imp.Symbols...)
			}
		}

		extractedSymbols := osv.ExtractPossibleSymbols(dep.Name, adv.Summary, adv.Details)
		allOSVSymbols = append(allOSVSymbols, extractedSymbols...)
		uniqueOSVSymbols := reachability.DeduplicateSlice(allOSVSymbols)

		for _, filePath := range sourceFiles {
			result, err := va.treeSitterAnalyzer.AnalyzeFileForVulnerabilities(filePath, dep.Name, uniqueOSVSymbols)
			if err != nil {
				continue
			}

			if len(result.Basic.VulnerableCalls) > 0 {
				if fileVulnMap[filePath] == nil {
					fileVulnMap[filePath] = &FileVulnerability{
						FilePath:        filePath,
						PackageName:     dep.Name,
						PackageVersion:  dep.Version,
						VulnerableCalls: []string{},
						Advisories:      []AdvisoryDetail{},
					}
				}

				advisoryDetail := AdvisoryDetail{
					ID:                adv.ID,
					Summary:           adv.Summary,
					Symbols:           uniqueOSVSymbols,
					HasReachableCalls: true,
					VulnerableFiles: []VulnerableFile{{
						FilePath:        filePath,
						VulnerableCalls: result.Basic.VulnerableCalls,
					}},
				}

				if isUnknownVersion {
					advisoryDetail.Summary = "[UNKNOWN VERSION] " + advisoryDetail.Summary
				}

				fileVulnMap[filePath].VulnerableCalls = append(fileVulnMap[filePath].VulnerableCalls, result.Basic.VulnerableCalls...)
				fileVulnMap[filePath].Advisories = append(fileVulnMap[filePath].Advisories, advisoryDetail)

				if verbose {
					if isUnknownVersion {
						fmt.Printf("    File %s: %v (unknown version)\n", filePath, result.Basic.VulnerableCalls)
					} else {
						fmt.Printf("    File %s: %v\n", filePath, result.Basic.VulnerableCalls)
					}
				}
			}
		}
	}

	for _, fileVuln := range fileVulnMap {
		fileVuln.VulnerableCalls = reachability.DeduplicateSlice(fileVuln.VulnerableCalls)
		fileVulnerabilities = append(fileVulnerabilities, *fileVuln)
	}

	return len(advisories), fileVulnerabilities, nil
}

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
	for _, dep := range discoveredDeps {
		if dep.IsInManifest {
			manifestCount++
		} else {
			codeOnlyCount++
		}
	}

	fmt.Printf("  - With versions (in manifests): %d\n", manifestCount)
	fmt.Printf("  - Unknown versions (code-only): %d\n", codeOnlyCount)
	fmt.Printf("Packages with vulnerabilities: %d\n", vulnerablePackages)
	fmt.Printf("Total vulnerability advisories: %d\n", totalVulnerabilities)
	fmt.Printf("Files with reachable vulnerabilities: %d\n", len(fileVulnerabilities))

}

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

func (va *VulnerabilityAnalyzer) findSourceFiles(repoPath string) ([]string, error) {
	var sourceFiles []string

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && path != "." && (strings.HasPrefix(info.Name(), ".") ||
			info.Name() == "node_modules" ||
			info.Name() == "__pycache__" ||
			info.Name() == "vendor" ||
			info.Name() == "build" ||
			info.Name() == "dist") {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".js" || ext == ".py" || ext == ".go" {
				sourceFiles = append(sourceFiles, path)
			}
		}

		return nil
	})

	return sourceFiles, err
}

func (va *VulnerabilityAnalyzer) extractImportsFromFile(filePath string) ([]string, error) {
	fileParser, err := parser.CreateParser(filePath)
	if err != nil {
		return nil, err
	}
	defer fileParser.Close()

	parseResult, err := fileParser.ParseFile(filePath)
	if err != nil {
		return nil, err
	}
	defer parseResult.Tree.Close()

	imports, err := fileParser.ExtractImports(parseResult.Tree.RootNode(), parseResult.Source)
	if err != nil {
		return nil, err
	}

	var packageNames []string
	for _, imp := range imports {
		packageNames = append(packageNames, imp.PackageName)
	}

	return reachability.DeduplicateSlice(packageNames), nil
}

func (va *VulnerabilityAnalyzer) detectEcosystem(sampleFile string) string {
	ext := filepath.Ext(sampleFile)

	switch ext {
	case ".js":
		return "npm"
	case ".py":
		return "PyPI"
	case ".go":
		return "Go"
	default:
		return "unknown"
	}
}

func (va *VulnerabilityAnalyzer) normalizeImportName(importPath string, filePath string) string {
	ext := filepath.Ext(filePath)

	switch ext {
	case ".js":
		return va.normalizeJSImport(importPath)
	case ".py":
		return va.normalizePythonImport(importPath)
	case ".go":
		return va.normalizeGoImport(importPath)
	default:
		return importPath
	}
}

func (va *VulnerabilityAnalyzer) normalizeJSImport(importPath string) string {
	if strings.HasPrefix(importPath, ".") || strings.HasPrefix(importPath, "/") {
		return ""
	}

	if strings.HasPrefix(importPath, "@") {
		return importPath
	}

	parts := strings.Split(importPath, "/")
	return parts[0]
}

func (va *VulnerabilityAnalyzer) normalizePythonImport(importPath string) string {
	stdlib := []string{"os", "sys", "json", "re", "time", "datetime", "collections", "itertools", "functools", "operator", "pathlib", "urllib", "http", "email", "html", "xml", "csv", "sqlite3", "threading", "multiprocessing", "subprocess", "shutil", "glob", "pickle", "base64", "hashlib", "hmac", "secrets", "ssl", "socket", "logging", "unittest", "argparse", "configparser", "io", "math", "random", "statistics", "decimal", "fractions", "enum", "types", "copy", "pprint", "textwrap", "string", "bytes", "bytearray", "memoryview", "array"}

	for _, std := range stdlib {
		if importPath == std {
			return ""
		}
	}

	parts := strings.Split(importPath, ".")
	return parts[0]
}

func (va *VulnerabilityAnalyzer) normalizeGoImport(importPath string) string {
	if !strings.Contains(importPath, ".") {
		return ""
	}

	if strings.Contains(importPath, "github.com/hannajonsd/reachability-analysis") {
		return ""
	}

	if strings.HasPrefix(importPath, "golang.org/x/") {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}

	if strings.HasPrefix(importPath, "github.com/") {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 3 {
			basePackage := strings.Join(parts[:3], "/")

			return basePackage
		}
	}

	parts := strings.Split(importPath, "/")
	if len(parts) >= 2 {
		if strings.Contains(parts[0], ".") {
			return importPath
		}
		return strings.Join(parts[:2], "/")
	}

	return importPath
}

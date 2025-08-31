package analyzer

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/hannajonsd/reachability-analysis/parser"
	"github.com/hannajonsd/reachability-analysis/reachability"
	"github.com/hannajonsd/reachability-analysis/version_lookup"
)

// VulnerabilityAnalyzer performs vulnerability analysis on source code repositories
type VulnerabilityAnalyzer struct {
	treeSitterAnalyzer *reachability.TreeSitterAnalyzer
}

// New creates a new vulnerability analyzer instance
func New() *VulnerabilityAnalyzer {
	return &VulnerabilityAnalyzer{
		treeSitterAnalyzer: reachability.NewTreeSitterAnalyzer(),
	}
}

// AnalyzeRepository performs vulnerability analysis on a repository
func (va *VulnerabilityAnalyzer) AnalyzeRepository(repoPath string, verbose bool) (int, error) {
	fmt.Printf("Analyzing repository: %s\n", repoPath)

	sourceFiles, err := va.findSourceFiles(repoPath)
	if err != nil {
		return 0, fmt.Errorf("failed to find source files: %w", err)
	}
	fmt.Printf("Found %d source files for analysis\n", len(sourceFiles))

	discoveredDeps, err := va.DiscoverDependencies(sourceFiles, repoPath)
	if err != nil {
		return 0, fmt.Errorf("failed to discover dependencies: %w", err)
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

		vulnCount, vulnerableFiles, err := va.AnalyzeDependency(simpleDep, sourceFiles, verbose)
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

	va.displayResults(fileVulnerabilities, discoveredDeps, sourceFiles, vulnerablePackages)

	return len(fileVulnerabilities), nil
}

// extractImportsFromFile extracts import statements from a source file
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

// detectEcosystem determines package ecosystem based on file extension
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

// DiscoverDependencies finds all external dependencies used in source files
func (va *VulnerabilityAnalyzer) DiscoverDependencies(sourceFiles []string, rootDir string) ([]DiscoveredDependency, error) {
	codeImports := make(map[string][]string)

	// Extract imports from all source files
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
	var discovered []DiscoveredDependency

	for packageName, files := range codeImports {
		ecosystem := va.detectEcosystem(files[0])

		var version string
		var isInManifest bool

		if ecosystem == "Go" {
			version, isInManifest = va.findGoModuleVersion(lookup, rootDir, packageName)

			if !isInManifest && va.isStandardLibrary(packageName) {
				continue
			}
		} else {
			version = lookup.GetPackageVersion(rootDir, packageName, ecosystem)
			isInManifest = version != ""
		}

		dep := DiscoveredDependency{
			Name:            packageName,
			Ecosystem:       ecosystem,
			FoundInFiles:    reachability.DeduplicateSlice(files),
			Version:         version,
			IsInManifest:    isInManifest,
			ManifestVersion: version,
		}

		discovered = append(discovered, dep)
	}

	return discovered, nil
}

// findGoModuleVersion searches for Go module versions at any path level
func (va *VulnerabilityAnalyzer) findGoModuleVersion(lookup *version_lookup.SimpleVersionLookup, rootDir, fullImportPath string) (string, bool) {
	if !strings.Contains(fullImportPath, "/") {
		version := lookup.GetPackageVersion(rootDir, fullImportPath, "Go")
		return version, version != ""
	}

	hierarchicalPaths := generateHierarchicalPaths(fullImportPath)

	for _, modulePath := range hierarchicalPaths {
		version := lookup.GetPackageVersion(rootDir, modulePath, "Go")
		if version != "" {
			return version, true
		}
	}

	return "", false
}

// isStandardLibrary checks if a Go package is part of the standard library
func (va *VulnerabilityAnalyzer) isStandardLibrary(importPath string) bool {
	if strings.Contains(importPath, ".") {
		return false
	}

	switch importPath {
	case "fmt", "os", "io", "log", "net", "sync", "time", "math", "sort", "path",
		"mime", "html", "text", "hash", "bytes", "bufio", "image", "crypto",
		"errors", "regexp", "strings", "strconv", "unicode", "unsafe", "context",
		"reflect", "testing", "syscall", "runtime", "flag":
		return true
	}

	stdlibPrefixes := []string{
		"archive/", "compress/", "container/", "crypto/", "database/",
		"debug/", "encoding/", "go/", "hash/", "html/", "image/",
		"index/", "net/", "os/", "path/", "text/", "mime/",
	}

	for _, prefix := range stdlibPrefixes {
		if strings.HasPrefix(importPath, prefix) {
			return true
		}
	}

	return false
}

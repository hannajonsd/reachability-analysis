package analyzer

// SimpleDependency represents a package dependency with basic information
type SimpleDependency struct {
	Name      string
	Version   string
	Ecosystem string
}

// DiscoveredDependency represents a dependency found in source code with metadata
type DiscoveredDependency struct {
	Name            string
	Version         string
	Ecosystem       string
	FoundInFiles    []string
	IsInManifest    bool
	ManifestVersion string
}

// FileVulnerability represents vulnerabilities found in a specific file
type FileVulnerability struct {
	FilePath        string
	PackageName     string
	PackageVersion  string
	VulnerableCalls []string
	Advisories      []AdvisoryDetail
}

// AdvisoryDetail represents a security advisory with reachability information
type AdvisoryDetail struct {
	ID                string
	Summary           string
	Symbols           []string
	HasReachableCalls bool
	VulnerableFiles   []VulnerableFile
}

// VulnerableFile represents a file with specific vulnerable function calls
type VulnerableFile struct {
	FilePath        string
	VulnerableCalls []string
}

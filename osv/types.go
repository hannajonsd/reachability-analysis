package osv

// OSVRequest represents a vulnerability query request to the OSV API
type OSVRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Advisory represents a security vulnerability advisory from OSV
type Advisory struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Affected []Affected `json:"affected"`
}

// Affected represents a package affected by a vulnerability
type Affected struct {
	Package           PackageInfo       `json:"package"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

// PackageInfo contains basic package identification information
type PackageInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// EcosystemSpecific contains ecosystem-specific vulnerability details
type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

// Import represents a vulnerable import path and its affected symbols
type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

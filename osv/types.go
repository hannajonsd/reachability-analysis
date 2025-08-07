package osv

type OSVRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type Advisory struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package           PackageInfo       `json:"package"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type PackageInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

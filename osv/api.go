package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func QueryOSV(pkgName string, version string, ecosystem string) ([]Advisory, error) {
	req := OSVRequest{}
	req.Package.Name = pkgName
	req.Package.Ecosystem = ecosystem
	req.Version = version

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API error: %s", resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	var result struct {
		Vulns []Advisory `json:"vulns"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}
	return result.Vulns, nil

}

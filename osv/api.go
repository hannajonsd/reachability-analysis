package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type OSVRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

func QueryOSV(pkgName string, version string, ecosystem string) (string, error) {
	req := OSVRequest{}
	req.Package.Name = pkgName
	req.Package.Ecosystem = ecosystem
	req.Version = version

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("error encoding request: %w", err)
	}

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OSV API error: %s", resp.Status)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	return string(respBody), nil
}

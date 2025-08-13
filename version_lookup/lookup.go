package version_lookup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SimpleVersionLookup struct{}

func SimpleVersionLookupFunc() *SimpleVersionLookup {
	return &SimpleVersionLookup{}
}

func (s *SimpleVersionLookup) GetPackageVersion(rootDir, packageName, ecosystem string) string {
	manifestFiles := s.findManifests(rootDir, ecosystem)

	for _, manifestFile := range manifestFiles {
		if version := s.searchVersionInFile(manifestFile, packageName, ecosystem); version != "" {
			return version
		}
	}

	return ""
}

func (s *SimpleVersionLookup) GetAllVersions(rootDir string, packages map[string]string) map[string]string {
	versions := make(map[string]string)

	allManifests := s.findManifests(rootDir)

	for packageName, ecosystem := range packages {
		for _, manifestFile := range allManifests {
			if version := s.searchVersionInFile(manifestFile, packageName, ecosystem); version != "" {
				versions[packageName] = version
				break
			}
		}
	}

	return versions
}

func (s *SimpleVersionLookup) searchVersionInFile(filePath, packageName, ecosystem string) string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	text := string(content)
	fileName := filepath.Base(filePath)

	switch fileName {
	case "package.json":
		return s.searchNpmVersion(text, packageName)
	case "go.mod":
		return s.searchGoVersion(text, packageName)
	case "requirements.txt":
		return s.searchPythonVersion(text, packageName)
	default:
		return ""
	}
}

func (s *SimpleVersionLookup) findManifests(rootDir string, ecosystems ...string) []string {
	ecoToFiles := map[string][]string{
		"npm":  {"package.json"},
		"Go":   {"go.mod"},
		"PyPI": {"requirements.txt"},
	}

	targets := make(map[string]struct{})
	if len(ecosystems) == 0 {
		for _, names := range ecoToFiles {
			for _, n := range names {
				targets[n] = struct{}{}
			}
		}
	} else {
		for _, eco := range ecosystems {
			for _, n := range ecoToFiles[eco] {
				targets[n] = struct{}{}
			}
		}
	}

	rootAbs, _ := filepath.Abs(rootDir)
	var files []string

	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			pathAbs, _ := filepath.Abs(path)
			if pathAbs != rootAbs {
				name := d.Name()
				if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "__pycache__" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if _, ok := targets[filepath.Base(path)]; ok {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func (s *SimpleVersionLookup) searchNpmVersion(content, packageName string) string {
	pattern := fmt.Sprintf(`"%s"\s*:\s*"([^"]+)"`, regexp.QuoteMeta(packageName))
	re := regexp.MustCompile(pattern)

	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (s *SimpleVersionLookup) searchGoVersion(content, packageName string) string {
	pattern := fmt.Sprintf(`%s\s+([^\s]+)`, regexp.QuoteMeta(packageName))
	re := regexp.MustCompile(pattern)

	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (s *SimpleVersionLookup) searchPythonVersion(content, packageName string) string {
	pattern := fmt.Sprintf(`^%s\s*([>=<~!]+[^\s#]+)`, regexp.QuoteMeta(packageName))
	re := regexp.MustCompile(pattern)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

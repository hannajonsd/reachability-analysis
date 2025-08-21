package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// NewGitignoreParser creates a new gitignore parser for the given directory
func NewGitignoreParser(rootDir string) *GitignoreParser {
	parser := &GitignoreParser{
		rootDir: rootDir,
	}
	parser.loadGitignore()
	return parser
}

// loadGitignore reads and parses the .gitignore file
func (gp *GitignoreParser) loadGitignore() {
	gitignorePath := filepath.Join(gp.rootDir, ".gitignore")
	file, err := os.Open(gitignorePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "!") {
			pattern := strings.TrimPrefix(line, "!")
			gp.negationPatterns = append(gp.negationPatterns, pattern)
		} else {
			gp.ignorePatterns = append(gp.ignorePatterns, line)
		}
	}
}

// ShouldIgnore checks if a path should be ignored based on .gitignore patterns
func (gp *GitignoreParser) ShouldIgnore(path string) bool {
	relPath, err := filepath.Rel(gp.rootDir, path)
	if err != nil {
		return false
	}

	relPath = filepath.ToSlash(relPath)

	shouldIgnore := false
	for _, pattern := range gp.ignorePatterns {
		if gp.matchPattern(pattern, relPath) {
			shouldIgnore = true
			break
		}
	}

	if shouldIgnore {
		for _, pattern := range gp.negationPatterns {
			if gp.matchPattern(pattern, relPath) {
				return false
			}
		}
	}

	return shouldIgnore
}

// matchPattern checks if a path matches a gitignore pattern
func (gp *GitignoreParser) matchPattern(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/") {
		pattern = strings.TrimSuffix(pattern, "/")

		if strings.HasPrefix(path, pattern+"/") || path == pattern {
			return true
		}

		pathParts := strings.Split(path, "/")
		for i := range pathParts {
			if pathParts[i] == pattern {
				return true
			}
		}

		return false
	}

	if strings.HasPrefix(pattern, "/") {
		pattern = strings.TrimPrefix(pattern, "/")
		return gp.matchSimplePattern(pattern, path)
	}

	pathParts := strings.Split(path, "/")

	if gp.matchSimplePattern(pattern, path) {
		return true
	}

	for i := range pathParts {
		subPath := strings.Join(pathParts[i:], "/")
		if gp.matchSimplePattern(pattern, subPath) {
			return true
		}
	}

	if !strings.Contains(pattern, "/") {
		for _, part := range pathParts {
			if gp.matchSimplePattern(pattern, part) {
				return true
			}
		}
	}

	return false
}

// matchSimplePattern handles basic pattern matching
func (gp *GitignoreParser) matchSimplePattern(pattern, text string) bool {
	if pattern == text {
		return true
	}

	if strings.Contains(pattern, "*") {
		return gp.matchWildcard(pattern, text)
	}

	return false
}

// matchWildcard performs basic wildcard pattern matching
func (gp *GitignoreParser) matchWildcard(pattern, text string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(text, middle)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(text, suffix)
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(text, prefix)
	}

	return false
}

// findSourceFiles finds all source files in the repository
func (va *VulnerabilityAnalyzer) findSourceFiles(repoPath string) ([]string, error) {
	var sourceFiles []string

	gitignoreParser := NewGitignoreParser(repoPath)

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if gitignoreParser.ShouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip common build/dependency directories
		if info.IsDir() && path != repoPath && (strings.HasPrefix(info.Name(), ".") ||
			info.Name() == "node_modules" ||
			info.Name() == "__pycache__" ||
			info.Name() == "vendor" ||
			info.Name() == "build" ||
			info.Name() == "dist" ||
			info.Name() == "venv" ||
			info.Name() == "env" ||
			info.Name() == ".venv" ||
			strings.HasSuffix(info.Name(), ".egg-info")) {
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

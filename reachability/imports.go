package reachability

import (
	"regexp"
	"strings"
)

func extractJSImports(content string) []PackageImport {
	var imports []PackageImport

	patterns := []struct {
		regex      *regexp.Regexp
		importType string
	}{
		// const alias = require("package")
		{regexp.MustCompile(`const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)`), "require"},
		// let alias = require("package")
		{regexp.MustCompile(`let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)`), "require"},
		// var alias = require("package")
		{regexp.MustCompile(`var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)`), "require"},
		// import alias from "package"
		{regexp.MustCompile(`import\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s+["']([^"']+)["']`), "import"},
		// import * as alias from "package"
		{regexp.MustCompile(`import\s+\*\s+as\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s+["']([^"']+)["']`), "import"},
	}

	for _, pattern := range patterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				alias := match[1]
				packageName := match[2]

				packageName = cleanPackageName(packageName)

				imports = append(imports, PackageImport{
					PackageName: packageName,
					Alias:       alias,
					ImportType:  pattern.importType,
				})
			}
		}
	}

	// Handle destructured imports: const { method1, method2 } = require("package")
	destructuredPattern := regexp.MustCompile(`(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)`)
	matches := destructuredPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			methodsStr := match[1]
			packageName := cleanPackageName(match[2])

			methods := parseDestructuredMethods(methodsStr)
			for _, method := range methods {
				imports = append(imports, PackageImport{
					PackageName: packageName,
					Alias:       method,
					ImportType:  "destructured",
				})
			}
		}
	}

	return imports
}

func cleanPackageName(packageName string) string {
	versionPattern := regexp.MustCompile(`@[\d\.]+.*$`)
	packageName = versionPattern.ReplaceAllString(packageName, "")
	packageName = strings.TrimPrefix(packageName, "@")

	return packageName
}

func parseDestructuredMethods(methodsStr string) []string {
	var methods []string

	parts := strings.Split(methodsStr, ",")
	for _, part := range parts {
		aliasPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:as\s+([a-zA-Z_$][a-zA-Z0-9_$]*))?`)
		match := aliasPattern.FindStringSubmatch(strings.TrimSpace(part))

		if len(match) >= 2 {
			if len(match) >= 3 && match[2] != "" {
				methods = append(methods, match[2])
			} else {
				methods = append(methods, match[1])
			}
		}
	}

	return methods
}

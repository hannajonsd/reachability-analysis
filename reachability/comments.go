package reachability

import (
	"regexp"
	"strings"
)

func removeJSComments(content string) string {
	singleLinePattern := regexp.MustCompile(`//.*`)
	content = singleLinePattern.ReplaceAllString(content, "")

	multiLinePattern := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	content = multiLinePattern.ReplaceAllString(content, "")

	return content
}

func isValidJSIdentifier(s string) bool {
	if s == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z_$][a-zA-Z0-9_$]*$`, s)
	return matched
}

func isCommonFileExtension(s string) bool {
	fileExtensions := []string{
		"js", "ts", "jsx", "tsx", "json", "md", "txt", "html", "css",
		"png", "jpg", "jpeg", "gif", "svg", "ico", "pdf", "zip",
		"com", "org", "net", "io", "dev", "co",
	}

	lower := strings.ToLower(s)
	for _, ext := range fileExtensions {
		if lower == ext {
			return true
		}
	}
	return false
}

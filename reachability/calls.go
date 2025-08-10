package reachability

import (
	"fmt"
	"regexp"
	"strings"
)

func extractMethodCalls(content string) []string {
	var results []string
	seen := make(map[string]bool)

	objectMethodPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:\(|[^\w\s\.]|$)`)
	matches := objectMethodPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			object := strings.TrimSpace(match[1])
			property := strings.TrimSpace(match[2])

			if !isValidJSIdentifier(object) || !isValidJSIdentifier(property) {
				continue
			}

			if isCommonFileExtension(property) {
				continue
			}

			functionCall := fmt.Sprintf("%s.%s", object, property)
			if !seen[functionCall] {
				seen[functionCall] = true
				results = append(results, functionCall)
			}
		}
	}

	return results
}

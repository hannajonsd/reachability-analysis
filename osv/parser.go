package osv

import (
	"regexp"
	"strings"
)

var functionPattern = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\s*\(\)`)
var backtickPattern = regexp.MustCompile("`([a-zA-Z_][a-zA-Z0-9_]*)`")
var funcWordPattern = regexp.MustCompile(`(?i)\b([a-zA-Z_][a-zA-Z0-9_]*)\b\s+function`)
var quotedPattern = regexp.MustCompile(`['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`)

// ExtractMentionedSymbols finds function names and identifiers from text using regex patterns
func ExtractMentionedSymbols(text string) []string {
	funcMatches := functionPattern.FindAllString(text, -1)
	tickMatches := backtickPattern.FindAllStringSubmatch(text, -1)
	funcWordMatches := funcWordPattern.FindAllStringSubmatch(text, -1)
	quoteMatches := quotedPattern.FindAllStringSubmatch(text, -1)

	unique := make(map[string]struct{})
	for _, match := range funcMatches {
		symbol := match[:len(match)-2]
		unique[symbol] = struct{}{}
	}

	for _, match := range tickMatches {
		if len(match) > 1 {
			unique[match[1]] = struct{}{}
		}
	}

	for _, match := range funcWordMatches {
		if len(match) > 1 {
			unique[match[1]] = struct{}{}
		}
	}

	for _, match := range quoteMatches {
		if len(match) > 1 {
			unique[match[1]] = struct{}{}
		}
	}

	var results []string
	for s := range unique {
		if isValidSymbol(s) && isSymbolLike(s) && !looksLikeGarbageSymbol(s) {
			results = append(results, s)
		}
	}
	return results
}

// isValidSymbol filters out symbols containing common domain names and file extensions
func isValidSymbol(symbol string) bool {
	domains := []string{"github.com", ".com", ".io", ".rs", ".md", ".png", ".aarch64", ".x86_64", "e.g"}
	for _, domain := range domains {
		if strings.Contains(symbol, domain) {
			return false
		}
	}
	return true
}

// isSymbolLike filters out URLs, file names, and other non-symbol-like strings
func isSymbolLike(s string) bool {
	blockedKeywords := []string{
		".com", ".org", ".rs", ".io", ".md", ".txt", ".png", ".html", ".exe", ".zip", ".cr",
		"http", "www.", "docs.", "lists.", "datatracker.", "main.ts", "go.mod", "core.rs",
		"faq.", "readme", "swhkd.sock", "swhks.pid", "libraries.html", "e.g", "i.e",
	}

	lowerS := strings.ToLower(s)
	for _, keyword := range blockedKeywords {
		if strings.Contains(lowerS, keyword) {
			return false
		}
	}
	return true
}

// ExtractPossibleSymbols extracts valid function/variable symbols from vulnerability text, excluding the package name itself
func ExtractPossibleSymbols(name, summary, details string) []string {
	text := summary + " " + details

	allMatches := ExtractMentionedSymbols(text)

	var validMatches []string
	for _, match := range allMatches {
		if isValidSymbol(match) && isSymbolLike(match) && !looksLikeGarbageSymbol(match) {
			validMatches = append(validMatches, match)
		}
	}

	// Remove the package name from results
	for i, match := range validMatches {
		if match == name {
			validMatches = append(validMatches[:i], validMatches[i+1:]...)
			break
		}
	}
	return validMatches
}

func looksLikeGarbageSymbol(s string) bool {
	lower := strings.ToLower(s)

	// obvious junk words
	junk := []string{"true", "false", "none", "object", "the", "previous", "vulnerable"}
	for _, j := range junk {
		if lower == j {
			return true
		}
	}

	if strings.Contains(s, "_") && strings.ToLower(s) == s {
		return true
	}

	return false
}

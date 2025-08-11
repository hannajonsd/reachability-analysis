package main

import (
	"fmt"
	"net/http"

	"golang.org/x/text/language"
)

func main() {
	fmt.Println("Hello world")

	lang := language.ParseAcceptLanguage("en-US,en;q=0.9,fr;q=0.8")
	fmt.Println(lang)

	matches := language.MatchStrings([]string{"en", "fr"})
	fmt.Println(matches)

	http.Get("https://example.com")
}

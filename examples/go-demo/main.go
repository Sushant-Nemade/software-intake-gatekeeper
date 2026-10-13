package main

import (
	"fmt"

	"golang.org/x/text/language"
)

// Fixture only: pins an old golang.org/x/text so the scanner has a known advisory to report.
func main() {
	tag, err := language.Parse("de-DE")
	if err != nil {
		panic(err)
	}
	fmt.Println("intake-gatekeeper demo tool:", tag)
}

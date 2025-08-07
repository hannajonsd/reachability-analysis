package main

import (
	"fmt"

	"github.com/hannajonsd/reachability-analysis/osv"
)

func main() {
	result, err := osv.QueryOSV("lodash", "4.17.20", "npm")
	if err != nil {
		fmt.Println("Failed to query OSV:", err)
		return
	}
	fmt.Println("Raw OSV Response:\n", result)
}

package main

import (
	"os"

	"github.com/jblesener/nbxcli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

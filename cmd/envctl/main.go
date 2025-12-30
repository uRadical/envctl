// Package main provides the entrypoint for the envctl CLI.
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"

	"uradical.io/go/envctl/internal/cli"
	"uradical.io/go/envctl/internal/daemon"
)

//go:embed ui
var uiFS embed.FS

var version = "dev"

func init() {
	uiRoot, err := fs.Sub(uiFS, "ui")
	if err == nil {
		daemon.UIFilesystem = uiRoot
	}
}

func main() {
	cli.SetVersion(version)
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

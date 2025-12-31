// Command gendocs generates man pages from Cobra commands.
package main

import (
	"log"
	"os"

	"github.com/spf13/cobra/doc"
	"envctl.dev/go/envctl/internal/cli"
)

func main() {
	// Man page header
	header := &doc.GenManHeader{
		Title:   "ENVCTL",
		Section: "1",
		Source:  "uRadical",
		Manual:  "envctl manual",
	}

	// Create man directory
	if err := os.MkdirAll("./man", 0755); err != nil {
		log.Fatalf("Failed to create man directory: %v", err)
	}

	// Get the root command
	rootCmd := cli.RootCmd

	// Generate man pages
	if err := doc.GenManTree(rootCmd, header, "./man"); err != nil {
		log.Fatalf("Failed to generate man pages: %v", err)
	}

	log.Println("Man pages generated in ./man")

	// Also generate markdown docs
	if err := os.MkdirAll("./docs/cli", 0755); err != nil {
		log.Fatalf("Failed to create docs directory: %v", err)
	}

	if err := doc.GenMarkdownTree(rootCmd, "./docs/cli"); err != nil {
		log.Fatalf("Failed to generate markdown docs: %v", err)
	}

	log.Println("Markdown docs generated in ./docs/cli")
}

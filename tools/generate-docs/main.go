package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jblesener/nbxcli/cmd"
	"github.com/spf13/cobra/doc"
)

const outputDir = "docs/reference"

func main() {
	if err := os.RemoveAll(outputDir); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fatal(err)
	}

	root := cmd.NewDocumentationRootCmd()
	err := doc.GenMarkdownTreeCustom(root, outputDir, frontMatter, referenceLink)
	if err != nil {
		fatal(err)
	}
}

func frontMatter(filename string) string {
	name := strings.TrimSuffix(filepath.Base(filename), ".md")
	title := strings.ReplaceAll(name, "_", " ")
	return fmt.Sprintf("---\nlayout: reference\ntitle: %q\n---\n\n", title)
}

func referenceLink(link string) string {
	return strings.TrimSuffix(link, ".md") + ".html"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

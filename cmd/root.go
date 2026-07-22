package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/jblesener/nbxcli/internal/prompt"
	"github.com/jblesener/nbxcli/internal/tokenstore"
	"github.com/spf13/cobra"
)

type dependencies struct {
	configs   config.Store
	tokens    tokenstore.Store
	api       netbox.Provisioner
	resources netbox.ResourceReader
	prompt    prompt.Prompter
}

func defaultDependencies(in io.Reader, out io.Writer) (dependencies, error) {
	configs, err := config.NewDefaultStore()
	if err != nil {
		return dependencies{}, err
	}
	client := netbox.NewClient()
	return dependencies{
		configs:   configs,
		tokens:    tokenstore.NewKeyringStore(),
		api:       client,
		resources: client,
		prompt:    prompt.New(in, out),
	}, nil
}

func newRootCmd(deps dependencies) *cobra.Command {
	root := &cobra.Command{
		Use:           "nbxcli",
		Short:         "A command-line client for NetBox",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newAuthCmd(deps), newGetCmd(deps), newResourcesCmd(deps))
	return root
}

// Execute runs the command-line application with the host terminal attached.
func Execute() error {
	deps, err := defaultDependencies(os.Stdin, os.Stdout)
	if err != nil {
		return fmt.Errorf("initialize nbxcli: %w", err)
	}
	return newRootCmd(deps).Execute()
}

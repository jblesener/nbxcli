package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/spf13/cobra"
)

const defaultResourceLimit = 100

type resourceGetOptions struct {
	profile string
	search  string
	filters []string
	limit   int
	output  string
}

type resourcesOptions struct {
	profile string
	output  string
}

func newGetCmd(deps dependencies) *cobra.Command {
	options := resourceGetOptions{limit: defaultResourceLimit, output: "table"}
	get := &cobra.Command{
		Use:   "get RESOURCE [ID]",
		Short: "List or retrieve a NetBox resource",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return getResource(cmd.Context(), cmd.OutOrStdout(), deps, args, options, cmd.Flags())
		},
	}
	get.Flags().StringVar(&options.profile, "profile", "", "saved NetBox profile to use")
	get.Flags().StringVar(&options.search, "search", "", "free-text resource search")
	get.Flags().StringArrayVar(&options.filters, "filter", nil, "NetBox resource filter in key=value form (repeatable)")
	get.Flags().IntVar(&options.limit, "limit", defaultResourceLimit, "maximum number of records to return")
	get.Flags().StringVarP(&options.output, "output", "o", "table", "output format: table or json")
	return get
}

func newResourcesCmd(deps dependencies) *cobra.Command {
	options := resourcesOptions{output: "table"}
	resources := &cobra.Command{
		Use:   "resources",
		Short: "List available NetBox resources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listResources(cmd.Context(), cmd.OutOrStdout(), deps, options)
		},
	}
	resources.Flags().StringVar(&options.profile, "profile", "", "saved NetBox profile to use")
	resources.Flags().StringVarP(&options.output, "output", "o", "table", "output format: table or json")
	return resources
}

func getResource(ctx context.Context, out io.Writer, deps dependencies, args []string, options resourceGetOptions, flags interface{ Changed(string) bool }) error {
	if deps.resources == nil {
		return errors.New("resource queries are not configured")
	}
	if err := validateOutput(options.output); err != nil {
		return err
	}
	profile, token, err := resourceConnection(deps, options.profile)
	if err != nil {
		return err
	}
	if len(args) == 2 {
		if flags.Changed("search") || flags.Changed("filter") || flags.Changed("limit") {
			return errors.New("--search, --filter, and --limit can only be used when listing a resource")
		}
		id, err := strconv.Atoi(args[1])
		if err != nil || id <= 0 {
			return fmt.Errorf("invalid resource ID %q; use a positive integer", args[1])
		}
		record, err := deps.resources.GetResource(ctx, profile.BaseURL, token, profile.InsecureTLS, args[0], id)
		if err != nil {
			return fmt.Errorf("query NetBox resource: %w", err)
		}
		return writeResourceResult(out, record, options.output)
	}
	if options.limit <= 0 {
		return errors.New("limit must be a positive integer")
	}
	filters, err := parseResourceFilters(options.filters)
	if err != nil {
		return err
	}
	records, err := deps.resources.ListResource(ctx, profile.BaseURL, token, profile.InsecureTLS, args[0], netbox.ResourceQuery{
		Search: options.search, Filters: filters, Limit: options.limit,
	})
	if err != nil {
		return fmt.Errorf("query NetBox resource: %w", err)
	}
	return writeResourceList(out, records, options.output)
}

func listResources(ctx context.Context, out io.Writer, deps dependencies, options resourcesOptions) error {
	if deps.resources == nil {
		return errors.New("resource queries are not configured")
	}
	if err := validateOutput(options.output); err != nil {
		return err
	}
	profile, token, err := resourceConnection(deps, options.profile)
	if err != nil {
		return err
	}
	resources, err := deps.resources.ListResources(ctx, profile.BaseURL, token, profile.InsecureTLS)
	if err != nil {
		return fmt.Errorf("discover NetBox resources: %w", err)
	}
	if options.output == "json" {
		return writeJSON(out, resources)
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "RESOURCE"); err != nil {
		return err
	}
	for _, resource := range resources {
		if _, err := fmt.Fprintln(table, resource.Name); err != nil {
			return err
		}
	}
	return table.Flush()
}

func resourceConnection(deps dependencies, selectedProfile string) (config.Profile, string, error) {
	cfg, err := deps.configs.Load()
	if err != nil {
		return config.Profile{}, "", fmt.Errorf("load profiles: %w", err)
	}
	profileName := selectedProfile
	if profileName == "" {
		profileName = defaultProfile(cfg)
	}
	profile, ok := cfg.Profiles[profileName]
	if !ok {
		return config.Profile{}, "", fmt.Errorf("profile %q does not exist", profileName)
	}
	token, err := deps.tokens.Get(profileName)
	if err != nil {
		return config.Profile{}, "", fmt.Errorf("retrieve token from OS keychain: %w", err)
	}
	return profile, token, nil
}

func validateOutput(output string) error {
	if output != "table" && output != "json" {
		return fmt.Errorf("unsupported output format %q (use table or json)", output)
	}
	return nil
}

func parseResourceFilters(values []string) ([]netbox.ResourceFilter, error) {
	filters := make([]netbox.ResourceFilter, 0, len(values))
	for _, value := range values {
		key, filterValue, ok := strings.Cut(value, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid resource filter %q; use key=value", value)
		}
		filters = append(filters, netbox.ResourceFilter{Key: key, Value: filterValue})
	}
	return filters, nil
}

func writeResourceList(out io.Writer, records []json.RawMessage, output string) error {
	if output == "json" {
		if records == nil {
			records = []json.RawMessage{}
		}
		return writeJSON(out, records)
	}
	return writeResourceTable(out, records)
}

func writeResourceResult(out io.Writer, record json.RawMessage, output string) error {
	if output == "json" {
		return writeJSON(out, record)
	}
	return writeResourceTable(out, []json.RawMessage{record})
}

func writeJSON(out io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode JSON output: %w", err)
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err
}

func writeResourceTable(out io.Writer, records []json.RawMessage) error {
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "ID\tDISPLAY\tSTATUS"); err != nil {
		return err
	}
	for _, raw := range records {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(raw, &record); err != nil {
			return fmt.Errorf("decode resource for table output: %w", err)
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\n", jsonValue(record["id"]), firstPresent(record, "display", "display_name", "name", "slug"), statusValue(record["status"])); err != nil {
			return err
		}
	}
	return table.Flush()
}

func firstPresent(record map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		if value := jsonValue(record[name]); value != "" {
			return value
		}
	}
	return ""
}

func statusValue(raw json.RawMessage) string {
	if value := jsonValue(raw); value != "" {
		return value
	}
	var status map[string]json.RawMessage
	if json.Unmarshal(raw, &status) != nil {
		return ""
	}
	return firstPresent(status, "label", "value")
}

func jsonValue(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/jblesener/nbxcli/internal/tokenstore"
	"github.com/spf13/cobra"
)

func newAuthCmd(deps dependencies) *cobra.Command {
	auth := &cobra.Command{Use: "auth", Short: "Manage NetBox authentication"}
	auth.AddCommand(newLoginCmd(deps), newTokenCmd(deps), newProfileCmd(deps))
	return auth
}

func newLoginCmd(deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Create and securely store a NetBox API token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return login(cmd.Context(), cmd.OutOrStdout(), deps)
		},
	}
}

func login(ctx context.Context, out interface{ Write([]byte) (int, error) }, deps dependencies) error {
	cfg, err := deps.configs.Load()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}

	profileName, err := deps.prompt.String("Profile name", defaultProfile(cfg))
	if err != nil {
		return err
	}
	if err := config.ValidateProfileName(profileName); err != nil {
		return err
	}
	existing, exists := cfg.Profiles[profileName]
	if exists {
		confirmed, err := deps.prompt.Confirm(fmt.Sprintf("Profile %q already exists. Creating a new NetBox token will replace its locally stored token. Continue", profileName), false)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("login cancelled")
		}
	}

	baseURL, err := deps.prompt.String("NetBox URL", existing.BaseURL)
	if err != nil {
		return err
	}
	baseURL, err = netbox.NormalizeBaseURL(baseURL)
	if err != nil {
		return err
	}
	username, err := deps.prompt.String("Username", "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username cannot be empty")
	}
	password, err := deps.prompt.Password("Password")
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("password cannot be empty")
	}

	result, err := deps.api.Provision(ctx, baseURL, username, password, false)
	insecure := false
	if err != nil && netbox.IsTLSVerificationError(err) {
		confirmed, promptErr := deps.prompt.Confirm("Certificate verification failed. Retry without verifying the server certificate for this profile", false)
		if promptErr != nil {
			return promptErr
		}
		if !confirmed {
			return fmt.Errorf("certificate verification failed; login cancelled: %w", err)
		}
		result, err = deps.api.Provision(ctx, baseURL, username, password, true)
		insecure = true
	}
	if err != nil {
		return fmt.Errorf("provision NetBox token: %w", err)
	}

	previousToken, previousTokenErr := deps.tokens.Get(profileName)
	hadPreviousToken := previousTokenErr == nil
	if previousTokenErr != nil && !errors.Is(previousTokenErr, tokenstore.ErrNotFound) {
		return fmt.Errorf("read existing stored token: %w", previousTokenErr)
	}
	if err := deps.tokens.Set(profileName, result.Token); err != nil {
		return fmt.Errorf("store token in OS keychain: %w", err)
	}

	cfg.Profiles[profileName] = config.Profile{
		BaseURL:       baseURL,
		TokenVersion:  result.Version,
		RemoteTokenID: result.ID,
		InsecureTLS:   insecure,
	}
	cfg.CurrentProfile = profileName
	if err := deps.configs.Save(cfg); err != nil {
		if hadPreviousToken {
			_ = deps.tokens.Set(profileName, previousToken)
		} else {
			_ = deps.tokens.Delete(profileName)
		}
		return fmt.Errorf("save profile: %w", err)
	}

	fmt.Fprintf(out, "Authenticated to %s. Token stored securely for profile %q.\n", baseURL, profileName)
	return nil
}

func defaultProfile(cfg config.Config) string {
	if cfg.CurrentProfile != "" {
		return cfg.CurrentProfile
	}
	return "default"
}

func newTokenCmd(deps dependencies) *cobra.Command {
	token := &cobra.Command{Use: "token", Short: "Manage saved API tokens", SilenceUsage: true}
	var profileName string
	show := &cobra.Command{
		Use:   "show",
		Short: "Write a saved API token to standard output",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := deps.configs.Load()
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			if profileName == "" {
				profileName = defaultProfile(cfg)
			}
			if err := config.ValidateProfileName(profileName); err != nil {
				return err
			}
			if _, ok := cfg.Profiles[profileName]; !ok {
				return fmt.Errorf("profile %q does not exist", profileName)
			}
			value, err := deps.tokens.Get(profileName)
			if err != nil {
				return fmt.Errorf("retrieve token from OS keychain: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	}
	show.Flags().StringVar(&profileName, "profile", "", "saved NetBox profile to use")

	var rotateProfile string
	var rotateYes bool
	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Replace a saved v2 API token and revoke the previous token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rotateToken(cmd.Context(), cmd.OutOrStdout(), deps, rotateProfile, rotateYes)
		},
	}
	rotate.Flags().StringVar(&rotateProfile, "profile", "", "saved NetBox profile to use")
	rotate.Flags().BoolVarP(&rotateYes, "yes", "y", false, "confirm rotation without prompting")

	var revokeProfile string
	var revokeYes bool
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a saved v2 API token and remove its profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return revokeToken(cmd.Context(), cmd.OutOrStdout(), deps, revokeProfile, revokeYes)
		},
	}
	revoke.Flags().StringVar(&revokeProfile, "profile", "", "saved NetBox profile to use")
	revoke.Flags().BoolVarP(&revokeYes, "yes", "y", false, "confirm revocation without prompting")

	token.AddCommand(show, rotate, revoke)
	return token
}

func rotateToken(ctx context.Context, out io.Writer, deps dependencies, selectedProfile string, yes bool) error {
	name, profile, oldToken, oldID, err := lifecycleConnection(ctx, deps, selectedProfile)
	if err != nil {
		return err
	}
	if !yes {
		if err := confirmDestructiveAction(deps.prompt, fmt.Sprintf("Rotate token for profile %q and revoke its previous token", name)); err != nil {
			return err
		}
	}

	created, err := deps.tokenAPI.CreateToken(ctx, profile.BaseURL, oldToken, profile.InsecureTLS)
	if err != nil {
		return fmt.Errorf("create replacement NetBox token: %w", err)
	}
	if created.Version != 2 {
		if created.ID <= 0 {
			return errors.New("NetBox did not create a v2 token and omitted its ID; revoke the replacement token manually")
		}
		cleanupErr := deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, oldToken, profile.InsecureTLS, created.ID)
		if cleanupErr != nil {
			return fmt.Errorf("NetBox did not create a v2 token and cleanup failed: %w", cleanupErr)
		}
		return errors.New("NetBox did not create a v2 token; token lifecycle commands require NetBox v2 tokens")
	}
	if created.ID <= 0 {
		return errors.New("NetBox created a replacement token without an ID; refusing to replace the saved token")
	}
	if err := deps.tokens.Set(name, created.Token); err != nil {
		cleanupErr := deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, oldToken, profile.InsecureTLS, created.ID)
		if cleanupErr != nil {
			return fmt.Errorf("store replacement token in OS keychain: %w (remote cleanup also failed: %v)", err, cleanupErr)
		}
		return fmt.Errorf("store replacement token in OS keychain: %w", err)
	}

	cfg, err := deps.configs.Load()
	if err != nil {
		_ = deps.tokens.Set(name, oldToken)
		_ = deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, oldToken, profile.InsecureTLS, created.ID)
		return fmt.Errorf("load profiles after creating replacement token: %w", err)
	}
	updated := cfg.Profiles[name]
	updated.TokenVersion = created.Version
	updated.RemoteTokenID = created.ID
	cfg.Profiles[name] = updated
	if err := deps.configs.Save(cfg); err != nil {
		_ = deps.tokens.Set(name, oldToken)
		cleanupErr := deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, oldToken, profile.InsecureTLS, created.ID)
		if cleanupErr != nil {
			return fmt.Errorf("save replacement profile: %w (remote cleanup also failed: %v)", err, cleanupErr)
		}
		return fmt.Errorf("save replacement profile: %w", err)
	}
	if err := deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, created.Token, profile.InsecureTLS, oldID); err != nil {
		return fmt.Errorf("replacement token is saved, but revoking the previous NetBox token failed: %w", err)
	}
	_, err = fmt.Fprintf(out, "Rotated token for profile %q.\n", name)
	return err
}

func revokeToken(ctx context.Context, out io.Writer, deps dependencies, selectedProfile string, yes bool) error {
	name, profile, token, tokenID, err := lifecycleConnection(ctx, deps, selectedProfile)
	if err != nil {
		return err
	}
	if !yes {
		if err := confirmDestructiveAction(deps.prompt, fmt.Sprintf("Revoke token for profile %q and remove its local profile", name)); err != nil {
			return err
		}
	}
	if err := deps.tokenAPI.DeleteToken(ctx, profile.BaseURL, token, profile.InsecureTLS, tokenID); err != nil {
		return fmt.Errorf("revoke NetBox token: %w", err)
	}
	if err := removeProfile(out, deps, name, true); err != nil {
		return fmt.Errorf("NetBox token was revoked, but remove local profile: %w", err)
	}
	return nil
}

func lifecycleConnection(ctx context.Context, deps dependencies, selectedProfile string) (string, config.Profile, string, int, error) {
	if deps.tokenAPI == nil {
		return "", config.Profile{}, "", 0, errors.New("token lifecycle is not configured")
	}
	cfg, err := deps.configs.Load()
	if err != nil {
		return "", config.Profile{}, "", 0, fmt.Errorf("load profiles: %w", err)
	}
	name := selectedProfile
	if name == "" {
		name = defaultProfile(cfg)
	}
	if err := config.ValidateProfileName(name); err != nil {
		return "", config.Profile{}, "", 0, err
	}
	profile, ok := cfg.Profiles[name]
	if !ok {
		return "", config.Profile{}, "", 0, fmt.Errorf("profile %q does not exist", name)
	}
	token, err := deps.tokens.Get(name)
	if err != nil {
		return "", config.Profile{}, "", 0, fmt.Errorf("retrieve token from OS keychain: %w", err)
	}
	if !strings.HasPrefix(token, "nbt_") {
		return "", config.Profile{}, "", 0, errors.New("token lifecycle commands require a NetBox v2 token; log in again to create one")
	}
	if profile.RemoteTokenID > 0 {
		return name, profile, token, profile.RemoteTokenID, nil
	}
	metadata, err := deps.tokenAPI.FindToken(ctx, profile.BaseURL, token, profile.InsecureTLS)
	if err != nil {
		return "", config.Profile{}, "", 0, fmt.Errorf("identify saved NetBox token: %w", err)
	}
	if metadata.Version != 2 || metadata.ID <= 0 {
		return "", config.Profile{}, "", 0, errors.New("saved NetBox token is not a v2 token")
	}
	return name, profile, token, metadata.ID, nil
}

type profileView struct {
	Name         string `json:"name"`
	BaseURL      string `json:"base_url"`
	TokenVersion int    `json:"token_version"`
	InsecureTLS  bool   `json:"insecure_tls"`
	Current      bool   `json:"current"`
}

func newProfileCmd(deps dependencies) *cobra.Command {
	profile := &cobra.Command{Use: "profile", Short: "Manage saved NetBox profiles", SilenceUsage: true}

	var listOutput string
	list := &cobra.Command{
		Use:   "list",
		Short: "List saved NetBox profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listProfiles(cmd.OutOrStdout(), deps, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "table", "output format: table or json")

	var showOutput string
	show := &cobra.Command{
		Use:   "show NAME",
		Short: "Show non-secret profile details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showProfile(cmd.OutOrStdout(), deps, args[0], showOutput)
		},
	}
	show.Flags().StringVarP(&showOutput, "output", "o", "table", "output format: table or json")

	use := &cobra.Command{
		Use:   "use NAME",
		Short: "Select the current NetBox profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return useProfile(cmd.OutOrStdout(), deps, args[0])
		},
	}

	var removeYes bool
	remove := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove a saved NetBox profile and token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return removeProfile(cmd.OutOrStdout(), deps, args[0], removeYes)
		},
	}
	remove.Flags().BoolVarP(&removeYes, "yes", "y", false, "confirm removal without prompting")

	profile.AddCommand(list, show, use, remove)
	return profile
}

func listProfiles(out io.Writer, deps dependencies, output string) error {
	if err := validateOutput(output); err != nil {
		return err
	}
	cfg, err := deps.configs.Load()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}
	profiles := profileViews(cfg)
	if output == "json" {
		return writeJSON(out, profiles)
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "NAME\tBASE URL\tTOKEN VERSION\tINSECURE TLS\tCURRENT"); err != nil {
		return err
	}
	for _, value := range profiles {
		if _, err := fmt.Fprintf(table, "%s\t%s\t%d\t%t\t%t\n", value.Name, value.BaseURL, value.TokenVersion, value.InsecureTLS, value.Current); err != nil {
			return err
		}
	}
	return table.Flush()
}

func showProfile(out io.Writer, deps dependencies, name, output string) error {
	if err := config.ValidateProfileName(name); err != nil {
		return err
	}
	if err := validateOutput(output); err != nil {
		return err
	}
	cfg, err := deps.configs.Load()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}
	value, ok := cfg.Profiles[name]
	if !ok {
		return fmt.Errorf("profile %q does not exist", name)
	}
	view := profileView{Name: name, BaseURL: value.BaseURL, TokenVersion: value.TokenVersion, InsecureTLS: value.InsecureTLS, Current: cfg.CurrentProfile == name}
	if output == "json" {
		return writeJSON(out, view)
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "NAME\tBASE URL\tTOKEN VERSION\tINSECURE TLS\tCURRENT"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(table, "%s\t%s\t%d\t%t\t%t\n", view.Name, view.BaseURL, view.TokenVersion, view.InsecureTLS, view.Current); err != nil {
		return err
	}
	return table.Flush()
}

func useProfile(out io.Writer, deps dependencies, name string) error {
	if err := config.ValidateProfileName(name); err != nil {
		return err
	}
	cfg, err := deps.configs.Load()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("profile %q does not exist", name)
	}
	cfg.CurrentProfile = name
	if err := deps.configs.Save(cfg); err != nil {
		return fmt.Errorf("save current profile: %w", err)
	}
	_, err = fmt.Fprintf(out, "Selected profile %q.\n", name)
	return err
}

func removeProfile(out io.Writer, deps dependencies, name string, yes bool) error {
	if err := config.ValidateProfileName(name); err != nil {
		return err
	}
	cfg, err := deps.configs.Load()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("profile %q does not exist", name)
	}
	if !yes {
		if err := confirmDestructiveAction(deps.prompt, fmt.Sprintf("Remove profile %q and its saved token", name)); err != nil {
			return err
		}
	}
	updated := cfg
	updated.Profiles = make(map[string]config.Profile, len(cfg.Profiles)-1)
	for profileName, profileValue := range cfg.Profiles {
		if profileName != name {
			updated.Profiles[profileName] = profileValue
		}
	}
	if updated.CurrentProfile == name {
		updated.CurrentProfile = ""
	}
	if err := deps.configs.Save(updated); err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}
	if err := deps.tokens.Delete(name); err != nil {
		return fmt.Errorf("remove token from OS keychain: %w", err)
	}
	_, err = fmt.Fprintf(out, "Removed profile %q.\n", name)
	return err
}

func profileViews(cfg config.Config) []profileView {
	profiles := make([]profileView, 0, len(cfg.Profiles))
	for name, value := range cfg.Profiles {
		profiles = append(profiles, profileView{
			Name: name, BaseURL: value.BaseURL, TokenVersion: value.TokenVersion, InsecureTLS: value.InsecureTLS, Current: cfg.CurrentProfile == name,
		})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles
}

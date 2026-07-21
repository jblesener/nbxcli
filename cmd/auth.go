package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/jblesener/nbxcli/internal/tokenstore"
	"github.com/spf13/cobra"
)

func newAuthCmd(deps dependencies) *cobra.Command {
	auth := &cobra.Command{Use: "auth", Short: "Manage NetBox authentication"}
	auth.AddCommand(newLoginCmd(deps), newTokenCmd(deps))
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
		BaseURL:      baseURL,
		TokenVersion: result.Version,
		InsecureTLS:  insecure,
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
	token := &cobra.Command{Use: "token", Short: "Manage saved API tokens"}
	token.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Display a saved API token after confirmation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := deps.configs.Load()
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			profileName, err := deps.prompt.String("Profile name", defaultProfile(cfg))
			if err != nil {
				return err
			}
			if _, ok := cfg.Profiles[profileName]; !ok {
				return fmt.Errorf("profile %q does not exist", profileName)
			}
			confirmed, err := deps.prompt.Confirm("Print this token to the terminal", false)
			if err != nil {
				return err
			}
			if !confirmed {
				return errors.New("token display cancelled")
			}
			value, err := deps.tokens.Get(profileName)
			if err != nil {
				return fmt.Errorf("retrieve token from OS keychain: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	})
	return token
}

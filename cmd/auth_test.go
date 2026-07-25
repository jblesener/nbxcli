package cmd

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/jblesener/nbxcli/internal/tokenstore"
)

type memoryConfigStore struct {
	cfg     config.Config
	saveErr error
	saved   bool
}

func (s *memoryConfigStore) Load() (config.Config, error) { return s.cfg, nil }
func (s *memoryConfigStore) Save(cfg config.Config) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.cfg, s.saved = cfg, true
	return nil
}

type memoryTokenStore struct{ values map[string]string }

func (s *memoryTokenStore) Set(profile, value string) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[profile] = value
	return nil
}
func (s *memoryTokenStore) Get(profile string) (string, error) {
	value, ok := s.values[profile]
	if !ok {
		return "", tokenstore.ErrNotFound
	}
	return value, nil
}
func (s *memoryTokenStore) Delete(profile string) error { delete(s.values, profile); return nil }

type scriptedPrompt struct {
	strings  []string
	password string
	confirms []bool
}

func (p *scriptedPrompt) String(_, _ string) (string, error) {
	value := p.strings[0]
	p.strings = p.strings[1:]
	return value, nil
}
func (p *scriptedPrompt) Password(string) (string, error) { return p.password, nil }
func (p *scriptedPrompt) Confirm(string, bool) (bool, error) {
	value := p.confirms[0]
	p.confirms = p.confirms[1:]
	return value, nil
}

type fakeProvisioner struct {
	calls   []bool
	results []netbox.ProvisionResult
	errors  []error
}

func (p *fakeProvisioner) Provision(_ context.Context, _, _, _ string, insecure bool) (netbox.ProvisionResult, error) {
	p.calls = append(p.calls, insecure)
	index := len(p.calls) - 1
	if p.errors[index] != nil {
		return netbox.ProvisionResult{}, p.errors[index]
	}
	return p.results[index], nil
}

func TestLoginStoresTokenButDoesNotPrintIt(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{Profiles: map[string]config.Profile{}}}
	tokens := &memoryTokenStore{}
	api := &fakeProvisioner{results: []netbox.ProvisionResult{{Token: "nbt_key.secret", Version: 2}}, errors: []error{nil}}
	deps := dependencies{
		configs: configs,
		tokens:  tokens,
		api:     api,
		prompt:  &scriptedPrompt{strings: []string{"lab", "https://netbox.example/", "alice"}, password: "password"},
	}
	var out bytes.Buffer
	if err := login(context.Background(), &out, deps); err != nil {
		t.Fatalf("login() error = %v", err)
	}
	if tokens.values["lab"] != "nbt_key.secret" {
		t.Fatalf("stored token = %q", tokens.values["lab"])
	}
	if got := configs.cfg.Profiles["lab"]; got.BaseURL != "https://netbox.example" || got.TokenVersion != 2 || got.InsecureTLS {
		t.Fatalf("saved profile = %#v", got)
	}
	if strings.Contains(out.String(), "nbt_key.secret") || !strings.Contains(out.String(), "stored securely") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestLoginRetriesOnlyAfterConfirmedTLSBypass(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{Profiles: map[string]config.Profile{}}}
	tokens := &memoryTokenStore{}
	api := &fakeProvisioner{
		results: []netbox.ProvisionResult{{}, {Token: "legacy", Version: 1}},
		errors:  []error{x509.UnknownAuthorityError{}, nil},
	}
	deps := dependencies{
		configs: configs,
		tokens:  tokens,
		api:     api,
		prompt:  &scriptedPrompt{strings: []string{"lab", "https://netbox.example", "alice"}, password: "password", confirms: []bool{true}},
	}
	if err := login(context.Background(), &bytes.Buffer{}, deps); err != nil {
		t.Fatalf("login() error = %v", err)
	}
	if got := api.calls; len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("TLS attempts = %#v", got)
	}
	if !configs.cfg.Profiles["lab"].InsecureTLS {
		t.Fatal("InsecureTLS was not saved")
	}
}

func TestLoginFailureDoesNotReplaceExistingToken(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{Profiles: map[string]config.Profile{"lab": {BaseURL: "https://old.example", TokenVersion: 1}}}}
	tokens := &memoryTokenStore{values: map[string]string{"lab": "old-token"}}
	api := &fakeProvisioner{results: []netbox.ProvisionResult{{}}, errors: []error{errors.New("bad credentials")}}
	deps := dependencies{
		configs: configs,
		tokens:  tokens,
		api:     api,
		prompt:  &scriptedPrompt{strings: []string{"lab", "https://netbox.example", "alice"}, password: "password", confirms: []bool{true}},
	}
	if err := login(context.Background(), &bytes.Buffer{}, deps); err == nil {
		t.Fatal("login() succeeded, want error")
	}
	if tokens.values["lab"] != "old-token" || configs.saved {
		t.Fatalf("existing profile was changed: tokens=%#v saved=%v", tokens.values, configs.saved)
	}
}

func TestTokenShowWritesSelectedToken(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{
		CurrentProfile: "lab",
		Profiles:       map[string]config.Profile{"lab": {BaseURL: "https://netbox.example", TokenVersion: 2}},
	}}
	tokens := &memoryTokenStore{values: map[string]string{"lab": "nbt_key.secret"}}

	cmd := newTokenCmd(dependencies{configs: configs, tokens: tokens})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"show", "--profile", "lab"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth token show error = %v", err)
	}
	if got := out.String(); got != "nbt_key.secret\n" {
		t.Fatalf("auth token show output = %q", got)
	}
}

func TestTokenShowUsesCurrentProfileAndRejectsMissingToken(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{
		CurrentProfile: "lab",
		Profiles:       map[string]config.Profile{"lab": {BaseURL: "https://netbox.example", TokenVersion: 2}},
	}}
	t.Run("current profile", func(t *testing.T) {
		cmd := newTokenCmd(dependencies{configs: configs, tokens: &memoryTokenStore{values: map[string]string{"lab": "current-secret"}}})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"show"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if got := out.String(); got != "current-secret\n" {
			t.Fatalf("stdout = %q", got)
		}
	})
	t.Run("missing token", func(t *testing.T) {
		cmd := newTokenCmd(dependencies{configs: configs, tokens: &memoryTokenStore{}})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"show"})
		if err := cmd.Execute(); err == nil {
			t.Fatal("auth token show succeeded for missing token")
		}
		if got := out.String(); got != "" {
			t.Fatalf("stdout = %q", got)
		}
	})
	t.Run("missing profile", func(t *testing.T) {
		cmd := newTokenCmd(dependencies{configs: configs, tokens: &memoryTokenStore{}})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"show", "--profile", "unknown"})
		if err := cmd.Execute(); err == nil {
			t.Fatal("auth token show succeeded for missing profile")
		}
		if got := out.String(); got != "" {
			t.Fatalf("stdout = %q", got)
		}
	})
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreRoundTripUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store := NewFileStore(path)
	want := Config{
		CurrentProfile: "lab",
		Profiles: map[string]Profile{
			"lab": {BaseURL: "https://netbox.example", TokenVersion: 2, RemoteTokenID: 7, InsecureTLS: true},
		},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config permissions = %o, want 600", got)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.CurrentProfile != want.CurrentProfile || got.Profiles["lab"] != want.Profiles["lab"] {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestValidateProfileName(t *testing.T) {
	for _, name := range []string{"default", "lab-east_1", "prod.eu"} {
		if err := ValidateProfileName(name); err != nil {
			t.Errorf("ValidateProfileName(%q) unexpected error: %v", name, err)
		}
	}
	for _, name := range []string{"", " lab", "lab/name", "lab name"} {
		if err := ValidateProfileName(name); err == nil {
			t.Errorf("ValidateProfileName(%q) succeeded, want error", name)
		}
	}
}

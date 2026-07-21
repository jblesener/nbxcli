package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const appName = "nbxcli"

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Profile contains non-secret connection metadata. API tokens belong in the OS keychain.
type Profile struct {
	BaseURL      string `json:"base_url"`
	TokenVersion int    `json:"token_version"`
	InsecureTLS  bool   `json:"insecure_tls,omitempty"`
}

type Config struct {
	CurrentProfile string             `json:"current_profile,omitempty"`
	Profiles       map[string]Profile `json:"profiles"`
}

type Store interface {
	Load() (Config, error)
	Save(Config) error
}

type FileStore struct{ path string }

func NewDefaultStore() (*FileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &FileStore{path: filepath.Join(dir, appName, "config.json")}, nil
}

func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

func (s *FileStore) Load() (Config, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Profiles: make(map[string]Profile)}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]Profile)
	}
	return cfg, nil
}

func (s *FileStore) Save(cfg Config) error {
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]Profile)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, s.path)
}

func ValidateProfileName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return errors.New("profile name must start with a letter or number and contain only letters, numbers, dots, underscores, or hyphens")
	}
	return nil
}

package tokenstore

import (
	"errors"

	"github.com/zalando/go-keyring"
)

const serviceName = "nbxcli"

var ErrNotFound = errors.New("token not found")

type Store interface {
	Set(profile, token string) error
	Get(profile string) (string, error)
	Delete(profile string) error
}

type KeyringStore struct{}

func NewKeyringStore() KeyringStore { return KeyringStore{} }

func (KeyringStore) Set(profile, token string) error { return keyring.Set(serviceName, profile, token) }

func (KeyringStore) Get(profile string) (string, error) {
	token, err := keyring.Get(serviceName, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return token, err
}

func (KeyringStore) Delete(profile string) error {
	err := keyring.Delete(serviceName, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

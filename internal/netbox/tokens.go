package netbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const tokensPath = "/api/users/tokens/"

// TokenMetadata identifies a NetBox API token without exposing its plaintext value.
type TokenMetadata struct {
	ID      int
	Version int
}

// TokenManager creates, identifies, and deletes the API token currently used by a profile.
type TokenManager interface {
	FindToken(context.Context, string, string, bool) (TokenMetadata, error)
	CreateToken(context.Context, string, string, bool) (ProvisionResult, error)
	DeleteToken(context.Context, string, string, bool, int) error
}

// FindToken locates a v2 token using its public key. Older token formats cannot
// be identified safely from their stored plaintext.
func (c *Client) FindToken(ctx context.Context, baseURL, token string, insecureTLS bool) (TokenMetadata, error) {
	key, err := tokenKey(token)
	if err != nil {
		return TokenMetadata{}, err
	}
	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + tokensPath)
	if err != nil {
		return TokenMetadata{}, err
	}
	query := endpoint.Query()
	query.Set("key", key)
	query.Set("limit", "2")
	endpoint.RawQuery = query.Encode()
	body, _, err := c.request(ctx, baseURL, token, insecureTLS, http.MethodGet, endpoint.String(), nil, "")
	if err != nil {
		return TokenMetadata{}, err
	}
	var payload struct {
		Results []struct {
			ID      int `json:"id"`
			Version int `json:"version"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return TokenMetadata{}, fmt.Errorf("decode NetBox token response: %w", err)
	}
	if len(payload.Results) != 1 || payload.Results[0].ID <= 0 {
		return TokenMetadata{}, errors.New("could not identify the saved NetBox v2 token")
	}
	if payload.Results[0].Version != 2 {
		return TokenMetadata{}, errors.New("saved NetBox token is not a v2 token")
	}
	return TokenMetadata{ID: payload.Results[0].ID, Version: payload.Results[0].Version}, nil
}

// CreateToken creates a token using an existing authenticated token.
func (c *Client) CreateToken(ctx context.Context, baseURL, token string, insecureTLS bool) (ProvisionResult, error) {
	body, _, err := c.request(ctx, baseURL, token, insecureTLS, http.MethodPost, strings.TrimRight(baseURL, "/")+tokensPath, []byte(`{}`), "")
	if err != nil {
		return ProvisionResult{}, err
	}
	var payload struct {
		ID      int    `json:"id"`
		Version int    `json:"version"`
		Key     string `json:"key"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ProvisionResult{}, fmt.Errorf("decode NetBox token response: %w", err)
	}
	return provisionResult(payload.ID, payload.Version, payload.Key, payload.Token)
}

// DeleteToken permanently revokes a token by its NetBox ID.
func (c *Client) DeleteToken(ctx context.Context, baseURL, token string, insecureTLS bool, id int) error {
	if id <= 0 {
		return errors.New("NetBox token ID must be positive")
	}
	endpoint := fmt.Sprintf("%s%s%d/", strings.TrimRight(baseURL, "/"), tokensPath, id)
	_, _, err := c.request(ctx, baseURL, token, insecureTLS, http.MethodDelete, endpoint, nil, "")
	return err
}

func tokenKey(token string) (string, error) {
	if !strings.HasPrefix(token, "nbt_") {
		return "", errors.New("token lifecycle commands require a NetBox v2 token; log in again to create one")
	}
	remainder := strings.TrimPrefix(token, "nbt_")
	key, plaintext, ok := strings.Cut(remainder, ".")
	if !ok || key == "" || plaintext == "" || strings.Contains(plaintext, ".") {
		return "", errors.New("saved NetBox v2 token is malformed")
	}
	return key, nil
}

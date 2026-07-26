package netbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const provisionPath = "/api/users/tokens/provision/"

type ProvisionResult struct {
	ID      int
	Token   string
	Version int
}

type Provisioner interface {
	Provision(ctx context.Context, baseURL, username, password string, insecureTLS bool) (ProvisionResult, error)
}

type Client struct{ timeout time.Duration }

func NewClient() *Client { return &Client{timeout: 30 * time.Second} }

func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("NetBox URL must be an absolute http or https URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("NetBox URL scheme must be http or https")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("NetBox URL cannot include credentials, a query, or a fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.TrimRight(u.String(), "/"), nil
}

func (c *Client) Provision(ctx context.Context, baseURL, username, password string, insecureTLS bool) (ProvisionResult, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return ProvisionResult{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + provisionPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ProvisionResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicitly confirmed by the user.
	}
	client := &http.Client{Transport: transport, Timeout: c.timeout}
	response, err := client.Do(req)
	if err != nil {
		return ProvisionResult{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return ProvisionResult{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ProvisionResult{}, apiError(response.StatusCode, responseBody)
	}
	var payload struct {
		ID      int    `json:"id"`
		Version int    `json:"version"`
		Key     string `json:"key"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return ProvisionResult{}, fmt.Errorf("decode NetBox response: %w", err)
	}
	return provisionResult(payload.ID, payload.Version, payload.Key, payload.Token)
}

func provisionResult(id, version int, key, token string) (ProvisionResult, error) {
	if version == 0 {
		version = 1
	}
	if version == 2 {
		if key == "" || token == "" {
			return ProvisionResult{}, errors.New("NetBox v2 token response is missing key or token")
		}
		return ProvisionResult{ID: id, Token: "nbt_" + key + "." + token, Version: 2}, nil
	}
	if version != 1 || key == "" {
		return ProvisionResult{}, errors.New("NetBox token response is missing token key")
	}
	return ProvisionResult{ID: id, Token: key, Version: 1}, nil
}

func apiError(status int, body []byte) error {
	var payload struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Detail != "" {
		return fmt.Errorf("NetBox returned HTTP %d: %s", status, payload.Detail)
	}
	return fmt.Errorf("NetBox returned HTTP %d", status)
}

func IsTLSVerificationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	var hostname x509.HostnameError
	return errors.As(err, &unknownAuthority) || errors.As(err, &invalidCertificate) || errors.As(err, &hostname)
}

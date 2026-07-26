package netbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	InspectCertificate(ctx context.Context, baseURL string) (string, error)
	Provision(ctx context.Context, baseURL, username, password, certificateThumbprint string) (ProvisionResult, error)
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

// InspectCertificate returns the SHA-256 thumbprint of the leaf certificate
// presented by an HTTPS server. It performs no HTTP request and sends no
// credentials, so login can show the value before trusting it.
func (c *Client) InspectCertificate(ctx context.Context, baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("certificate inspection requires an https NetBox URL")
	}
	dialer := &tls.Dialer{Config: &tls.Config{ // #nosec G402 -- the certificate is displayed for explicit user approval before use.
		InsecureSkipVerify: true,
		ServerName:         u.Hostname(),
	}}
	conn, err := dialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("server did not present a certificate")
	}
	return thumbprint(state.PeerCertificates[0].Raw), nil
}

func (c *Client) Provision(ctx context.Context, baseURL, username, password, certificateThumbprint string) (ProvisionResult, error) {
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
	if transport.TLSClientConfig, err = tlsConfig(certificateThumbprint); err != nil {
		return ProvisionResult{}, err
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

func tlsConfig(certificateThumbprint string) (*tls.Config, error) {
	if certificateThumbprint == "" {
		return nil, nil
	}
	pinned, err := decodeThumbprint(certificateThumbprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{ // #nosec G402 -- VerifyConnection requires an exact saved certificate match.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server did not present a certificate")
			}
			presented := sha256.Sum256(state.PeerCertificates[0].Raw)
			if presented != pinned {
				return errors.New("server certificate thumbprint does not match the pinned certificate")
			}
			return nil
		},
	}, nil
}

func thumbprint(rawCertificate []byte) string {
	digest := sha256.Sum256(rawCertificate)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

func decodeThumbprint(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, errors.New("certificate thumbprint must be a SHA-256 hexadecimal digest")
	}
	copy(digest[:], decoded)
	return digest, nil
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

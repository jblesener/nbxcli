package netbox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const apiPath = "/api/"

// Resource is a first-party NetBox model collection available from an instance.
type Resource struct {
	Name string `json:"name"`
}

// ResourceFilter is a NetBox list-query parameter.
type ResourceFilter struct {
	Key   string
	Value string
}

// ResourceQuery controls a paginated NetBox resource-list request.
type ResourceQuery struct {
	Search  string
	Filters []ResourceFilter
	Limit   int
}

// ResourceReader discovers and retrieves NetBox model records.
type ResourceReader interface {
	ListResources(context.Context, string, string, bool) ([]Resource, error)
	ListResource(context.Context, string, string, bool, string, ResourceQuery) ([]json.RawMessage, error)
	GetResource(context.Context, string, string, bool, string, int) (json.RawMessage, error)
}

// ListResources discovers first-party model collection endpoints. Plugin endpoints
// are intentionally excluded because they are not part of the built-in data model.
func (c *Client) ListResources(ctx context.Context, baseURL, token string, insecureTLS bool) ([]Resource, error) {
	root, err := c.getMap(ctx, baseURL, token, insecureTLS, apiPath)
	if err != nil {
		return nil, fmt.Errorf("discover NetBox API root: %w", err)
	}
	apps := make([]string, 0, len(root))
	for app := range root {
		if app != "plugins" && validSegment(app) {
			apps = append(apps, app)
		}
	}
	sort.Strings(apps)

	resources := make([]Resource, 0)
	for _, app := range apps {
		models, err := c.getMap(ctx, baseURL, token, insecureTLS, apiPath+app+"/")
		if err != nil {
			return nil, fmt.Errorf("discover NetBox application %q: %w", app, err)
		}
		for model := range models {
			if validSegment(model) {
				resources = append(resources, Resource{Name: app + "." + model})
			}
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
	return resources, nil
}

// ListResource returns at most query.Limit raw records for a discovered resource.
func (c *Client) ListResource(ctx context.Context, baseURL, token string, insecureTLS bool, resource string, query ResourceQuery) ([]json.RawMessage, error) {
	if query.Limit <= 0 {
		return nil, errors.New("resource query limit must be positive")
	}
	endpoint, err := c.resourceEndpoint(ctx, baseURL, token, insecureTLS, resource)
	if err != nil {
		return nil, err
	}
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	params := parsedURL.Query()
	if query.Search != "" {
		params.Set("q", query.Search)
	}
	for _, filter := range query.Filters {
		if strings.TrimSpace(filter.Key) == "" {
			return nil, errors.New("resource filter key cannot be empty")
		}
		params.Add(filter.Key, filter.Value)
	}

	records := make([]json.RawMessage, 0, query.Limit)
	for offset := 0; len(records) < query.Limit; {
		params.Set("limit", strconv.Itoa(query.Limit-len(records)))
		params.Set("offset", strconv.Itoa(offset))
		parsedURL.RawQuery = params.Encode()
		body, err := c.get(ctx, baseURL, token, insecureTLS, parsedURL.String())
		if err != nil {
			return nil, err
		}
		var page struct {
			Next    *string           `json:"next"`
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode NetBox resource response: %w", err)
		}
		remaining := query.Limit - len(records)
		if len(page.Results) > remaining {
			page.Results = page.Results[:remaining]
		}
		records = append(records, page.Results...)
		if page.Next == nil || *page.Next == "" || len(page.Results) == 0 {
			break
		}
		offset += len(page.Results)
	}
	return records, nil
}

// GetResource retrieves one record by its positive numeric ID.
func (c *Client) GetResource(ctx context.Context, baseURL, token string, insecureTLS bool, resource string, id int) (json.RawMessage, error) {
	if id <= 0 {
		return nil, errors.New("resource ID must be positive")
	}
	endpoint, err := c.resourceEndpoint(ctx, baseURL, token, insecureTLS, resource)
	if err != nil {
		return nil, err
	}
	body, err := c.get(ctx, baseURL, token, insecureTLS, endpoint+strconv.Itoa(id)+"/")
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, errors.New("decode NetBox resource response: invalid JSON")
	}
	return json.RawMessage(body), nil
}

func (c *Client) resourceEndpoint(ctx context.Context, baseURL, token string, insecureTLS bool, resource string) (string, error) {
	app, model, ok := strings.Cut(resource, ".")
	if !ok || !validSegment(app) || !validSegment(model) || strings.Contains(model, ".") {
		return "", fmt.Errorf("invalid resource %q; use application.resource", resource)
	}
	resources, err := c.ListResources(ctx, baseURL, token, insecureTLS)
	if err != nil {
		return "", err
	}
	for _, candidate := range resources {
		if candidate.Name == resource {
			return strings.TrimRight(baseURL, "/") + apiPath + app + "/" + model + "/", nil
		}
	}
	return "", fmt.Errorf("resource %q is not available on this NetBox instance", resource)
}

func (c *Client) getMap(ctx context.Context, baseURL, token string, insecureTLS bool, path string) (map[string]string, error) {
	body, err := c.get(ctx, baseURL, token, insecureTLS, strings.TrimRight(baseURL, "/")+path)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(body, &values); err != nil {
		return nil, fmt.Errorf("decode NetBox API discovery response: %w", err)
	}
	return values, nil
}

func (c *Client) get(ctx context.Context, baseURL, token string, insecureTLS bool, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.HasPrefix(token, "nbt_") {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("Authorization", "Token "+token)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- stored only after explicit user confirmation.
	}
	client := &http.Client{Transport: transport, Timeout: c.timeout}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, apiError(response.StatusCode, body)
	}
	return body, nil
}

func validSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

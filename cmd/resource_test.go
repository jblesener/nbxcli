package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jblesener/nbxcli/internal/config"
	"github.com/jblesener/nbxcli/internal/netbox"
	"github.com/spf13/pflag"
)

type fakeResourceReader struct {
	baseURL   string
	token     string
	insecure  bool
	resource  string
	query     netbox.ResourceQuery
	resources []netbox.Resource
	records   []json.RawMessage
	record    json.RawMessage
	payload   json.RawMessage
	id        int
	deleted   bool
	err       error
}

type nonInteractivePrompt struct{}

func (nonInteractivePrompt) String(string, string) (string, error) {
	return "", errors.New("should not prompt")
}
func (nonInteractivePrompt) Password(string) (string, error) {
	return "", errors.New("should not prompt")
}
func (nonInteractivePrompt) Confirm(string, bool) (bool, error) {
	return false, errors.New("should not prompt")
}
func (nonInteractivePrompt) Interactive() bool { return false }

func (r *fakeResourceReader) ListResources(_ context.Context, baseURL, token string, insecure bool) ([]netbox.Resource, error) {
	r.baseURL, r.token, r.insecure = baseURL, token, insecure
	return r.resources, r.err
}
func (r *fakeResourceReader) ListResource(_ context.Context, baseURL, token string, insecure bool, resource string, query netbox.ResourceQuery) ([]json.RawMessage, error) {
	r.baseURL, r.token, r.insecure, r.resource, r.query = baseURL, token, insecure, resource, query
	return r.records, r.err
}
func (r *fakeResourceReader) GetResource(_ context.Context, baseURL, token string, insecure bool, resource string, _ int) (json.RawMessage, error) {
	r.baseURL, r.token, r.insecure, r.resource = baseURL, token, insecure, resource
	return r.record, r.err
}
func (r *fakeResourceReader) CreateResource(_ context.Context, baseURL, token string, insecure bool, resource string, payload json.RawMessage) (json.RawMessage, error) {
	r.baseURL, r.token, r.insecure, r.resource, r.payload = baseURL, token, insecure, resource, payload
	return r.record, r.err
}
func (r *fakeResourceReader) UpdateResource(_ context.Context, baseURL, token string, insecure bool, resource string, id int, payload json.RawMessage) (json.RawMessage, error) {
	r.baseURL, r.token, r.insecure, r.resource, r.id, r.payload = baseURL, token, insecure, resource, id, payload
	return r.record, r.err
}
func (r *fakeResourceReader) DeleteResource(_ context.Context, baseURL, token string, insecure bool, resource string, id int) error {
	r.baseURL, r.token, r.insecure, r.resource, r.id, r.deleted = baseURL, token, insecure, resource, id, true
	return r.err
}

func TestGetResourceUsesProfileAndRendersTable(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example", InsecureTLS: true}}}}
	reader := &fakeResourceReader{records: []json.RawMessage{json.RawMessage(`{"id":1,"name":"leaf-01","status":{"label":"Active"}}`)}}
	deps := dependencies{configs: configs, tokens: &memoryTokenStore{values: map[string]string{"lab": "secret"}}, resources: reader}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var out bytes.Buffer
	err := getResource(context.Background(), &out, deps, []string{"dcim.devices"}, resourceGetOptions{search: "leaf", filters: []string{"site=tokyo"}, limit: 5, output: "table"}, flags)
	if err != nil {
		t.Fatalf("getResource() error = %v", err)
	}
	if reader.baseURL != "https://netbox.example" || reader.token != "secret" || !reader.insecure || reader.resource != "dcim.devices" || reader.query.Limit != 5 {
		t.Fatalf("query = %#v", reader)
	}
	if !strings.Contains(out.String(), "ID") || !strings.Contains(out.String(), "leaf-01") || !strings.Contains(out.String(), "Active") {
		t.Fatalf("table output = %q", out.String())
	}
}

func TestGetCommandDefaultsToTable(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}
	deps := dependencies{configs: configs, tokens: &memoryTokenStore{values: map[string]string{"lab": "secret"}}}

	for _, test := range []struct {
		name    string
		args    []string
		reader  *fakeResourceReader
		matches []string
	}{
		{
			name:    "list",
			args:    []string{"dcim.devices"},
			reader:  &fakeResourceReader{records: []json.RawMessage{json.RawMessage(`{"id":1,"name":"leaf-01","status":{"label":"Active"}}`)}},
			matches: []string{"ID", "DISPLAY", "STATUS", "1", "leaf-01", "Active"},
		},
		{
			name:    "detail",
			args:    []string{"ipam.prefixes", "42"},
			reader:  &fakeResourceReader{record: json.RawMessage(`{"id":42,"display":"192.0.2.0/24","status":"active"}`)},
			matches: []string{"ID", "DISPLAY", "STATUS", "42", "192.0.2.0/24", "active"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := newGetCmd(dependencies{configs: deps.configs, tokens: deps.tokens, resources: test.reader})
			cmd.SetOut(&out)
			cmd.SetArgs(test.args)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			for _, match := range test.matches {
				if !strings.Contains(out.String(), match) {
					t.Errorf("output %q does not contain %q", out.String(), match)
				}
			}
		})
	}
}

func TestGetCommandDetailWritesJSON(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}
	reader := &fakeResourceReader{record: json.RawMessage(`{"id":42,"display":"192.0.2.0/24"}`)}
	deps := dependencies{configs: configs, tokens: &memoryTokenStore{values: map[string]string{"lab": "secret"}}, resources: reader}
	var out bytes.Buffer
	cmd := newGetCmd(deps)
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"ipam.prefixes", "42", "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if reader.resource != "ipam.prefixes" || out.String() != `{"id":42,"display":"192.0.2.0/24"}`+"\n" {
		t.Fatalf("result = reader=%#v output=%q", reader, out.String())
	}
}

func TestListResourcesWritesJSON(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}
	reader := &fakeResourceReader{resources: []netbox.Resource{{Name: "dcim.devices"}, {Name: "ipam.prefixes"}}}
	deps := dependencies{configs: configs, tokens: &memoryTokenStore{values: map[string]string{"lab": "secret"}}, resources: reader}
	var out bytes.Buffer
	if err := listResources(context.Background(), &out, deps, resourcesOptions{output: "json"}); err != nil {
		t.Fatalf("listResources() error = %v", err)
	}
	if got := out.String(); got != `[{"name":"dcim.devices"},{"name":"ipam.prefixes"}]`+"\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestGetResourceRejectsInvalidInputsAndMissingToken(t *testing.T) {
	deps := dependencies{configs: &memoryConfigStore{cfg: config.Config{Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}, tokens: &memoryTokenStore{}, resources: &fakeResourceReader{err: errors.New("should not be called")}}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	_ = flags.Bool("search", false, "")
	_ = flags.Bool("filter", false, "")
	_ = flags.Bool("limit", false, "")
	for _, args := range [][]string{{"dcim.devices"}, {"dcim.devices", "zero"}} {
		err := getResource(context.Background(), &bytes.Buffer{}, deps, args, resourceGetOptions{limit: 0, output: "table"}, flags)
		if err == nil {
			t.Fatalf("getResource(%#v) succeeded", args)
		}
	}
}

func TestCreateAndUpdateResourceUseJSONPayloads(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}
	tokens := &memoryTokenStore{values: map[string]string{"lab": "secret"}}
	t.Run("create inline JSON", func(t *testing.T) {
		reader := &fakeResourceReader{record: json.RawMessage(`{"id":1,"name":"leaf-01"}`)}
		var out bytes.Buffer
		err := createResource(context.Background(), &out, dependencies{configs: configs, tokens: tokens, resources: reader}, "dcim.devices", resourceWriteOptions{data: `{"name":"leaf-01"}`, output: "json"})
		if err != nil {
			t.Fatal(err)
		}
		if reader.resource != "dcim.devices" || string(reader.payload) != `{"name":"leaf-01"}` || out.String() != `{"id":1,"name":"leaf-01"}`+"\n" {
			t.Fatalf("reader=%#v output=%q", reader, out.String())
		}
	})
	t.Run("update file JSON", func(t *testing.T) {
		path := t.TempDir() + "/payload.json"
		if err := os.WriteFile(path, []byte(`{"status":"active"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		reader := &fakeResourceReader{record: json.RawMessage(`{"id":7,"status":"active"}`)}
		err := updateResource(context.Background(), &bytes.Buffer{}, dependencies{configs: configs, tokens: tokens, resources: reader}, "dcim.devices", "7", resourceWriteOptions{data: "@" + path, output: "table"})
		if err != nil {
			t.Fatal(err)
		}
		if reader.id != 7 || string(reader.payload) != `{"status":"active"}` {
			t.Fatalf("reader=%#v", reader)
		}
	})
}

func TestResourceMutationRejectsUnsafeInputs(t *testing.T) {
	deps := dependencies{resources: &fakeResourceReader{}}
	if err := createResource(context.Background(), &bytes.Buffer{}, deps, "dcim.devices", resourceWriteOptions{data: "[]", output: "table"}); err == nil {
		t.Fatal("createResource accepted an array payload")
	}
	if err := updateResource(context.Background(), &bytes.Buffer{}, deps, "dcim.devices", "zero", resourceWriteOptions{data: `{}`, output: "table"}); err == nil {
		t.Fatal("updateResource accepted an invalid ID")
	}
	if err := deleteResource(context.Background(), &bytes.Buffer{}, deps, "dcim.devices", "1", resourceDeleteOptions{}); err == nil || !strings.Contains(err.Error(), "no interactive prompt") {
		t.Fatalf("deleteResource error = %v", err)
	}
	deps.prompt = nonInteractivePrompt{}
	if err := deleteResource(context.Background(), &bytes.Buffer{}, deps, "dcim.devices", "1", resourceDeleteOptions{}); err == nil || !strings.Contains(err.Error(), "not an interactive terminal") {
		t.Fatalf("deleteResource error = %v", err)
	}
}

func TestDeleteResourceRequiresConfirmationOrYes(t *testing.T) {
	configs := &memoryConfigStore{cfg: config.Config{CurrentProfile: "lab", Profiles: map[string]config.Profile{"lab": {BaseURL: "https://netbox.example"}}}}
	tokens := &memoryTokenStore{values: map[string]string{"lab": "secret"}}
	reader := &fakeResourceReader{}
	deps := dependencies{configs: configs, tokens: tokens, resources: reader, prompt: &scriptedPrompt{confirms: []bool{true}}}
	var out bytes.Buffer
	if err := deleteResource(context.Background(), &out, deps, "dcim.devices", "3", resourceDeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if !reader.deleted || out.String() != "Deleted dcim.devices 3.\n" {
		t.Fatalf("reader=%#v output=%q", reader, out.String())
	}
	reader = &fakeResourceReader{}
	if err := deleteResource(context.Background(), &bytes.Buffer{}, dependencies{configs: configs, tokens: tokens, resources: reader}, "dcim.devices", "4", resourceDeleteOptions{yes: true}); err != nil {
		t.Fatal(err)
	}
	if !reader.deleted || reader.id != 4 {
		t.Fatalf("reader=%#v", reader)
	}
}

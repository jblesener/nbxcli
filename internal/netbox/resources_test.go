package netbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListResourcesDiscoversFirstPartyModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token saved-token" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"plugins":"plugins/","dcim":"dcim/","ipam":"ipam/"}`))
		case "/api/dcim/":
			_, _ = w.Write([]byte(`{"devices":"devices/","interfaces":"interfaces/"}`))
		case "/api/ipam/":
			_, _ = w.Write([]byte(`{"prefixes":"prefixes/","bad/path":"bad/path/"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	resources, err := NewClient().ListResources(context.Background(), server.URL, "saved-token", false)
	if err != nil {
		t.Fatalf("ListResources() error = %v", err)
	}
	want := []string{"dcim.devices", "dcim.interfaces", "ipam.prefixes"}
	if len(resources) != len(want) {
		t.Fatalf("resources = %#v", resources)
	}
	for index, name := range want {
		if resources[index].Name != name {
			t.Fatalf("resource %d = %q, want %q", index, resources[index].Name, name)
		}
	}
}

func TestListResourceAuthenticatesFiltersAndPaginates(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"dcim":"dcim/"}`))
		case "/api/dcim/":
			_, _ = w.Write([]byte(`{"devices":"devices/"}`))
		case "/api/dcim/devices/":
			calls++
			if got := r.Header.Get("Authorization"); got != "Token saved-token" {
				t.Fatalf("Authorization = %q", got)
			}
			if got := r.URL.Query().Get("q"); got != "edge" {
				t.Fatalf("q = %q", got)
			}
			if got := r.URL.Query()["site"]; len(got) != 2 || got[0] != "tokyo" || got[1] != "osaka" {
				t.Fatalf("site = %#v", got)
			}
			switch r.URL.Query().Get("offset") {
			case "0":
				_, _ = w.Write([]byte(`{"next":"next","results":[{"name":"one"},{"name":"two"}]}`))
			case "2":
				if got := r.URL.Query().Get("limit"); got != "1" {
					t.Fatalf("second limit = %q", got)
				}
				_, _ = w.Write([]byte(`{"next":null,"results":[{"name":"three"}]}`))
			default:
				t.Fatalf("offset = %q", r.URL.Query().Get("offset"))
			}
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	records, err := NewClient().ListResource(context.Background(), server.URL, "saved-token", false, "dcim.devices", ResourceQuery{
		Search: "edge", Filters: []ResourceFilter{{Key: "site", Value: "tokyo"}, {Key: "site", Value: "osaka"}}, Limit: 3,
	})
	if err != nil {
		t.Fatalf("ListResource() error = %v", err)
	}
	if calls != 2 || len(records) != 3 {
		t.Fatalf("calls=%d records=%d, want 2 and 3", calls, len(records))
	}
}

func TestGetResourceUsesBearerForV2Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"ipam":"ipam/"}`))
		case "/api/ipam/":
			_, _ = w.Write([]byte(`{"prefixes":"prefixes/"}`))
		case "/api/ipam/prefixes/42/":
			if got := r.Header.Get("Authorization"); got != "Bearer nbt_key.secret" {
				t.Fatalf("Authorization = %q", got)
			}
			_, _ = w.Write([]byte(`{"id":42,"display":"192.0.2.0/24"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	record, err := NewClient().GetResource(context.Background(), server.URL, "nbt_key.secret", false, "ipam.prefixes", 42)
	if err != nil {
		t.Fatalf("GetResource() error = %v", err)
	}
	if got := string(record); got != `{"id":42,"display":"192.0.2.0/24"}` {
		t.Fatalf("record = %s", record)
	}
}

func TestResourceQueriesRejectInvalidInput(t *testing.T) {
	client := NewClient()
	if _, err := client.ListResource(context.Background(), "https://netbox.example", "token", false, "dcim.devices", ResourceQuery{}); err == nil {
		t.Fatal("ListResource() succeeded with zero limit")
	}
	if _, err := client.GetResource(context.Background(), "https://netbox.example", "token", false, "dcim.devices", 0); err == nil {
		t.Fatal("GetResource() succeeded with zero ID")
	}
}

func TestCreateResourcePostsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"dcim":"dcim/"}`))
		case "/api/dcim/":
			_, _ = w.Write([]byte(`{"devices":"devices/"}`))
		case "/api/dcim/devices/":
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer nbt_key.secret" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("request = %s auth=%q content-type=%q", r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["name"] != "leaf-01" {
				t.Fatalf("body=%#v err=%v", body, err)
			}
			_, _ = w.Write([]byte(`{"id":1,"name":"leaf-01"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	record, err := NewClient().CreateResource(context.Background(), server.URL, "nbt_key.secret", false, "dcim.devices", json.RawMessage(`{"name":"leaf-01"}`))
	if err != nil || string(record) != `{"id":1,"name":"leaf-01"}` {
		t.Fatalf("CreateResource() = %s, %v", record, err)
	}
}

func TestUpdateResourceUsesETag(t *testing.T) {
	patchCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"dcim":"dcim/"}`))
		case "/api/dcim/":
			_, _ = w.Write([]byte(`{"devices":"devices/"}`))
		case "/api/dcim/devices/42/":
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("ETag", `W/"2026-01-01T00:00:00Z"`)
				_, _ = w.Write([]byte(`{"id":42,"name":"old"}`))
			case http.MethodPatch:
				patchCalled = true
				if got := r.Header.Get("If-Match"); got != `W/"2026-01-01T00:00:00Z"` {
					t.Fatalf("If-Match = %q", got)
				}
				_, _ = w.Write([]byte(`{"id":42,"name":"new"}`))
			default:
				t.Fatalf("method = %s", r.Method)
			}
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	record, err := NewClient().UpdateResource(context.Background(), server.URL, "token", false, "dcim.devices", 42, json.RawMessage(`{"name":"new"}`))
	if err != nil || !patchCalled || string(record) != `{"id":42,"name":"new"}` {
		t.Fatalf("UpdateResource() = %s, %v; patch=%v", record, err, patchCalled)
	}
}

func TestUpdateResourceRejectsMissingETagAndConflict(t *testing.T) {
	t.Run("missing ETag", func(t *testing.T) {
		patchCalled := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/":
				_, _ = w.Write([]byte(`{"dcim":"dcim/"}`))
			case "/api/dcim/":
				_, _ = w.Write([]byte(`{"devices":"devices/"}`))
			case "/api/dcim/devices/42/":
				if r.Method == http.MethodPatch {
					patchCalled = true
				}
				_, _ = w.Write([]byte(`{"id":42}`))
			}
		}))
		defer server.Close()
		_, err := NewClient().UpdateResource(context.Background(), server.URL, "token", false, "dcim.devices", 42, json.RawMessage(`{"name":"new"}`))
		if err == nil || !strings.Contains(err.Error(), "did not return an ETag") || patchCalled {
			t.Fatalf("error=%v patch=%v", err, patchCalled)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/":
				_, _ = w.Write([]byte(`{"dcim":"dcim/"}`))
			case "/api/dcim/":
				_, _ = w.Write([]byte(`{"devices":"devices/"}`))
			case "/api/dcim/devices/42/":
				if r.Method == http.MethodGet {
					w.Header().Set("ETag", `W/"old"`)
					_, _ = w.Write([]byte(`{"id":42}`))
					return
				}
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"detail":"Record has changed."}`))
			}
		}))
		defer server.Close()
		_, err := NewClient().UpdateResource(context.Background(), server.URL, "token", false, "dcim.devices", 42, json.RawMessage(`{"name":"new"}`))
		if err == nil || !strings.Contains(err.Error(), "HTTP 412") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestDeleteResourceUsesDetailEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/":
			_, _ = w.Write([]byte(`{"ipam":"ipam/"}`))
		case "/api/ipam/":
			_, _ = w.Write([]byte(`{"prefixes":"prefixes/"}`))
		case "/api/ipam/prefixes/4/":
			if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Token token" {
				t.Fatalf("request = %s auth=%q", r.Method, r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	if err := NewClient().DeleteResource(context.Background(), server.URL, "token", false, "ipam.prefixes", 4); err != nil {
		t.Fatal(err)
	}
}

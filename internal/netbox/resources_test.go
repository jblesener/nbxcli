package netbox

import (
	"context"
	"net/http"
	"net/http/httptest"
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

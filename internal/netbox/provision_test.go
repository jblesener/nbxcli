package netbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProvisionV2Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != provisionPath {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["username"] != "alice" || body["password"] != "secret" {
			t.Fatalf("body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":2,"key":"shortkey","token":"plaintext"}`))
	}))
	defer server.Close()

	got, err := NewClient().Provision(context.Background(), server.URL, "alice", "secret", false)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if got.Token != "nbt_shortkey.plaintext" || got.Version != 2 {
		t.Fatalf("Provision() = %#v", got)
	}
}

func TestProvisionLegacyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"key":"legacytoken"}`))
	}))
	defer server.Close()

	got, err := NewClient().Provision(context.Background(), server.URL, "alice", "secret", false)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if got.Token != "legacytoken" || got.Version != 1 {
		t.Fatalf("Provision() = %#v", got)
	}
}

func TestProvisionReturnsSafeAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Token creation is not permitted."}`))
	}))
	defer server.Close()

	_, err := NewClient().Provision(context.Background(), server.URL, "alice", "secret", false)
	if err == nil || err.Error() != "NetBox returned HTTP 403: Token creation is not permitted." {
		t.Fatalf("Provision() error = %v", err)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	got, err := NormalizeBaseURL(" https://netbox.example/netbox/ ")
	if err != nil || got != "https://netbox.example/netbox" {
		t.Fatalf("NormalizeBaseURL() = %q, %v", got, err)
	}
	for _, value := range []string{"netbox.example", "ftp://netbox.example", "https://netbox.example/?x=1"} {
		if _, err := NormalizeBaseURL(value); err == nil {
			t.Errorf("NormalizeBaseURL(%q) succeeded, want error", value)
		}
	}
}

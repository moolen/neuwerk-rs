package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIClientFallsBackToSecondEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"configured":true,"source":"local","fingerprint_sha256":"abc123"}`))
	}))
	defer server.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := newAPIClient(apiClientConfig{
		endpoints:      []string{"https://127.0.0.1:1", server.URL},
		token:          "token-1",
		caCertPEM:      certPEM,
		requestTimeout: time.Second,
		retryTimeout:   250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	status, err := client.GetTLSInterceptCA(context.Background())
	if err != nil {
		t.Fatalf("get tls intercept ca: %v", err)
	}
	if !status.Configured {
		t.Fatalf("expected configured status")
	}
	if status.Source == nil || *status.Source != "local" {
		t.Fatalf("unexpected source: %#v", status.Source)
	}
}

func TestAPIClientDecodesStructuredErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
	}))
	defer server.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := newAPIClient(apiClientConfig{
		endpoints:      []string{server.URL},
		token:          "token-1",
		caCertPEM:      certPEM,
		requestTimeout: time.Second,
		retryTimeout:   0,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = client.DeleteIntegration(context.Background(), "prod")
	if err == nil {
		t.Fatalf("expected error")
	}

	apiErr, ok := err.(*apiError)
	if !ok {
		t.Fatalf("expected apiError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status: %d", apiErr.StatusCode)
	}
	if apiErr.Message != "admin role required" {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestBuildHTTPClientAcceptsCustomCA(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`ok`))
	}))
	defer server.Close()

	block := &pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}
	certPEM := pem.EncodeToMemory(block)

	client, err := buildHTTPClient(certPEM, time.Second)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to parse cert pem")
	}
}

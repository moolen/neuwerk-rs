package provider

import (
	"context"
	"crypto/x509"
	"encoding/json"
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

func TestAPIClientCreatesServiceAccount(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		var req createServiceAccountRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Name != "ci-bot" {
			t.Fatalf("unexpected name %q", req.Name)
		}
		if req.Description == nil || *req.Description != "build bot" {
			t.Fatalf("unexpected description %#v", req.Description)
		}
		if req.Role != "admin" {
			t.Fatalf("unexpected role %q", req.Role)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"acc-1","name":"ci-bot","description":"build bot","created_at":"2024-01-01T00:00:00Z","created_by":"admin","role":"admin","status":"active"}`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	account, err := client.CreateServiceAccount(context.Background(), createServiceAccountRequest{
		Name:        "ci-bot",
		Description: stringPtr("build bot"),
		Role:        "admin",
	})
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	if account.ID != "acc-1" {
		t.Fatalf("unexpected id %q", account.ID)
	}
	if account.Name != "ci-bot" {
		t.Fatalf("unexpected name %q", account.Name)
	}
	if account.Description == nil || *account.Description != "build bot" {
		t.Fatalf("unexpected description %#v", account.Description)
	}
	if account.CreatedAt != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", account.CreatedAt)
	}
	if account.CreatedBy != "admin" {
		t.Fatalf("unexpected created_by %q", account.CreatedBy)
	}
	if account.Role != "admin" {
		t.Fatalf("unexpected role %q", account.Role)
	}
	if account.Status != "active" {
		t.Fatalf("unexpected status %q", account.Status)
	}
}

func TestAPIClientListsServiceAccounts(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id":"acc-1","name":"ci-bot","description":"build bot","created_at":"2024-01-01T00:00:00Z","created_by":"admin","role":"admin","status":"active"},
			{"id":"acc-2","name":"reporter","description":null,"created_at":"2024-01-02T00:00:00Z","created_by":"admin","role":"readonly","status":"disabled"}
		]`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	accounts, err := client.ListServiceAccounts(context.Background())
	if err != nil {
		t.Fatalf("list service accounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("unexpected account count %d", len(accounts))
	}
	if accounts[1].ID != "acc-2" {
		t.Fatalf("unexpected id %q", accounts[1].ID)
	}
	if accounts[1].Description != nil {
		t.Fatalf("unexpected description %#v", accounts[1].Description)
	}
	if accounts[1].Status != "disabled" {
		t.Fatalf("unexpected status %q", accounts[1].Status)
	}
}

func TestAPIClientListsServiceAccountsEmptyResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`null`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	accounts, err := client.ListServiceAccounts(context.Background())
	if err != nil {
		t.Fatalf("list service accounts: %v", err)
	}
	if accounts == nil {
		t.Fatalf("expected non-nil slice")
	}
	if len(accounts) != 0 {
		t.Fatalf("unexpected account count %d", len(accounts))
	}
}

func TestAPIClientMintsServiceAccountToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-1/tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var req createServiceAccountTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Name == nil || *req.Name != "deploy token" {
			t.Fatalf("unexpected name %#v", req.Name)
		}
		if req.TTL == nil || *req.TTL != "24h" {
			t.Fatalf("unexpected ttl %#v", req.TTL)
		}
		if req.Eternal == nil || *req.Eternal {
			t.Fatalf("unexpected eternal %#v", req.Eternal)
		}
		if req.Role == nil || *req.Role != "readonly" {
			t.Fatalf("unexpected role %#v", req.Role)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"token":"signed-token",
			"token_meta":{
				"id":"tok-1",
				"service_account_id":"acc-1",
				"name":"deploy token",
				"created_at":"2024-01-01T00:00:00Z",
				"created_by":"admin",
				"expires_at":"2024-01-02T00:00:00Z",
				"revoked_at":null,
				"last_used_at":null,
				"kid":"kid-1",
				"role":"readonly",
				"status":"active"
			}
		}`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	record, err := client.CreateServiceAccountToken(context.Background(), "acc-1", createServiceAccountTokenRequest{
		Name:    stringPtr("deploy token"),
		TTL:     stringPtr("24h"),
		Eternal: boolPtr(false),
		Role:    stringPtr("readonly"),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if record.Token != "signed-token" {
		t.Fatalf("unexpected token %q", record.Token)
	}
	if record.TokenMeta.ID != "tok-1" {
		t.Fatalf("unexpected meta id %q", record.TokenMeta.ID)
	}
	if record.TokenMeta.ServiceAccountID != "acc-1" {
		t.Fatalf("unexpected service account id %q", record.TokenMeta.ServiceAccountID)
	}
	if record.TokenMeta.Kid != "kid-1" {
		t.Fatalf("unexpected kid %q", record.TokenMeta.Kid)
	}
	if record.TokenMeta.Status != "active" {
		t.Fatalf("unexpected status %q", record.TokenMeta.Status)
	}
}

func TestAPIClientGetsUpdatesAndDeletesServiceAccount(t *testing.T) {
	t.Parallel()

	step := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if r.URL.Path != "/api/v1/service-accounts/acc-1" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"acc-1","name":"ci-bot","description":"build bot","created_at":"2024-01-01T00:00:00Z","created_by":"admin","role":"admin","status":"active"}`))
		case 2:
			if r.Method != http.MethodPut {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if r.URL.Path != "/api/v1/service-accounts/acc-1" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			var req updateServiceAccountRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req.Name != "ci-bot-2" {
				t.Fatalf("unexpected name %q", req.Name)
			}
			if req.Description == nil || *req.Description != "updated" {
				t.Fatalf("unexpected description %#v", req.Description)
			}
			if req.Role != "readonly" {
				t.Fatalf("unexpected role %q", req.Role)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"acc-1","name":"ci-bot-2","description":"updated","created_at":"2024-01-01T00:00:00Z","created_by":"admin","role":"readonly","status":"active"}`))
		case 3:
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if r.URL.Path != "/api/v1/service-accounts/acc-1" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %d: %s %s", step, r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	account, err := client.GetServiceAccount(context.Background(), "acc-1")
	if err != nil {
		t.Fatalf("get service account: %v", err)
	}
	if account.ID != "acc-1" {
		t.Fatalf("unexpected id %q", account.ID)
	}

	updated, err := client.UpdateServiceAccount(context.Background(), "acc-1", updateServiceAccountRequest{
		Name:        "ci-bot-2",
		Description: stringPtr("updated"),
		Role:        "readonly",
	})
	if err != nil {
		t.Fatalf("update service account: %v", err)
	}
	if updated.Name != "ci-bot-2" {
		t.Fatalf("unexpected updated name %q", updated.Name)
	}
	if err := client.DeleteServiceAccount(context.Background(), "acc-1"); err != nil {
		t.Fatalf("delete service account: %v", err)
	}
}

func TestAPIClientListsAndDeletesServiceAccountToken(t *testing.T) {
	t.Parallel()

	step := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if r.URL.Path != "/api/v1/service-accounts/acc-1/tokens" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{
					"id":"tok-1",
					"service_account_id":"acc-1",
					"name":"deploy token",
					"created_at":"2024-01-01T00:00:00Z",
					"created_by":"admin",
					"expires_at":"2024-01-02T00:00:00Z",
					"revoked_at":null,
					"last_used_at":null,
					"kid":"kid-1",
					"role":"readonly",
					"status":"active"
				}
			]`))
		case 2:
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method %s", r.Method)
			}
			if r.URL.Path != "/api/v1/service-accounts/acc-1/tokens/tok-1" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %d: %s %s", step, r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	tokens, err := client.ListServiceAccountTokens(context.Background(), "acc-1")
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("unexpected token count %d", len(tokens))
	}
	token := tokens[0]
	if token.ID != "tok-1" {
		t.Fatalf("unexpected id %q", token.ID)
	}
	if token.ServiceAccountID != "acc-1" {
		t.Fatalf("unexpected service account id %q", token.ServiceAccountID)
	}
	if token.Kid != "kid-1" {
		t.Fatalf("unexpected kid %q", token.Kid)
	}
	if token.Role != "readonly" {
		t.Fatalf("unexpected role %q", token.Role)
	}
	if token.Status != "active" {
		t.Fatalf("unexpected status %q", token.Status)
	}
	if err := client.DeleteServiceAccountToken(context.Background(), "acc-1", "tok-1"); err != nil {
		t.Fatalf("delete token: %v", err)
	}
}

func TestAPIClientListsServiceAccountTokensEmptyResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-1/tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`null`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	tokens, err := client.ListServiceAccountTokens(context.Background(), "acc-1")
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if tokens == nil {
		t.Fatalf("expected non-nil slice")
	}
	if len(tokens) != 0 {
		t.Fatalf("unexpected token count %d", len(tokens))
	}
}

func TestAPIClientCreateServiceAccountTokenSurfacesAPIErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		payload  string
		expected string
	}{
		{name: "role too high", payload: `{"error":"token role exceeds account role"}`, expected: "token role exceeds account role"},
		{name: "disabled", payload: `{"error":"service account disabled"}`, expected: "service account disabled"},
		{name: "invalid ttl", payload: `{"error":"invalid ttl: expected duration"}`, expected: "invalid ttl: expected duration"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Fatalf("unexpected method %s", r.Method)
				}
				if r.URL.Path != "/api/v1/service-accounts/acc-1/tokens" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				http.Error(w, tc.payload, http.StatusBadRequest)
			}))
			defer server.Close()

			client := newTestAPIClient(t, server)
			_, err := client.CreateServiceAccountToken(context.Background(), "acc-1", createServiceAccountTokenRequest{
				Name: stringPtr("deploy token"),
			})
			if err == nil {
				t.Fatalf("expected error")
			}
			apiErr, ok := err.(*apiError)
			if !ok {
				t.Fatalf("expected apiError, got %T", err)
			}
			if apiErr.Message != tc.expected {
				t.Fatalf("unexpected error message %q", apiErr.Message)
			}
		})
	}
}

func newTestAPIClient(t *testing.T, server *httptest.Server) *apiClient {
	t.Helper()

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
	return client
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

package provider

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

type apiClientConfig struct {
	endpoints      []string
	token          string
	caCertPEM      []byte
	requestTimeout time.Duration
	retryTimeout   time.Duration
	headers        map[string]string
}

type apiClient struct {
	endpoints    []string
	token        string
	httpClient   *http.Client
	retryTimeout time.Duration
	headers      map[string]string
}

type apiError struct {
	StatusCode int
	Message    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("api request failed with status %d: %s", e.StatusCode, e.Message)
}

type apiErrorBody struct {
	Error string `json:"error"`
}

type apiIntegrationView struct {
	ID              string `json:"id"`
	CreatedAt       string `json:"created_at"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	APIServerURL    string `json:"api_server_url"`
	CACertPEM       string `json:"ca_cert_pem"`
	AuthType        string `json:"auth_type"`
	TokenConfigured bool   `json:"token_configured"`
}

type apiTLSInterceptCAStatus struct {
	Configured        bool    `json:"configured"`
	Source            *string `json:"source"`
	FingerprintSHA256 *string `json:"fingerprint_sha256"`
}

type apiServiceAccount struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	CreatedAt   string  `json:"created_at"`
	CreatedBy   string  `json:"created_by"`
	Role        string  `json:"role"`
	Status      string  `json:"status"`
}

type apiServiceAccountTokenMeta struct {
	ID               string  `json:"id"`
	ServiceAccountID string  `json:"service_account_id"`
	Name             *string `json:"name"`
	CreatedAt        string  `json:"created_at"`
	CreatedBy        string  `json:"created_by"`
	ExpiresAt        *string `json:"expires_at"`
	RevokedAt        *string `json:"revoked_at"`
	LastUsedAt       *string `json:"last_used_at"`
	Kid              string  `json:"kid"`
	Role             string  `json:"role"`
	Status           string  `json:"status"`
}

type apiServiceAccountTokenRecord struct {
	Token     string                     `json:"token"`
	TokenMeta apiServiceAccountTokenMeta `json:"token_meta"`
}

type createIntegrationRequest struct {
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	APIServerURL        string `json:"api_server_url"`
	CACertPEM           string `json:"ca_cert_pem"`
	ServiceAccountToken string `json:"service_account_token"`
}

type updateIntegrationRequest struct {
	APIServerURL        string `json:"api_server_url"`
	CACertPEM           string `json:"ca_cert_pem"`
	ServiceAccountToken string `json:"service_account_token"`
}

type createSsoProviderRequest struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	Enabled              *bool    `json:"enabled,omitempty"`
	DisplayOrder         *int64   `json:"display_order,omitempty"`
	IssuerURL            *string  `json:"issuer_url,omitempty"`
	AuthorizationURL     *string  `json:"authorization_url,omitempty"`
	TokenURL             *string  `json:"token_url,omitempty"`
	UserinfoURL          *string  `json:"userinfo_url,omitempty"`
	ClientID             string   `json:"client_id"`
	ClientSecret         *string  `json:"client_secret,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	PKCERequired         *bool    `json:"pkce_required,omitempty"`
	SubjectClaim         *string  `json:"subject_claim,omitempty"`
	EmailClaim           *string  `json:"email_claim,omitempty"`
	GroupsClaim          *string  `json:"groups_claim,omitempty"`
	DefaultRole          *string  `json:"default_role,omitempty"`
	AdminSubjects        []string `json:"admin_subjects,omitempty"`
	AdminGroups          []string `json:"admin_groups,omitempty"`
	AdminEmailDomains    []string `json:"admin_email_domains,omitempty"`
	ReadonlySubjects     []string `json:"readonly_subjects,omitempty"`
	ReadonlyGroups       []string `json:"readonly_groups,omitempty"`
	ReadonlyEmailDomains []string `json:"readonly_email_domains,omitempty"`
	AllowedEmailDomains  []string `json:"allowed_email_domains,omitempty"`
	SessionTTLSecs       *int64   `json:"session_ttl_secs,omitempty"`
}

type updateSsoProviderRequest struct {
	Name                 *string  `json:"name,omitempty"`
	Enabled              *bool    `json:"enabled,omitempty"`
	DisplayOrder         *int64   `json:"display_order,omitempty"`
	IssuerURL            *string  `json:"issuer_url,omitempty"`
	AuthorizationURL     *string  `json:"authorization_url,omitempty"`
	TokenURL             *string  `json:"token_url,omitempty"`
	UserinfoURL          *string  `json:"userinfo_url,omitempty"`
	ClientID             *string  `json:"client_id,omitempty"`
	ClientSecret         *string  `json:"client_secret,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	PKCERequired         *bool    `json:"pkce_required,omitempty"`
	SubjectClaim         *string  `json:"subject_claim,omitempty"`
	EmailClaim           *string  `json:"email_claim,omitempty"`
	GroupsClaim          *string  `json:"groups_claim,omitempty"`
	DefaultRole          *string  `json:"default_role,omitempty"`
	AdminSubjects        []string `json:"admin_subjects,omitempty"`
	AdminGroups          []string `json:"admin_groups,omitempty"`
	AdminEmailDomains    []string `json:"admin_email_domains,omitempty"`
	ReadonlySubjects     []string `json:"readonly_subjects,omitempty"`
	ReadonlyGroups       []string `json:"readonly_groups,omitempty"`
	ReadonlyEmailDomains []string `json:"readonly_email_domains,omitempty"`
	AllowedEmailDomains  []string `json:"allowed_email_domains,omitempty"`
	SessionTTLSecs       *int64   `json:"session_ttl_secs,omitempty"`
}

type createServiceAccountRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Role        string  `json:"role"`
}

type updateServiceAccountRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Role        string  `json:"role"`
}

type createServiceAccountTokenRequest struct {
	Name    *string `json:"name,omitempty"`
	TTL     *string `json:"ttl,omitempty"`
	Eternal *bool   `json:"eternal,omitempty"`
	Role    *string `json:"role,omitempty"`
}

type putTLSInterceptCARequest struct {
	CACertPEM   string  `json:"ca_cert_pem"`
	CAKeyPEM    *string `json:"ca_key_pem,omitempty"`
	CAKeyDERB64 *string `json:"ca_key_der_b64,omitempty"`
}

func newAPIClient(cfg apiClientConfig) (*apiClient, error) {
	normalized := make([]string, 0, len(cfg.endpoints))
	for _, raw := range cfg.endpoints {
		endpoint, err := normalizeEndpoint(raw)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, endpoint)
	}

	httpClient, err := buildHTTPClient(cfg.caCertPEM, cfg.requestTimeout)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(cfg.headers))
	for key, value := range cfg.headers {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return nil, fmt.Errorf("header names must not be empty")
		}
		headers[trimmedKey] = value
	}

	return &apiClient{
		endpoints:    normalized,
		token:        cfg.token,
		httpClient:   httpClient,
		retryTimeout: cfg.retryTimeout,
		headers:      headers,
	}, nil
}

func (c *apiClient) GetIntegration(ctx context.Context, name string) (*apiIntegrationView, error) {
	var out apiIntegrationView
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/integrations/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) CreateIntegration(ctx context.Context, req createIntegrationRequest) (*apiIntegrationView, error) {
	var out apiIntegrationView
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/integrations", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) UpdateIntegration(ctx context.Context, name string, req updateIntegrationRequest) (*apiIntegrationView, error) {
	var out apiIntegrationView
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/integrations/"+url.PathEscape(name), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) DeleteIntegration(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/integrations/"+url.PathEscape(name), nil, nil)
}

func (c *apiClient) CreateSsoProvider(ctx context.Context, req createSsoProviderRequest) (*apiSsoProvider, error) {
	var out apiSsoProvider
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/settings/sso/providers", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) GetSsoProvider(ctx context.Context, id string) (*apiSsoProvider, error) {
	var out apiSsoProvider
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/settings/sso/providers/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) UpdateSsoProvider(ctx context.Context, id string, req updateSsoProviderRequest) (*apiSsoProvider, error) {
	var out apiSsoProvider
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/settings/sso/providers/"+url.PathEscape(id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) DeleteSsoProvider(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/settings/sso/providers/"+url.PathEscape(id), nil, nil)
}

func (c *apiClient) GetTLSInterceptCA(ctx context.Context) (*apiTLSInterceptCAStatus, error) {
	var out apiTLSInterceptCAStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/settings/tls-intercept-ca", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) GenerateTLSInterceptCA(ctx context.Context) (*apiTLSInterceptCAStatus, error) {
	var out apiTLSInterceptCAStatus
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/settings/tls-intercept-ca/generate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) PutTLSInterceptCA(ctx context.Context, req putTLSInterceptCARequest) (*apiTLSInterceptCAStatus, error) {
	var out apiTLSInterceptCAStatus
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/settings/tls-intercept-ca", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) DeleteTLSInterceptCA(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/settings/tls-intercept-ca", nil, nil)
}

func (c *apiClient) ListServiceAccounts(ctx context.Context) ([]apiServiceAccount, error) {
	var out []apiServiceAccount
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/service-accounts", nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return []apiServiceAccount{}, nil
	}
	return out, nil
}

func (c *apiClient) GetServiceAccount(ctx context.Context, id string) (*apiServiceAccount, error) {
	accounts, err := c.ListServiceAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		if accounts[i].ID == id {
			return &accounts[i], nil
		}
	}
	return nil, &apiError{
		StatusCode: http.StatusNotFound,
		Message:    "service account not found",
	}
}

func (c *apiClient) CreateServiceAccount(ctx context.Context, req createServiceAccountRequest) (*apiServiceAccount, error) {
	var out apiServiceAccount
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/service-accounts", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) UpdateServiceAccount(ctx context.Context, id string, req updateServiceAccountRequest) (*apiServiceAccount, error) {
	var out apiServiceAccount
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/service-accounts/"+url.PathEscape(id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) DeleteServiceAccount(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/service-accounts/"+url.PathEscape(id), nil, nil)
}

func (c *apiClient) ListServiceAccountTokens(ctx context.Context, serviceAccountID string) ([]apiServiceAccountTokenMeta, error) {
	var out []apiServiceAccountTokenMeta
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens", nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return []apiServiceAccountTokenMeta{}, nil
	}
	return out, nil
}

func (c *apiClient) CreateServiceAccountToken(ctx context.Context, serviceAccountID string, req createServiceAccountTokenRequest) (*apiServiceAccountTokenRecord, error) {
	var out apiServiceAccountTokenRecord
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) DeleteServiceAccountToken(ctx context.Context, serviceAccountID string, tokenID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens/"+url.PathEscape(tokenID), nil, nil)
}

func (c *apiClient) doJSON(ctx context.Context, method string, path string, requestBody any, out any) error {
	var bodyBytes []byte
	var err error
	if requestBody != nil {
		bodyBytes, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
	}

	resp, payload, err := c.do(ctx, method, path, bodyBytes)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, payload)
	}

	if out == nil || len(payload) == 0 {
		return nil
	}

	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *apiClient) do(ctx context.Context, method string, path string, body []byte) (*http.Response, []byte, error) {
	deadline := time.Now().Add(c.retryTimeout)
	if c.retryTimeout <= 0 {
		deadline = time.Now()
	}

	var lastErr error
	for {
		for _, endpoint := range c.endpoints {
			resp, payload, err := c.doSingle(ctx, endpoint, method, path, body)
			if err == nil {
				return resp, payload, nil
			}
			lastErr = err
		}

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if lastErr == nil {
		lastErr = errors.New("request failed without a response")
	}
	return nil, nil, lastErr
}

func (c *apiClient) doSingle(ctx context.Context, endpoint string, method string, path string, body []byte) (*http.Response, []byte, error) {
	reader := bytes.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request %s %s failed: %w", method, endpoint+path, err)
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("read response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(payload))

	return resp, payload, nil
}

func decodeAPIError(statusCode int, payload []byte) error {
	message := strings.TrimSpace(string(payload))
	if len(payload) > 0 {
		var body apiErrorBody
		if err := json.Unmarshal(payload, &body); err == nil && strings.TrimSpace(body.Error) != "" {
			message = body.Error
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &apiError{
		StatusCode: statusCode,
		Message:    message,
	}
}

func isNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func buildHTTPClient(caCertPEM []byte, requestTimeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caCertPEM); !ok {
			return nil, fmt.Errorf("failed to append CA certificate to trust store")
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
	}, nil
}

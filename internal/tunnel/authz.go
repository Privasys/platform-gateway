package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuthorizePath is the management-service endpoint that verifies a tunnel
// request's enclaveauth signature (method, path and body as signed by the
// enclave) and answers with the enclave id.
const AuthorizePath = "/api/v1/internal/tunnel/authorize"

// MgmtAuthorizer asks the management service, authenticating with the same
// bearer the route sync uses.
type MgmtAuthorizer struct {
	url    string
	token  string
	client *http.Client
}

// NewMgmtAuthorizer returns an authorizer for the given management base URL.
func NewMgmtAuthorizer(mgmtURL, token string) *MgmtAuthorizer {
	return &MgmtAuthorizer{
		url:   strings.TrimRight(mgmtURL, "/") + AuthorizePath,
		token: token,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

type authorizeResponse struct {
	EnclaveID string `json:"enclave_id"`
}

// Authorize implements Authorizer.
func (m *MgmtAuthorizer) Authorize(ctx context.Context, ar AuthRequest) (string, error) {
	body, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authorize: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out authorizeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("authorize: decode: %w", err)
	}
	if out.EnclaveID == "" {
		return "", fmt.Errorf("authorize: empty enclave_id")
	}
	return out.EnclaveID, nil
}

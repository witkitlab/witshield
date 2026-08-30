package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
)

type Client struct {
	base          *url.URL
	credentialsMu sync.RWMutex
	credentials   clientCredentials
	http          *http.Client
}

type clientCredentials struct {
	token, deviceID, identityPrivateKey string
}

func (c *Client) SetIdentity(deviceID, privateKey string) error {
	if strings.TrimSpace(deviceID) == "" {
		return errors.New("device identity is required")
	}
	if _, err := identity.DecodePrivateKey(privateKey); err != nil {
		return err
	}
	c.credentialsMu.Lock()
	c.credentials.deviceID, c.credentials.identityPrivateKey = deviceID, privateKey
	c.credentialsMu.Unlock()
	return nil
}

func (c *Client) credentialSnapshot() clientCredentials {
	c.credentialsMu.RLock()
	defer c.credentialsMu.RUnlock()
	return c.credentials
}

func (c *Client) publishEnrollmentCredentials(token, deviceID, privateKey string) {
	c.credentialsMu.Lock()
	c.credentials = clientCredentials{token: token, deviceID: deviceID, identityPrivateKey: privateKey}
	c.credentialsMu.Unlock()
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func NewClient(rawURL, token string) (*Client, error) {
	return newClient(rawURL, token, false)
}

// NewObserverClient keeps private-network HTTP available only for the
// explicitly read-only Docker observer. Native Agents can reach the privileged
// Helper, so they must use HTTPS or the installation-owned Unix socket.
func NewObserverClient(rawURL, token string) (*Client, error) {
	return newClient(rawURL, token, true)
}

func newClient(rawURL, token string, observerOnly bool) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid controller URL")
	}
	if u.Scheme == "unix" {
		if u.Host != "" || !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path {
			return nil, errors.New("unix controller URL must contain one absolute socket path")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		socketPath := u.Path
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		base, _ := url.Parse("http://witshield-controller")
		return &Client{base: base, credentials: clientCredentials{token: token}, http: controllerHTTPClient(transport)}, nil
	}
	if u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("controller URL must use https, unix, or observer-only http")
	}
	if u.Scheme == "http" {
		if !observerOnly {
			return nil, errors.New("native controller connections must use HTTPS or the installation-owned Unix socket")
		}
		ip := net.ParseIP(u.Hostname())
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			return nil, errors.New("observer-only HTTP controller URL is only allowed on local/private networks")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if u.Scheme == "http" {
		// Never send a plaintext device credential through an environment proxy.
		// Resolve service names at dial time, validate every returned address, and
		// dial the validated IP directly so DNS rebinding cannot change the target
		// between validation and connection. This also permits Compose/Kubernetes
		// service names such as "controller" on private networks.
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		transport.Proxy = nil
		transport.DialContext = privateControllerDialContext(u.Hostname(), net.DefaultResolver, dialer.DialContext)
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &Client{base: u, credentials: clientCredentials{token: token}, http: controllerHTTPClient(transport)}, nil
}

func controllerHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("controller redirects are disabled") }}
}

func privateControllerDialContext(controllerHost string, resolver ipResolver, dial dialContextFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid controller dial address: %w", err)
		}
		if !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(controllerHost, ".")) {
			return nil, errors.New("controller dial target changed unexpectedly")
		}
		var addresses []net.IPAddr
		if literal := net.ParseIP(host); literal != nil {
			addresses = []net.IPAddr{{IP: literal}}
		} else {
			addresses, err = resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve controller host: %w", err)
			}
		}
		if len(addresses) == 0 {
			return nil, errors.New("controller host resolved to no addresses")
		}
		for _, candidate := range addresses {
			if candidate.IP == nil || (!candidate.IP.IsLoopback() && !candidate.IP.IsPrivate()) {
				return nil, errors.New("plain HTTP controller resolved outside local/private networks")
			}
		}
		return dial(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}
}

type APIError struct {
	Status        int
	Code, Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("controller HTTP %d: %s", e.Status, e.Message) }
func (c *Client) do(ctx context.Context, method, route string, input, output any) error {
	return c.doWithCredentials(ctx, method, route, input, output, c.credentialSnapshot())
}

func (c *Client) doUnauthenticated(ctx context.Context, method, route string, input, output any) error {
	return c.doWithCredentials(ctx, method, route, input, output, clientCredentials{})
}

func (c *Client) doWithCredentials(ctx context.Context, method, route string, input, output any, credentials clientCredentials) error {
	var payload []byte
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		payload = b
	}
	return c.doRawWithCredentials(ctx, method, route, payload, input != nil, output, credentials)
}

func (c *Client) doRaw(ctx context.Context, method, route string, payload []byte, hasBody bool, output any) error {
	return c.doRawWithCredentials(ctx, method, route, payload, hasBody, output, c.credentialSnapshot())
}

func (c *Client) doRawWithCredentials(ctx context.Context, method, route string, payload []byte, hasBody bool, output any, credentials clientCredentials) error {
	if len(payload) > maxQueuedPayloadBytes {
		return errors.New("request body is too large")
	}
	var body io.Reader
	if hasBody {
		body = bytes.NewReader(payload)
	}
	rel, err := url.Parse(route)
	if err != nil || rel.IsAbs() {
		return errors.New("invalid controller route")
	}
	u := *c.base
	u.Path = path.Join(strings.TrimSuffix(u.Path, "/"), rel.Path)
	u.RawQuery = rel.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if credentials.token != "" {
		req.Header.Set("Authorization", "Bearer "+credentials.token)
		if credentials.identityPrivateKey == "" || credentials.deviceID == "" {
			return errors.New("post-enrollment request identity is not configured")
		}
		nonceBytes := make([]byte, 18)
		if _, err = rand.Read(nonceBytes); err != nil {
			return fmt.Errorf("generate request nonce: %w", err)
		}
		timestamp := strconv.FormatInt(time.Now().UTC().UnixMilli(), 10)
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		requestURI := u.EscapedPath()
		if u.RawQuery != "" {
			requestURI += "?" + u.RawQuery
		}
		signature, signErr := identity.SignAgentRequest(credentials.identityPrivateKey, identity.AgentRequestProof{DeviceID: credentials.deviceID, Method: method, RequestURI: requestURI, Timestamp: timestamp, Nonce: nonce, Body: payload})
		if signErr != nil {
			return fmt.Errorf("sign controller request: %w", signErr)
		}
		req.Header.Set("X-WitShield-Timestamp", timestamp)
		req.Header.Set("X-WitShield-Nonce", nonce)
		req.Header.Set("X-WitShield-Signature", signature)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("controller request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxQueuedPayloadBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxQueuedPayloadBytes {
		return errors.New("controller response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &envelope)
		if envelope.Error.Message == "" {
			envelope.Error.Message = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if output != nil && len(data) > 0 {
		if err = json.Unmarshal(data, output); err != nil {
			return errors.New("invalid controller response")
		}
	}
	return nil
}

type EnrollRequest struct {
	EnrollmentToken   string `json:"enrollmentToken"`
	Name              string `json:"name"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	AgentVersion      string `json:"agentVersion"`
	IdentityPublicKey string `json:"identityPublicKey"`
	// IdentityPrivateKey never leaves the Agent. Client.Enroll uses it only to
	// sign the Controller's one-time challenge.
	IdentityPrivateKey string `json:"-"`
	// ScanInterval is an enrollment-time compatibility hint for legacy
	// installers. The Controller persists the authoritative schedule; the Agent
	// does not run a local recurring timer after enrollment.
	ScanInterval string `json:"scanInterval,omitempty"`
	ObserverOnly bool   `json:"observerOnly"`
}

func (c *Client) Enroll(ctx context.Context, in EnrollRequest) (domain.Device, string, error) {
	if err := identity.ValidateKeyPair(in.IdentityPublicKey, in.IdentityPrivateKey); err != nil {
		return domain.Device{}, "", err
	}
	var challenge struct {
		ID        string `json:"id"`
		Challenge string `json:"challenge"`
	}
	if err := c.doUnauthenticated(ctx, http.MethodPost, "/agent/v1/enroll/challenge", map[string]string{
		"enrollmentToken":   in.EnrollmentToken,
		"identityPublicKey": in.IdentityPublicKey,
	}, &challenge); err != nil {
		return domain.Device{}, "", err
	}
	proof := identity.EnrollmentProof{
		ChallengeID: challenge.ID, Challenge: challenge.Challenge, EnrollmentToken: in.EnrollmentToken,
		Name: in.Name, Hostname: in.Hostname, OS: in.OS, Arch: in.Arch, AgentVersion: in.AgentVersion,
		IdentityPublicKey: in.IdentityPublicKey, ScanInterval: in.ScanInterval, ObserverOnly: in.ObserverOnly,
	}
	signature, err := identity.SignEnrollmentProof(in.IdentityPrivateKey, proof)
	if err != nil {
		return domain.Device{}, "", err
	}
	type enrollmentPayload struct {
		EnrollRequest
		ChallengeID string `json:"challengeId"`
		Challenge   string `json:"challenge"`
		Signature   string `json:"identitySignature"`
	}
	var out struct {
		Device      domain.Device `json:"device"`
		DeviceToken string        `json:"deviceToken"`
	}
	err = c.doUnauthenticated(ctx, http.MethodPost, "/agent/v1/enroll", enrollmentPayload{EnrollRequest: in, ChallengeID: challenge.ID, Challenge: challenge.Challenge, Signature: signature}, &out)
	if err == nil && (out.Device.ID == "" || len(out.DeviceToken) < 20) {
		err = errors.New("invalid enrollment response")
	}
	if err == nil {
		c.publishEnrollmentCredentials(out.DeviceToken, out.Device.ID, in.IdentityPrivateKey)
	}
	return out.Device, out.DeviceToken, err
}
func (c *Client) Heartbeat(ctx context.Context, meta map[string]string, sensorBatches ...[]domain.SensorHealth) error {
	payload := map[string]any{}
	for key, value := range meta {
		payload[key] = value
	}
	if len(sensorBatches) > 0 && len(sensorBatches[0]) > 0 {
		payload["sensors"] = sensorBatches[0]
	}
	return c.do(ctx, http.MethodPost, "/agent/v1/heartbeat", payload, &struct{}{})
}

func (c *Client) StartCommand(ctx context.Context, commandID string) (bool, error) {
	var out struct {
		Authorized bool `json:"authorized"`
	}
	err := c.do(ctx, http.MethodPost, "/agent/v1/commands/"+url.PathEscape(commandID)+"/start", &struct{}{}, &out)
	return out.Authorized, err
}
func (c *Client) Sync(ctx context.Context, wait time.Duration) ([]domain.DeviceCommand, error) {
	var out struct {
		Commands []domain.DeviceCommand `json:"commands"`
	}
	route := "/agent/v1/sync?wait=" + url.QueryEscape(wait.String())
	err := c.do(ctx, http.MethodGet, route, nil, &out)
	return out.Commands, err
}
func (c *Client) PostReport(ctx context.Context, r domain.Report) error {
	return c.do(ctx, http.MethodPost, "/agent/v1/reports", r, &struct{}{})
}
func (c *Client) PostEvents(ctx context.Context, events []domain.SecurityEvent, identitySignature string) error {
	return c.do(ctx, http.MethodPost, "/agent/v1/events", map[string]any{"events": events, "identitySignature": identitySignature}, &struct{}{})
}
func (c *Client) PostCommandResult(ctx context.Context, id string, result any) error {
	return c.do(ctx, http.MethodPost, "/agent/v1/commands/"+url.PathEscape(id)+"/result", result, nil)
}

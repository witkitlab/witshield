package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const maxResponseBody = 2 << 20

type Config struct {
	Protocol      domain.AIProtocol
	BaseURL       string
	Model         string
	APIKey        string
	CustomHeaders domain.Headers
}
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Client struct {
	cfg      Config
	http     *http.Client
	endpoint *url.URL
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Model) == "" || len(cfg.Model) > 200 {
		return nil, errors.New("model is required and must not exceed 200 characters")
	}
	switch cfg.Protocol {
	case domain.AIProtocolOpenAIResponses, domain.AIProtocolOpenAIChat, domain.AIProtocolAnthropic:
	default:
		return nil, errors.New("unsupported AI protocol")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil {
		return nil, errors.New("invalid AI base URL")
	}
	if err = validateURL(u); err != nil {
		return nil, err
	}
	for k, v := range cfg.CustomHeaders {
		if err = validateHeader(k, v); err != nil {
			return nil, err
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Provider credentials must never be forwarded to an ambient HTTP proxy.
	transport.Proxy = nil
	transport.DialContext = safeDialer((&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext)
	return &Client{cfg: cfg, endpoint: u, http: &http.Client{Timeout: 35 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("AI endpoint redirects are disabled") }}}, nil
}

func validateURL(u *url.URL) error {
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("AI base URL must use http or https")
	}
	if u.Hostname() == "" {
		return errors.New("AI base URL host is required")
	}
	if u.User != nil {
		return errors.New("AI base URL must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("AI base URL must not contain a query or fragment")
	}
	if port := u.Port(); port != "" {
		n, portErr := strconv.Atoi(port)
		if portErr != nil || n < 1 || n > 65535 {
			return errors.New("AI base URL port must be between 1 and 65535")
		}
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || (!ip.IsLoopback() && !ip.IsPrivate())) {
			return errors.New("plain HTTP AI endpoints are only allowed on local or private networks")
		}
	}
	return nil
}

// SameCredentialOrigin reports whether two validated AI endpoints share the
// same credential trust boundary. Paths are intentionally excluded: a provider
// may expose multiple protocol roots on one origin, while a scheme, host, or
// effective-port change must never inherit a stored secret implicitly.
func SameCredentialOrigin(a, b string) (bool, error) {
	left, err := credentialOrigin(a)
	if err != nil {
		return false, err
	}
	right, err := credentialOrigin(b)
	if err != nil {
		return false, err
	}
	return left == right, nil
}

func credentialOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid AI base URL")
	}
	if err = validateURL(u); err != nil {
		return "", err
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}
func forbiddenIP(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, raw := range []string{"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return true
		}
	}
	return false
}
func safeDialer(next func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return safeDialerWithResolver(net.DefaultResolver.LookupIP, next)
}

func safeDialerWithResolver(resolve func(context.Context, string, string) ([]net.IP, error), next func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid upstream address")
		}
		ips, err := resolve(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("AI host resolution failed")
		}
		if len(ips) == 0 {
			return nil, errors.New("AI host has no addresses")
		}
		for _, ip := range ips {
			if forbiddenIP(ip) {
				return nil, errors.New("AI endpoint resolves to a prohibited network address")
			}
		}
		return next(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}
func validateHeader(k, v string) error {
	if len(k) == 0 || len(k) > 100 || len(v) > 4096 {
		return errors.New("invalid custom header")
	}
	lower := strings.ToLower(k)
	switch lower {
	case "host", "content-length", "authorization", "x-api-key", "anthropic-version", "connection", "transfer-encoding":
		return fmt.Errorf("custom header %q is reserved", k)
	}
	if strings.ContainsAny(k+v, "\r\n") {
		return errors.New("custom headers must not contain newlines")
	}
	if !headerNamePattern.MatchString(k) {
		return errors.New("custom header name contains invalid characters")
	}
	return nil
}

var headerNamePattern = regexp.MustCompile(`^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$`)

func (c *Client) Chat(ctx context.Context, messages []Message) (string, error) {
	if len(messages) == 0 || len(messages) > 40 {
		return "", errors.New("messages must contain between 1 and 40 entries")
	}
	total := 0
	for _, m := range messages {
		if m.Role != "system" && m.Role != "user" && m.Role != "assistant" {
			return "", errors.New("invalid message role")
		}
		total += len(m.Content)
	}
	if total > 128*1024 {
		return "", errors.New("message content is too large")
	}
	var endpoint string
	var body any
	switch c.cfg.Protocol {
	case domain.AIProtocolOpenAIResponses:
		endpoint = "responses"
		var input []map[string]string
		for _, m := range messages {
			input = append(input, map[string]string{"role": m.Role, "content": m.Content})
		}
		body = map[string]any{"model": c.cfg.Model, "input": input, "max_output_tokens": 2048, "store": false}
	case domain.AIProtocolOpenAIChat:
		endpoint = "chat/completions"
		body = map[string]any{"model": c.cfg.Model, "messages": messages, "max_tokens": 2048}
	case domain.AIProtocolAnthropic:
		endpoint = "messages"
		var system string
		var nonSystem []Message
		for _, m := range messages {
			if m.Role == "system" {
				if system != "" {
					system += "\n"
				}
				system += m.Content
			} else {
				nonSystem = append(nonSystem, m)
			}
		}
		body = map[string]any{"model": c.cfg.Model, "messages": nonSystem, "system": system, "max_tokens": 2048}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	u := *c.endpoint
	u.Path = path.Join(strings.TrimSuffix(u.Path, "/"), endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.cfg.APIKey != "" {
		if c.cfg.Protocol == domain.AIProtocolAnthropic {
			req.Header.Set("x-api-key", c.cfg.APIKey)
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
		}
	}
	for k, v := range c.cfg.CustomHeaders {
		req.Header.Set(k, v)
	}
	// New fixes the endpoint authority, disables ambient proxies and redirects,
	// and installs safeDialer, which validates every DNS answer before dialing a
	// pinned numeric address. Private/loopback providers remain an intentional
	// administrator-configured capability.

	resp, err := c.http.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return "", fmt.Errorf("AI request failed: %s", c.redact(err.Error()))
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", errors.New("failed to read AI response")
	}
	if len(data) > maxResponseBody {
		return "", errors.New("AI response exceeded size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("AI upstream returned HTTP %d: %s", resp.StatusCode, c.redact(truncate(string(data), 512)))
	}
	text, err := parseResponse(c.cfg.Protocol, data)
	if err != nil {
		return "", fmt.Errorf("invalid AI response: %w", err)
	}
	return text, nil
}
func parseResponse(protocol domain.AIProtocol, data []byte) (string, error) {
	switch protocol {
	case domain.AIProtocolOpenAIResponses:
		var x struct {
			OutputText string `json:"output_text"`
			Output     []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if err := json.Unmarshal(data, &x); err != nil {
			return "", err
		}
		if x.OutputText != "" {
			return x.OutputText, nil
		}
		for _, o := range x.Output {
			for _, c := range o.Content {
				if c.Text != "" {
					return c.Text, nil
				}
			}
		}
	case domain.AIProtocolOpenAIChat:
		var x struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(data, &x); err != nil {
			return "", err
		}
		if len(x.Choices) > 0 && x.Choices[0].Message.Content != "" {
			return x.Choices[0].Message.Content, nil
		}
	case domain.AIProtocolAnthropic:
		var x struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(data, &x); err != nil {
			return "", err
		}
		for _, c := range x.Content {
			if c.Type == "text" && c.Text != "" {
				return c.Text, nil
			}
		}
	}
	return "", errors.New("response contained no text")
}
func (c *Client) redact(s string) string {
	values := []string{c.cfg.APIKey}
	for _, v := range c.cfg.CustomHeaders {
		values = append(values, v)
	}
	for _, v := range values {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

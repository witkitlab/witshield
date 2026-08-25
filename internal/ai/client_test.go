package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestProtocols(t *testing.T) {
	tests := []struct {
		p          domain.AIProtocol
		path, body string
	}{{domain.AIProtocolOpenAIResponses, "/v1/responses", `{"output":[{"content":[{"text":"response ok"}]}]}`}, {domain.AIProtocolOpenAIChat, "/v1/chat/completions", `{"choices":[{"message":{"content":"chat ok"}}]}`}, {domain.AIProtocolAnthropic, "/v1/messages", `{"content":[{"type":"text","text":"anthropic ok"}]}`}}
	for _, tt := range tests {
		t.Run(string(tt.p), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("path=%s", r.URL.Path)
				}
				if tt.p == domain.AIProtocolAnthropic {
					if r.Header.Get("x-api-key") != "secret-key" {
						t.Error("missing key")
					}
				} else if r.Header.Get("Authorization") != "Bearer secret-key" {
					t.Error("missing auth")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("decode body: %v", err)
				}
				if payload["model"] != "test" {
					t.Errorf("model=%v", payload["model"])
				}
				if tt.p == domain.AIProtocolOpenAIResponses && payload["store"] != false {
					t.Errorf("Responses store must be false: %v", payload)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()
			c, err := New(Config{Protocol: tt.p, BaseURL: srv.URL + "/v1", Model: "test", APIKey: "secret-key"})
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}})
			if err != nil || !strings.Contains(got, "ok") {
				t.Fatalf("%q %v", got, err)
			}
		})
	}
}
func TestKeyRedactedFromUpstreamError(t *testing.T) {
	secret := "super-secret-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); fmt.Fprint(w, "oops "+secret) }))
	defer srv.Close()
	c, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: srv.URL, Model: "m", APIKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked: %v", err)
	}
}
func TestURLAndHeadersValidation(t *testing.T) {
	if _, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: "file:///tmp/x", Model: "m"}); err == nil {
		t.Fatal("file URL accepted")
	}
	for _, rawURL := range []string{
		"https://example.com?",
		"https://example.com:0/v1",
		"https://example.com:65536/v1",
		"http://8.8.8.8/v1",
	} {
		if _, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: rawURL, Model: "m"}); err == nil {
			t.Fatalf("unsafe or malformed URL accepted: %s", rawURL)
		}
	}
	if _, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: "https://example.com", Model: "m", CustomHeaders: domain.Headers{"Authorization": "bad"}}); err == nil {
		t.Fatal("reserved header accepted")
	}
	if _, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: "https://example.com", Model: "m", CustomHeaders: domain.Headers{"Bad Header": "value"}}); err == nil {
		t.Fatal("invalid header name accepted")
	}
	client, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: "https://example.com", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("ambient proxy is enabled for secret-bearing AI requests")
	}
}

func TestCredentialOriginBindsSchemeHostAndEffectivePort(t *testing.T) {
	tests := []struct {
		name       string
		a, b       string
		equivalent bool
	}{
		{"path may change", "https://AI.example/v1", "https://ai.example/chat", true},
		{"default HTTPS port", "https://ai.example/v1", "https://ai.example:443/v2", true},
		{"default HTTP port", "http://127.0.0.1/v1", "http://127.0.0.1:80/v2", true},
		{"IPv6 spelling", "http://[0:0:0:0:0:0:0:1]/v1", "http://[::1]:80/v2", true},
		{"scheme changes", "http://127.0.0.1/v1", "https://127.0.0.1/v1", false},
		{"host changes", "https://ai.example/v1", "https://other.example/v1", false},
		{"port changes", "https://ai.example/v1", "https://ai.example:8443/v1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SameCredentialOrigin(tt.a, tt.b)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.equivalent {
				t.Fatalf("equivalent=%v want=%v", got, tt.equivalent)
			}
		})
	}
}

func TestSafeDialerRejectsEveryProhibitedAnswerAndPinsApprovedIP(t *testing.T) {
	tests := []struct {
		name      string
		answers   []net.IP
		wantError bool
		wantDial  string
	}{
		{"metadata", []net.IP{net.ParseIP("169.254.169.254")}, true, ""},
		{"mixed answer", []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("169.254.170.2")}, true, ""},
		{"private provider", []net.IP{net.ParseIP("10.20.30.40")}, false, "10.20.30.40:443"},
		{"public provider", []net.IP{net.ParseIP("203.0.113.10")}, false, "203.0.113.10:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dialed string
			dial := safeDialerWithResolver(func(context.Context, string, string) ([]net.IP, error) {
				return tt.answers, nil
			}, func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = address
				return nil, io.EOF
			})
			_, err := dial(context.Background(), "tcp", "provider.example:443")
			if tt.wantError {
				if err == nil || dialed != "" {
					t.Fatalf("err=%v dialed=%q", err, dialed)
				}
				return
			}
			if !errors.Is(err, io.EOF) || dialed != tt.wantDial {
				t.Fatalf("err=%v dialed=%q want=%q", err, dialed, tt.wantDial)
			}
		})
	}
}

func TestRedirectDoesNotForwardProviderCredential(t *testing.T) {
	secret := "provider-secret"
	received := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"unexpected"}}]}`)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	client, err := New(Config{Protocol: domain.AIProtocolOpenAIChat, BaseURL: redirector.URL, Model: "m", APIKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}); err == nil {
		t.Fatal("redirect was followed")
	}
	select {
	case got := <-received:
		t.Fatalf("redirect target received credential %q", got)
	default:
	}
}

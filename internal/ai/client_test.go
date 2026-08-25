package ai

import (
	"context"
	"encoding/json"
	"fmt"
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

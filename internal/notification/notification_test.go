package notification

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func testWebhookSecret() string {
	return strings.Repeat("test-value-", 4)
}

func TestSignedWebhook(t *testing.T) {
	secret := testWebhookSecret()
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		body, _ := io.ReadAll(r.Body)
		stamp := r.Header.Get("X-WitShield-Timestamp")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(stamp + "."))
		mac.Write(body)
		if r.Header.Get("X-WitShield-Signature") != "v1="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("invalid signature")
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	sender, err := New(Config{Settings: domain.NotificationSettings{WebhookEnabled: true, WebhookURL: srv.URL}, WebhookSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.Send(context.Background(), domain.NotificationEvent{Type: "test", Title: "Hello"}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("called=%d", called)
	}
}

func TestSMTPDeliveryToPrivateSink(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString("220 localhost ESMTP\r\n")
		_ = writer.Flush()
		var message strings.Builder
		inData := false
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					received <- message.String()
					_, _ = writer.WriteString("250 queued\r\n")
					_ = writer.Flush()
					continue
				}
				message.WriteString(line)
				continue
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"):
				_, _ = writer.WriteString("250-localhost\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(command, "HELO"), strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"):
				_, _ = writer.WriteString("250 ok\r\n")
			case command == "DATA":
				inData = true
				_, _ = writer.WriteString("354 end with dot\r\n")
			case command == "QUIT":
				_, _ = writer.WriteString("221 bye\r\n")
				_ = writer.Flush()
				return
			default:
				_, _ = writer.WriteString("250 ok\r\n")
			}
			_ = writer.Flush()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	sender, err := New(Config{Settings: domain.NotificationSettings{SMTPEnabled: true, SMTPHost: "127.0.0.1", SMTPPort: port, SMTPFrom: "witshield@example.test", SMTPTo: []string{"admin@example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.Send(context.Background(), domain.NotificationEvent{ID: "ntf_stable", Type: "critical", Title: "Critical finding", Message: "Review the host"}); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-received:
		if !strings.Contains(message, "Subject: [WitShield] Critical finding") || !strings.Contains(message, "Review the host") || !strings.Contains(message, "X-WitShield-Event-ID: ntf_stable") || !strings.Contains(message, "Message-ID: <") {
			t.Fatalf("unexpected message: %s", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP sink did not receive a message")
	}
}
func TestWebhookRetry(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if called < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	sender, err := New(Config{Settings: domain.NotificationSettings{WebhookEnabled: true, WebhookURL: srv.URL}, WebhookSecret: testWebhookSecret()})
	if err != nil {
		t.Fatal(err)
	}
	sender.sleep = func(context.Context, time.Duration) error { return nil }
	if err = sender.Send(context.Background(), domain.NotificationEvent{}); err != nil {
		t.Fatal(err)
	}
	if called != 3 {
		t.Fatalf("called=%d", called)
	}
}

func TestWebhookPermanentResponseIsNotRetried(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	sender, err := New(Config{Settings: domain.NotificationSettings{WebhookEnabled: true, WebhookURL: srv.URL}, WebhookSecret: testWebhookSecret()})
	if err != nil {
		t.Fatal(err)
	}
	sender.sleep = func(context.Context, time.Duration) error { return nil }
	err = sender.Send(context.Background(), domain.NotificationEvent{ID: "ntf_permanent"})
	if err == nil || called != 1 || IsRetryable(err) {
		t.Fatalf("permanent response err=%v called=%d retryable=%v", err, called, IsRetryable(err))
	}
}
func TestSecretNotInWebhookError(t *testing.T) {
	secret := testWebhookSecret()
	pathSecret := "slack-signing-path-secret"
	querySecret := "query-token-secret"
	sender, err := New(Config{Settings: domain.NotificationSettings{WebhookEnabled: true, WebhookURL: "http://127.0.0.1:1/hooks/" + pathSecret + "?token=" + querySecret}, WebhookSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	sender.sleep = func(context.Context, time.Duration) error { return nil }
	err = sender.Send(context.Background(), domain.NotificationEvent{})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), pathSecret) || strings.Contains(err.Error(), querySecret) || strings.Contains(err.Error(), "/hooks/") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestSMTPPeerErrorCannotEchoCredentials(t *testing.T) {
	const password = "smtp-password-must-never-leak"
	err := publicDeliveryError(domain.NotificationSMTP, "authentication", errors.New("535 password="+password), false)
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "535") {
		t.Fatalf("SMTP peer text leaked: %v", err)
	}
}

func TestWebhookAndSMTPDeliverIndependently(t *testing.T) {
	webhookStarted := make(chan struct{})
	releaseWebhook := make(chan struct{})
	var once sync.Once
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(webhookStarted) })
		<-releaseWebhook
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	emailReceived := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString("220 localhost ESMTP\r\n")
		_ = writer.Flush()
		inData := false
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					emailReceived <- struct{}{}
					_, _ = writer.WriteString("250 queued\r\n")
					_ = writer.Flush()
				}
				continue
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"):
				_, _ = writer.WriteString("250-localhost\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(command, "HELO"), strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"):
				_, _ = writer.WriteString("250 ok\r\n")
			case command == "DATA":
				inData = true
				_, _ = writer.WriteString("354 end with dot\r\n")
			case command == "QUIT":
				_, _ = writer.WriteString("221 bye\r\n")
				_ = writer.Flush()
				return
			default:
				_, _ = writer.WriteString("250 ok\r\n")
			}
			_ = writer.Flush()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	sender, err := New(Config{Settings: domain.NotificationSettings{
		WebhookEnabled: true, WebhookURL: webhook.URL,
		SMTPEnabled: true, SMTPHost: "127.0.0.1", SMTPPort: port,
		SMTPFrom: "witshield@example.test", SMTPTo: []string{"admin@example.test"},
	}, WebhookSecret: testWebhookSecret()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- sender.Send(context.Background(), domain.NotificationEvent{ID: "ntf_parallel", Title: "parallel"})
	}()
	select {
	case <-webhookStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook did not start")
	}
	select {
	case <-emailReceived:
		// SMTP completed while the webhook was deliberately blocked.
	case <-time.After(2 * time.Second):
		t.Fatal("blocked webhook delayed independent SMTP delivery")
	}
	close(releaseWebhook)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parallel delivery did not finish")
	}
}

func TestSendRejectsDisabledChannels(t *testing.T) {
	sender, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.Send(context.Background(), domain.NotificationEvent{}); !errors.Is(err, ErrNoChannels) {
		t.Fatalf("disabled delivery returned %v", err)
	}
}

func TestProhibitedEndpointIPBlocksCloudMetadata(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "ff02::1"} {
		if !prohibitedEndpointIP(net.ParseIP(raw)) {
			t.Errorf("expected %s to be prohibited", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "8.8.8.8", "2001:4860:4860::8888"} {
		if prohibitedEndpointIP(net.ParseIP(raw)) {
			t.Errorf("expected %s to remain permitted", raw)
		}
	}
}

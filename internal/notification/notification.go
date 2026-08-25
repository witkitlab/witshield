package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

type Config struct {
	Settings                    domain.NotificationSettings
	WebhookSecret, SMTPPassword string
}
type Sender struct {
	cfg   Config
	http  *http.Client
	sleep func(context.Context, time.Duration) error
}

var (
	ErrNoChannels      = errors.New("no notification channels are enabled")
	ErrChannelDisabled = errors.New("notification channel is disabled")
)

// DeliveryError is deliberately small and safe to expose through an API or
// structured log. It never wraps the original network error or SMTP peer text.
type DeliveryError struct {
	Channel   domain.NotificationChannel
	Stage     string
	Status    int
	Retryable bool
}

func (e *DeliveryError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("%s %s failed (status %d)", e.Channel, e.Stage, e.Status)
	}
	return fmt.Sprintf("%s %s failed", e.Channel, e.Stage)
}

func IsRetryable(err error) bool {
	var deliveryError *DeliveryError
	return errors.As(err, &deliveryError) && deliveryError.Retryable
}

func New(cfg Config) (*Sender, error) {
	if cfg.Settings.WebhookEnabled {
		u, err := url.Parse(cfg.Settings.WebhookURL)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("invalid webhook URL")
		}
		if cfg.WebhookSecret == "" || len(cfg.WebhookSecret) < 16 {
			return nil, errors.New("webhook signing secret must contain at least 16 characters")
		}
		if u.Scheme == "http" && !localOrPrivate(u.Hostname()) {
			return nil, errors.New("plain HTTP webhook is only allowed on local/private networks")
		}
	}
	if cfg.Settings.SMTPEnabled {
		if err := validateSMTP(cfg); err != nil {
			return nil, err
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeDial
	return &Sender{cfg: cfg, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("webhook redirects are disabled") }}, sleep: func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}}, nil
}
func localOrPrivate(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}
func safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("notification host resolution failed")
	}
	if len(ips) == 0 {
		return nil, errors.New("notification host has no addresses")
	}
	for _, ip := range ips {
		if prohibitedEndpointIP(ip) {
			return nil, errors.New("notification endpoint resolves to a prohibited address")
		}
	}
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func prohibitedEndpointIP(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, raw := range []string{"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return true
		}
	}
	return false
}
func (s *Sender) Send(ctx context.Context, event domain.NotificationEvent) error {
	if !s.Enabled() {
		return ErrNoChannels
	}
	type channelDelivery struct {
		channel domain.NotificationChannel
		enabled bool
	}
	channels := []channelDelivery{
		{channel: domain.NotificationWebhook, enabled: s.cfg.Settings.WebhookEnabled},
		{channel: domain.NotificationSMTP, enabled: s.cfg.Settings.SMTPEnabled},
	}
	errs := make([]error, len(channels))
	var wg sync.WaitGroup
	for index, delivery := range channels {
		if !delivery.enabled {
			continue
		}
		wg.Add(1)
		go func(index int, channel domain.NotificationChannel) {
			defer wg.Done()
			errs[index] = s.retry(ctx, func(attemptCtx context.Context) error {
				return s.SendChannel(attemptCtx, channel, event)
			})
		}(index, delivery.channel)
	}
	wg.Wait()
	var joined []error
	for index, delivery := range channels {
		if errs[index] != nil {
			joined = append(joined, fmt.Errorf("%s: %w", delivery.channel, errs[index]))
		}
	}
	return errors.Join(joined...)
}

// SendChannel performs exactly one channel attempt. Durable callers use this
// method so every failed attempt is recorded before a bounded retry; Send adds
// short in-request retries for the administrator's synchronous test action.
func (s *Sender) SendChannel(ctx context.Context, channel domain.NotificationChannel, event domain.NotificationEvent) error {
	switch channel {
	case domain.NotificationWebhook:
		if s.cfg.Settings.WebhookEnabled {
			body, err := json.Marshal(event)
			if err != nil {
				return errors.New("webhook event encoding failed")
			}
			return s.webhook(ctx, body)
		}
	case domain.NotificationSMTP:
		if s.cfg.Settings.SMTPEnabled {
			return s.email(ctx, event)
		}
	default:
		return errors.New("invalid notification channel")
	}
	return ErrChannelDisabled
}

func (s *Sender) Enabled() bool {
	return s.cfg.Settings.WebhookEnabled || s.cfg.Settings.SMTPEnabled
}
func (s *Sender) retry(ctx context.Context, fn func(context.Context) error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = fn(ctx); err == nil {
			return nil
		}
		if !IsRetryable(err) {
			return err
		}
		if attempt < 2 {
			if sleepErr := s.sleep(ctx, time.Duration(1<<attempt)*time.Second); sleepErr != nil {
				return sleepErr
			}
		}
	}
	return err
}
func (s *Sender) webhook(ctx context.Context, body []byte) error {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(s.cfg.WebhookSecret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Settings.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return publicDeliveryError(domain.NotificationWebhook, "request creation", err, false)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "WitShield/0.1")
	req.Header.Set("X-WitShield-Timestamp", timestamp)
	req.Header.Set("X-WitShield-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-WitShield-Event-ID", sanitizeHeader(eventIDFromBody(body)))
	resp, err := s.http.Do(req)
	if err != nil {
		return publicDeliveryError(domain.NotificationWebhook, "transport", err, true)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooEarly || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return &DeliveryError{Channel: domain.NotificationWebhook, Stage: "request", Status: resp.StatusCode, Retryable: retryable}
	}
	return nil
}
func validateSMTP(cfg Config) error {
	if cfg.Settings.SMTPHost == "" || cfg.Settings.SMTPPort < 1 || cfg.Settings.SMTPPort > 65535 {
		return errors.New("invalid SMTP host or port")
	}
	if len(cfg.Settings.SMTPHost) > 253 || strings.ContainsAny(cfg.Settings.SMTPHost, "\r\n\x00 /@") {
		return errors.New("invalid SMTP host")
	}
	if cfg.Settings.SMTPFrom == "" || len(cfg.Settings.SMTPTo) == 0 {
		return errors.New("SMTP from and recipients are required")
	}
	for _, raw := range append([]string{cfg.Settings.SMTPFrom}, cfg.Settings.SMTPTo...) {
		parsed, err := mail.ParseAddress(raw)
		if err != nil || parsed.Address != raw {
			return fmt.Errorf("invalid email address %q", raw)
		}
	}
	if strings.ContainsAny(cfg.Settings.SMTPUsername+cfg.SMTPPassword, "\r\n") {
		return errors.New("invalid SMTP credentials")
	}
	return nil
}
func (s *Sender) email(ctx context.Context, event domain.NotificationEvent) error {
	address := net.JoinHostPort(s.cfg.Settings.SMTPHost, strconv.Itoa(s.cfg.Settings.SMTPPort))
	conn, err := safeDial(ctx, "tcp", address)
	if err != nil {
		return publicDeliveryError(domain.NotificationSMTP, "connection", err, true)
	}
	defer conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	var client *smtp.Client
	if s.cfg.Settings.SMTPPort == 465 {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: s.cfg.Settings.SMTPHost, MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return publicDeliveryError(domain.NotificationSMTP, "TLS negotiation", err, true)
		}
		client, err = smtp.NewClient(tlsConn, s.cfg.Settings.SMTPHost)
	} else {
		client, err = smtp.NewClient(conn, s.cfg.Settings.SMTPHost)
		if err == nil {
			if ok, _ := client.Extension("STARTTLS"); ok {
				err = client.StartTLS(&tls.Config{ServerName: s.cfg.Settings.SMTPHost, MinVersion: tls.VersionTLS12})
			} else if !localOrPrivate(s.cfg.Settings.SMTPHost) {
				err = errors.New("SMTP server does not offer STARTTLS")
			}
		}
	}
	if err != nil {
		return smtpDeliveryError("session setup", err, true)
	}
	defer client.Close()
	if s.cfg.Settings.SMTPUsername != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return &DeliveryError{Channel: domain.NotificationSMTP, Stage: "authentication capability", Retryable: false}
		}
		if err = client.Auth(smtp.PlainAuth("", s.cfg.Settings.SMTPUsername, s.cfg.SMTPPassword, s.cfg.Settings.SMTPHost)); err != nil {
			return smtpDeliveryError("authentication", err, false)
		}
	}
	if err = client.Mail(s.cfg.Settings.SMTPFrom); err != nil {
		return smtpDeliveryError("sender command", err, false)
	}
	for _, to := range s.cfg.Settings.SMTPTo {
		if err = client.Rcpt(to); err != nil {
			return smtpDeliveryError("recipient command", err, false)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return smtpDeliveryError("message start", err, true)
	}
	subject := sanitizeHeader("[WitShield] " + event.Title)
	eventHeader := sanitizeHeader(event.ID)
	messageIDHash := sha256.Sum256([]byte(event.ID))
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@witshield.local>\r\nX-WitShield-Event-ID: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n\r\nDevice: %s\r\nEvent: %s\r\n", s.cfg.Settings.SMTPFrom, strings.Join(s.cfg.Settings.SMTPTo, ", "), subject, time.Now().Format(time.RFC1123Z), hex.EncodeToString(messageIDHash[:16]), eventHeader, event.Message, event.DeviceID, event.Type)
	if _, err = io.WriteString(writer, message); err != nil {
		_ = writer.Close()
		return publicDeliveryError(domain.NotificationSMTP, "message write", err, true)
	}
	if err = writer.Close(); err != nil {
		return smtpDeliveryError("message completion", err, true)
	}
	// A successful DATA completion means the server accepted the message. QUIT
	// is cleanup only; retrying after a lost QUIT response creates duplicates.
	_ = client.Quit()
	return nil
}

// publicDeliveryError intentionally does not wrap the network/library error:
// net/http includes the full webhook path and query in url.Error, while SMTP
// peers can return arbitrary text that echoes credentials. Only fixed stage
// names and cancellation classes may cross into APIs, logs, or the outbox.
func publicDeliveryError(channel domain.NotificationChannel, stage string, err error, retryable bool) error {
	if errors.Is(err, context.Canceled) {
		retryable = true
	}
	return &DeliveryError{Channel: channel, Stage: stage, Retryable: retryable}
}

func smtpDeliveryError(stage string, err error, defaultRetryable bool) error {
	status := 0
	retryable := defaultRetryable
	var protocolError *textproto.Error
	if errors.As(err, &protocolError) {
		status = protocolError.Code
		retryable = status >= 400 && status < 500
	}
	return &DeliveryError{Channel: domain.NotificationSMTP, Stage: stage, Status: status, Retryable: retryable}
}

func eventIDFromBody(body []byte) string {
	var event struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &event)
	return event.ID
}
func sanitizeHeader(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
}

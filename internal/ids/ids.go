package ids

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

func New(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return prefix + "_" + strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

func Token(prefix string, bytes int) (string, error) {
	if bytes < 16 {
		return "", fmt.Errorf("token entropy must be at least 128 bits")
	}
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func Hint(token string) string {
	if len(token) <= 10 {
		return "••••"
	}
	return token[:6] + "…" + token[len(token)-4:]
}

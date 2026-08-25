package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Vault struct {
	aead cipher.AEAD
}

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func (v *Vault) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := v.aead.Seal(nil, nonce, []byte(plaintext), []byte("witshield:v1"))
	return "v1:" + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func (v *Vault) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if len(ciphertext) < 3 || ciphertext[:3] != "v1:" {
		return "", errors.New("unsupported ciphertext version")
	}
	b, err := base64.RawURLEncoding.DecodeString(ciphertext[3:])
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}
	if len(b) < v.aead.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	plain, err := v.aead.Open(nil, b[:v.aead.NonceSize()], b[v.aead.NonceSize():], []byte("witshield:v1"))
	if err != nil {
		return "", errors.New("decrypt secret: authentication failed")
	}
	return string(plain), nil
}

func LoadOrCreateKey(path string) ([]byte, error) {
	if err := validateKeyDirectory(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("master key must be a regular file, not a symlink")
		}
		if err := validateSecretMode(path, info.Mode()); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(b))
		if decodeErr != nil || len(decoded) != 32 {
			return nil, errors.New("invalid master key file")
		}
		return decoded, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("master key directory must be a non-symlink directory")
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secure key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if n, err := f.WriteString(encoded); err != nil || n != len(encoded) {
		_ = f.Close()
		_ = os.Remove(path)
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func validateKeyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("master key directory must be a non-symlink directory")
	}
	clean := filepath.Clean(path)
	if clean != "/run/secrets" && !strings.HasPrefix(clean, "/run/secrets"+string(filepath.Separator)) && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("master key directory permissions are too broad: %04o", info.Mode().Perm())
	}
	return nil
}

// ReadFile reads a token/credential file without following a symlink. Native
// files must be owner-only; read-only Docker secrets below /run/secrets may be
// readable by the container user because the mount itself is isolated.
func ReadFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("secret must be a regular file, not a symlink")
	}
	if err := validateSecretMode(path, info.Mode()); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > 16*1024 {
		return "", errors.New("secret file is too large")
	}
	return string(b), nil
}

func validateSecretMode(path string, mode os.FileMode) error {
	clean := filepath.Clean(path)
	dockerSecret := clean == "/run/secrets" || strings.HasPrefix(clean, "/run/secrets"+string(filepath.Separator))
	if dockerSecret {
		if mode.Perm()&0o222 != 0 {
			return fmt.Errorf("docker secret must be read-only, got %04o", mode.Perm())
		}
		return nil
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("secret permissions must be 0600 or stricter, got %04o", mode.Perm())
	}
	return nil
}

func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

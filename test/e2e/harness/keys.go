package harness

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// EphemeralKeyHex generates a random secp256k1 private key as 32-byte hex (no 0x prefix).
func EphemeralKeyHex(t *testing.T) string {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(crypto.FromECDSA(pk))
}

// WriteKeyFile writes a private key hex string to a temp file (mode 0600).
func WriteKeyFile(t *testing.T, dir, name, keyHex string) string {
	t.Helper()
	keyHex = strings.TrimPrefix(strings.TrimSpace(keyHex), "0x")
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// EnsureKeyFile creates path with a new 32-byte secp256k1 key if missing (README: openssl rand -hex 32).
func EnsureKeyFile(t *testing.T, path string) {
	t.Helper()
	if KeyFileReady(path) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	method, err := writeKeyFileOpenSSL(path)
	if err != nil {
		t.Fatalf("create key file %s: %v", path, err)
	}
	t.Logf("created key file %s (%s)", path, method)
}

func writeKeyFileOpenSSL(path string) (method string, err error) {
	cmd := exec.Command("openssl", "rand", "-hex", "32")
	out, err := cmd.Output()
	if err == nil {
		hexKey := strings.TrimSpace(string(out))
		if len(hexKey) == 64 {
			if werr := os.WriteFile(path, []byte(hexKey+"\n"), 0o600); werr != nil {
				return "", werr
			}
			return "openssl rand -hex 32", nil
		}
		err = fmt.Errorf("openssl returned %d hex chars, want 64", len(hexKey))
	}
	// Fallback when openssl is unavailable (same 32-byte entropy as README intent).
	b := make([]byte, 32)
	if _, rerr := rand.Read(b); rerr != nil {
		if err != nil {
			return "", fmt.Errorf("openssl: %v; crypto/rand: %w", err, rerr)
		}
		return "", rerr
	}
	hexKey := hex.EncodeToString(b)
	if werr := os.WriteFile(path, []byte(hexKey+"\n"), 0o600); werr != nil {
		return "", werr
	}
	if err != nil {
		return "crypto/rand (openssl unavailable)", nil
	}
	return "crypto/rand", nil
}

// ReadKeyFile reads a key file and returns hex without 0x or newlines.
func ReadKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return "", fmt.Errorf("empty key in %s", path)
	}
	return s, nil
}

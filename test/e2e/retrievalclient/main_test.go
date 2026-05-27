// Package retrievalclient_test runs black-box CLI tests against a built retrieval-client binary.
package retrievalclient_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var retrievalClientBin string

func TestMain(m *testing.M) {
	bin := os.Getenv("RETRIEVAL_CLIENT_BIN")
	if bin == "" {
		dir, err := os.MkdirTemp("", "retrieval-client-e2e-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "mkdir temp bin dir: %v\n", err)
			os.Exit(1)
		}
		defer os.RemoveAll(dir)
		bin = filepath.Join(dir, "retrieval-client")
		root, err := moduleRoot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "module root: %v\n", err)
			os.Exit(1)
		}
		build := exec.Command("go", "build", "-o", bin, "./cmd/retrieval-client")
		build.Dir = root
		build.Stdout = os.Stdout
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build retrieval-client: %v\n", err)
			os.Exit(1)
		}
	}
	if _, err := os.Stat(bin); err != nil {
		fmt.Fprintf(os.Stderr, "retrieval-client binary %q: %v\n", bin, err)
		os.Exit(1)
	}
	retrievalClientBin = bin
	os.Exit(m.Run())
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", dir)
		}
		dir = parent
	}
}

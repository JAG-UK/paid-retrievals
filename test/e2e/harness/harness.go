// Package harness supports local black-box E2E tests (Docker nginx, subprocess binaries).
package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TestPieceCID is a valid IPFS CID for MPP parsing (see internal/mpp).
const TestPieceCID = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"

// PieceCARBody is the upstream CAR bytes served by the E2E nginx fixture.
var PieceCARBody = []byte("DUMMY-CAR-DATA")

const (
	DefaultCalibrationRPC = "https://api.calibration.node.glif.io/rpc/v1"
	EnvCalibrationE2E     = "E2E_CALIBRATION"
	EnvE2EDebug           = "E2E_DEBUG"
	EnvClientKeyFile      = "E2E_CLIENT_KEY_FILE"
	EnvSPKeyFile          = "E2E_SP_KEY_FILE"
	EnvRetrievalClientBin = "RETRIEVAL_CLIENT_BIN"
	EnvSPProxyBin         = "SP_PROXY_BIN"
	EnvCalibrationRPC     = "E2E_CALIBRATION_RPC"
)

// Binaries holds paths to built CLI tools.
type Binaries struct {
	RetrievalClient string
	SPProxy         string
}

// ModuleRoot finds the repo root containing go.mod.
func ModuleRoot() (string, error) {
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
			return "", fmt.Errorf("go.mod not found from cwd")
		}
		dir = parent
	}
}

// FixturesDir returns test/e2e/fixtures under module root.
func FixturesDir(root string) string {
	return filepath.Join(root, "test", "e2e", "fixtures")
}

// DockerAvailable reports whether the docker CLI can talk to a daemon.
func DockerAvailable() bool {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// CalibrationPaidEnabled is true when funded-wallet paid E2E should run.
func CalibrationPaidEnabled() bool {
	return strings.TrimSpace(os.Getenv(EnvCalibrationE2E)) == "1"
}

// DebugEnabled reports whether E2E subprocess logs should stream live.
func DebugEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvE2EDebug))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ClientKeyPath resolves the client key file for paid E2E.
func ClientKeyPath(root string) string {
	if p := strings.TrimSpace(os.Getenv(EnvClientKeyFile)); p != "" {
		return p
	}
	return filepath.Join(root, "test", "e2e", ".keys", "client.key")
}

// SPKeyPath resolves the SP settler key file for paid E2E.
func SPKeyPath(root string) string {
	if p := strings.TrimSpace(os.Getenv(EnvSPKeyFile)); p != "" {
		return p
	}
	return filepath.Join(root, "test", "e2e", ".keys", "sp.key")
}

// KeyFileReady reports whether path exists and is non-empty.
func KeyFileReady(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

// CARFilename is the retrieval-client output name for a CID.
func CARFilename(cid string) string {
	const maxLen = 200
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, cid)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s + ".car"
}

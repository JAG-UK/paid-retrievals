package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CalibrationKeys holds funded-wallet key file paths for Calibration E2E.
type CalibrationKeys struct {
	ClientKeyFile string
	SPKeyFile     string
}

// CalibrationRPC returns the JSON-RPC URL for Calibration (override with E2E_CALIBRATION_RPC).
func CalibrationRPC() string {
	if u := strings.TrimSpace(os.Getenv(EnvCalibrationRPC)); u != "" {
		return u
	}
	return DefaultCalibrationRPC
}

// PaidFetchOutDir returns a directory under t.TempDir for retrieval-client --out-dir.
func PaidFetchOutDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "out")
}

// RetrievalClientCalibFlags returns flags shared by rail-check and fetch on Calibration.
func RetrievalClientCalibFlags(keys CalibrationKeys, proxyBaseURL string) []string {
	args := []string{
		"--filpay-private-key-file", keys.ClientKeyFile,
		"--pay-rpc-url", CalibrationRPC(),
		"--sp-base-url", proxyBaseURL,
		"--cid", TestPieceCID,
	}
	if DebugEnabled() {
		args = append(args, "--pay-debug")
	}
	return args
}

// RetrievalClientFetchFlags returns flags for fetch (includes CalibFlags plus output/progress).
func RetrievalClientFetchFlags(keys CalibrationKeys, proxyBaseURL, outDir string) []string {
	args := RetrievalClientCalibFlags(keys, proxyBaseURL)
	args = append(args, "--no-progress", "--out-dir", outDir)
	if DebugEnabled() {
		args = append(args, "--verbose")
	}
	return args
}

//go:build e2e_stack

package stack_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fidlabs/paid-retrievals/test/e2e/harness"
)

// Calibration tests use funded wallets on a live testnet; keep sequential (no t.Parallel).

func startCalibrationStack(t *testing.T, keys harness.CalibrationKeys) *harness.SPProxy {
	t.Helper()
	requireStackBins(t)
	ng := harness.StartNginx(t, moduleRoot)
	proxy := harness.StartSPProxy(t, harness.SPProxyConfig{
		Bin:          bins.SPProxy,
		UpstreamPort: ng.Port,
		SPKeyFile:    keys.SPKeyFile,
		PayRPCURL:    harness.CalibrationRPC(),
		PayDebug:     harness.DebugEnabled(),
	})
	return proxy
}

func TestStack_CalibrationRailCheck(t *testing.T) {
	requireStackBins(t)
	keys := harness.RequireCalibrationKeys(t, moduleRoot)
	proxy := startCalibrationStack(t, keys)

	stdout, stderr, code := harness.RunRetrievalClient(t, bins.RetrievalClient, "",
		nil,
		append([]string{"rail-check"},
			harness.RetrievalClientCalibFlags(keys, proxy.BaseURL)...)...,
	)
	if code != 0 {
		t.Fatalf("rail-check exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "rail-check complete") {
		t.Fatalf("rail-check did not complete:\n%s", combined)
	}
	// Filecoin Pay may show INSUFFICIENT before fetch; wallet USDFC is validated in RequireCalibrationKeys.
	if strings.Contains(combined, "available_vs_required=INSUFFICIENT") {
		t.Log("rail-check: Filecoin Pay not yet funded (expected before fetch deposits wallet USDFC)")
	}
}

func TestStack_CalibrationPaidFetchFull(t *testing.T) {
	requireStackBins(t)
	keys := harness.RequireCalibrationKeys(t, moduleRoot)
	proxy := startCalibrationStack(t, keys)

	res, err := http.Get(proxy.BaseURL + "/piece/" + harness.TestPieceCID + "?client=0x5555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 challenge before paid fetch, got %d", res.StatusCode)
	}

	outDir := harness.PaidFetchOutDir(t)

	stdout, stderr, code := harness.RunRetrievalClient(t, bins.RetrievalClient, "",
		nil,
		append([]string{"fetch", "--yes"},
			harness.RetrievalClientFetchFlags(keys, proxy.BaseURL, outDir)...)...,
	)
	if code != 0 {
		t.Fatalf("fetch exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "Fetch complete") {
		t.Fatalf("missing Fetch complete in output:\n%s", combined)
	}
	if !strings.Contains(combined, "0.01 USDFC") {
		t.Fatalf("missing paid quote/charge in output:\n%s", combined)
	}

	carPath := filepath.Join(outDir, harness.CARFilename(harness.TestPieceCID))
	got, err := os.ReadFile(carPath)
	if err != nil {
		t.Fatalf("read downloaded CAR %s: %v", carPath, err)
	}
	if !bytes.Equal(got, harness.PieceCARBody) {
		t.Fatalf("CAR bytes mismatch: got %d bytes want %d", len(got), len(harness.PieceCARBody))
	}
	t.Logf("downloaded %s (%d bytes) via %s", carPath, len(got), proxy.BaseURL)
}

//go:build e2e_stack

package stack_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fidlabs/paid-retrievals/test/e2e/harness"
)

func requireStackBins(t *testing.T) {
	t.Helper()
	if bins.RetrievalClient == "" || bins.SPProxy == "" {
		t.Skip("docker required to build stack binaries (see test/e2e/stack/README.md)")
	}
}

func startStack(t *testing.T, spKeyFile string) (*harness.Nginx, *harness.SPProxy) {
	t.Helper()
	requireStackBins(t)
	ng := harness.StartNginx(t, moduleRoot)
	keyDir := t.TempDir()
	if spKeyFile == "" {
		spKeyFile = harness.WriteKeyFile(t, keyDir, "sp.key", harness.EphemeralKeyHex(t))
	}
	proxy := harness.StartSPProxy(t, harness.SPProxyConfig{
		Bin:          bins.SPProxy,
		UpstreamPort: ng.Port,
		SPKeyFile:    spKeyFile,
	})
	return ng, proxy
}

func TestStack_ProxyHealth(t *testing.T) {
	_, proxy := startStack(t, "")
	res, err := http.Get(proxy.BaseURL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("health: status=%d body=%q", res.StatusCode, body)
	}
}

func TestStack_ProxyHEADPiece(t *testing.T) {
	ng, proxy := startStack(t, "")
	req, err := http.NewRequest(http.MethodHead, proxy.BaseURL+"/piece/"+harness.TestPieceCID, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status %d", res.StatusCode)
	}
	if res.ContentLength != int64(len(harness.PieceCARBody)) {
		t.Fatalf("Content-Length=%d want %d", res.ContentLength, len(harness.PieceCARBody))
	}
	// Sanity: direct nginx matches.
	dres, err := http.Head(ng.BaseURL + "/piece/" + harness.TestPieceCID)
	if err != nil {
		t.Fatal(err)
	}
	defer dres.Body.Close()
	if dres.ContentLength != res.ContentLength {
		t.Fatalf("nginx vs proxy HEAD length mismatch")
	}
}

func TestStack_ProxyGETIssues402(t *testing.T) {
	_, proxy := startStack(t, "")
	client := "0x5555555555555555555555555555555555555555"
	res, err := http.Get(proxy.BaseURL + "/piece/" + harness.TestPieceCID + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("WWW-Authenticate"), "Payment") {
		t.Fatal("missing Payment challenge")
	}
}

func TestStack_ClientDryRunPaidQuote(t *testing.T) {
	requireStackBins(t)
	_, proxy := startStack(t, "")
	keyDir := t.TempDir()
	clientKey := harness.WriteKeyFile(t, keyDir, "client.key", harness.EphemeralKeyHex(t))
	outDir := t.TempDir()

	stdout, stderr, code := harness.RunRetrievalClient(t, bins.RetrievalClient, "",
		nil,
		"fetch",
		"--filpay-private-key-file", clientKey,
		"--dry-run",
		"--no-progress",
		"--sp-base-url", proxy.BaseURL,
		"--cid", harness.TestPieceCID,
		"--out-dir", outDir,
	)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "Quote:") || !strings.Contains(combined, "0.01 USDFC") {
		t.Fatalf("missing quote:\n%s", combined)
	}
	if !strings.Contains(combined, "Quote only (--dry-run)") {
		t.Fatalf("missing dry-run footer:\n%s", combined)
	}
}

func TestStack_ClientFreeDownloadDirectNginx(t *testing.T) {
	requireStackBins(t)
	ng := harness.StartNginx(t, moduleRoot)
	keyDir := t.TempDir()
	clientKey := harness.WriteKeyFile(t, keyDir, "client.key", harness.EphemeralKeyHex(t))
	outDir := t.TempDir()

	stdout, stderr, code := harness.RunRetrievalClient(t, bins.RetrievalClient, "y\n",
		nil,
		"fetch",
		"--filpay-private-key-file", clientKey,
		"--pay-rpc-url", harness.DefaultCalibrationRPC,
		"--no-progress",
		"--yes",
		"--sp-base-url", ng.BaseURL,
		"--cid", harness.TestPieceCID,
		"--out-dir", outDir,
	)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	carPath := filepath.Join(outDir, harness.CARFilename(harness.TestPieceCID))
	got, err := os.ReadFile(carPath)
	if err != nil {
		t.Fatalf("read %s: %v", carPath, err)
	}
	if !bytes.Equal(got, harness.PieceCARBody) {
		t.Fatalf("CAR bytes mismatch: got %q want %q", got, harness.PieceCARBody)
	}
}

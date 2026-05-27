package retrievalclient_test

import (
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func testPrivateKeyHex(t *testing.T) string {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(crypto.FromECDSA(pk))
}

func TestCLIHelp(t *testing.T) {
	res := runCLI(t, "", "--help")
	if res.Exit != 0 {
		t.Fatalf("exit=%d stderr=%s", res.Exit, res.Stderr)
	}
	out := combinedOutput(res)
	if !strings.Contains(out, "fetch") || !strings.Contains(out, "rail-check") {
		t.Fatalf("help output: %s", out)
	}
}

func TestCLIFetchMissingPrivateKey(t *testing.T) {
	res := runCLI(t, "", "fetch")
	if res.Exit == 0 {
		t.Fatal("expected non-zero exit")
	}
	combined := combinedOutput(res)
	if !strings.Contains(combined, "private key") {
		t.Fatalf("got stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
	if strings.Contains(combined, "Usage:") {
		t.Fatal("runtime error should not dump full usage")
	}
}

func TestCLIFetchUnknownFlagShowsUsage(t *testing.T) {
	key := testPrivateKeyHex(t)
	res := runCLI(t, "", "fetch", "--filpay-private-key", key, "--not-a-real-flag")
	if res.Exit == 0 {
		t.Fatal("expected non-zero exit")
	}
	combined := combinedOutput(res)
	if !strings.Contains(combined, "unknown flag") || !strings.Contains(combined, "Usage:") {
		t.Fatalf("got stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestCLIFetchNoCIDs(t *testing.T) {
	key := testPrivateKeyHex(t)
	res := runCLI(t, "", "fetch", "--filpay-private-key", key)
	if res.Exit == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(combinedOutput(res), "at least one CID") {
		t.Fatalf("stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestCLIFetchManifestExclusive(t *testing.T) {
	key := testPrivateKeyHex(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"pieces":[{"piece_cid":"baga1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "", "fetch", "--filpay-private-key", key, "--manifest", manifest, "--cid", "bafy1")
	if res.Exit == 0 {
		t.Fatal("expected error")
	}
	if !strings.Contains(combinedOutput(res), "mutually exclusive") {
		t.Fatalf("stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestCLIFetchDryRunPaidQuote(t *testing.T) {
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	key := testPrivateKeyHex(t)
	ts := httptest.NewServer(paidPieceServer(testPieceCID, dealUUID, "0.01", payee))
	defer ts.Close()

	res := runCLI(t, "",
		"fetch",
		"--filpay-private-key", key,
		"--dry-run",
		"--no-progress",
		"--sp-base-url", ts.URL,
		"--cid", testPieceCID,
		"--out-dir", t.TempDir(),
	)
	if res.Exit != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.Exit, res.Stdout, res.Stderr)
	}
	out := res.Stdout
	if !strings.Contains(out, "Quote:") || !strings.Contains(out, "0.01 USDFC") {
		t.Fatalf("quote table missing:\n%s", out)
	}
	if !strings.Contains(out, "Quote only (--dry-run)") {
		t.Fatalf("dry-run footer missing:\n%s", out)
	}
}

func TestCLIFetchDryRunFreeQuote(t *testing.T) {
	key := testPrivateKeyHex(t)
	body := []byte("free-car-bytes")
	ts := httptest.NewServer(freePieceServer(testPieceCID, body))
	defer ts.Close()

	res := runCLI(t, "",
		"fetch",
		"--filpay-private-key", key,
		"--dry-run",
		"--no-progress",
		"--sp-base-url", ts.URL,
		"--cid", testPieceCID,
	)
	if res.Exit != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.Exit, res.Stdout, res.Stderr)
	}
	out := res.Stdout
	if !strings.Contains(out, "free") {
		t.Fatalf("expected free row:\n%s", out)
	}
	if strings.Contains(out, "USDFC") && strings.Contains(out, "Total:") {
		t.Fatalf("free-only quote should not show paid total:\n%s", out)
	}
}

func TestCLIFetchAbortedAtPrompt(t *testing.T) {
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	key := testPrivateKeyHex(t)
	ts := httptest.NewServer(paidPieceServer(testPieceCID, dealUUID, "0.01", payee))
	defer ts.Close()

	res := runCLI(t, "n\n",
		"fetch",
		"--filpay-private-key", key,
		"--no-progress",
		"--sp-base-url", ts.URL,
		"--cid", testPieceCID,
	)
	if res.Exit == 0 {
		t.Fatal("expected non-zero exit when user declines")
	}
	if !strings.Contains(combinedOutput(res), "aborted") {
		t.Fatalf("stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

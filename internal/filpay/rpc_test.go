// Tests for NewClient RPC wiring using a minimal httptest JSON-RPC server (eth_chainId only).
//
// Trade-offs:
//   - Scope: verifies dial, chain ID resolution, default/explicit payments address, token
//     resolution, and PaymentsContract bind—not contract calls or account state.
//   - Fidelity: mockRPCServer ignores unknown methods (result null); sufficient for NewClient
//     init but not for methods that hit the node after construction.
//   - vs settlement_test.go: complements direct Client construction; together they reach ~70%
//     statement coverage without calibration/mainnet integration tests.
//   - Gaps intentionally left to settlement_test.go or future simchain tests: transact paths,
//     WaitMined against a real backend, and devnet (dynamic genesis / addresses).
package filpay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// mockRPCServer returns a server that only implements eth_chainId; other RPC methods are not
// modeled. Extend here if NewClient starts requiring additional calls at init time.
func mockRPCServer(t *testing.T, chainIDHex string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatal(err)
		}
		var result any
		switch req.Method {
		case "eth_chainId":
			result = chainIDHex
		default:
			result = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		})
	}))
}

func TestNewClientCalibrationRPC(t *testing.T) {
	pk := testPrivateKey(t)
	hex := testHexKey(t, pk)
	srv := mockRPCServer(t, "0x4cb2f") // 314159 calibration
	defer srv.Close()

	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	c, err := NewClient(context.Background(), srv.URL, hex, "", "", "", WithPayLogging(log, true))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ChainID().Int64() != constants.ChainIDCalibration {
		t.Fatalf("chain id %s", c.ChainID())
	}
	if c.paymentToken != constants.USDFCAddressesByChainID[constants.ChainIDCalibration] {
		t.Fatalf("token %s", c.paymentToken.Hex())
	}
	if c.PaymentsAddress() == (common.Address{}) {
		t.Fatal("expected non-zero payments contract address")
	}
	if c.SignerAddress() != crypto.PubkeyToAddress(pk.PublicKey) {
		t.Fatal("signer mismatch")
	}
	if !strings.Contains(buf.String(), "client initialized") {
		t.Fatalf("expected init log, got %q", buf.String())
	}
}

func TestNewClientMainnetRPC(t *testing.T) {
	pk := testPrivateKey(t)
	hex := testHexKey(t, pk)
	srv := mockRPCServer(t, "0x13a") // 314 mainnet
	defer srv.Close()
	c, err := NewClient(context.Background(), srv.URL, hex, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ChainID().Int64() != constants.ChainIDMainnet {
		t.Fatalf("chain id %s", c.ChainID())
	}
}

func TestNewClientUnknownChainRequiresPaymentsAddress(t *testing.T) {
	pk := testPrivateKey(t)
	hex := testHexKey(t, pk)
	srv := mockRPCServer(t, "0x1869f") // 99999
	defer srv.Close()
	_, err := NewClient(context.Background(), srv.URL, hex, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "unknown payments contract") {
		t.Fatalf("got %v", err)
	}
}

func TestNewClientExplicitPaymentsAddress(t *testing.T) {
	pk := testPrivateKey(t)
	hex := testHexKey(t, pk)
	srv := mockRPCServer(t, "0x4cb2f")
	defer srv.Close()
	payAddr := "0xAbCdEfabcdefabcdefabcdefabcdefabcdefABCD"
	c, err := NewClient(context.Background(), srv.URL, hex, "", "", payAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.PaymentsAddress() != common.HexToAddress(payAddr) {
		t.Fatalf("payments %s", c.PaymentsAddress().Hex())
	}
}

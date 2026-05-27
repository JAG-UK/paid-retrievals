package harness

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
)

const (
	calibFaucetBeryx     = "https://beryx.io/faucet"
	calibFaucetChainSafe = "https://faucet.calibnet.chainsafe-fil.io"
	calibFaucetUSDFC     = "https://forest-explorer.chainsafe.dev/faucet/calibnet_usdfc"
	calibStackPriceUSDFC = "0.01"
)

// minCalibFIL is the minimum native tFIL each wallet should hold for gas (in wei).
var minCalibFIL = new(big.Int).Mul(big.NewInt(1e16), big.NewInt(1)) // 0.01 FIL

// RequireCalibrationKeys ensures Calibration paid E2E can run: keys exist and wallets are funded.
func RequireCalibrationKeys(t *testing.T, root string) CalibrationKeys {
	t.Helper()
	if !CalibrationPaidEnabled() {
		t.Skip("set E2E_CALIBRATION=1 to run Calibration paid E2E (see test/e2e/stack/README.md)")
	}
	keys := CalibrationKeys{
		ClientKeyFile: ClientKeyPath(root),
		SPKeyFile:     SPKeyPath(root),
	}
	EnsureKeyFile(t, keys.ClientKeyFile)
	EnsureKeyFile(t, keys.SPKeyFile)
	ensureCalibrationFunded(t, keys)
	return keys
}

func ensureCalibrationFunded(t *testing.T, keys CalibrationKeys) {
	t.Helper()

	clientAddr, err := addressFromKeyFile(keys.ClientKeyFile)
	if err != nil {
		t.Fatalf("read client key: %v", err)
	}
	spAddr, err := addressFromKeyFile(keys.SPKeyFile)
	if err != nil {
		t.Fatalf("read sp key: %v", err)
	}

	requiredUSDFC, err := paymentheader.ParseTokenToBaseUnits(calibStackPriceUSDFC)
	if err != nil {
		t.Fatalf("parse required USDFC: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	ethCli, err := ethclient.DialContext(ctx, CalibrationRPC())
	if err != nil {
		t.Fatal(formatFundingError(keys, clientAddr, spAddr, nil,
			fmt.Sprintf("dial Calibration RPC %s: %v", CalibrationRPC(), err)))
	}
	defer ethCli.Close()

	var problems []string

	clientFIL, err := ethCli.BalanceAt(ctx, clientAddr, nil)
	if err != nil {
		problems = append(problems, fmt.Sprintf("client %s: cannot read tFIL balance: %v", clientAddr.Hex(), err))
	} else if clientFIL.Cmp(minCalibFIL) < 0 {
		problems = append(problems, fmt.Sprintf("client %s: tFIL %s (need ≥ ~0.01 tFIL for gas)",
			clientAddr.Hex(), formatFIL(clientFIL)))
	}

	spFIL, err := ethCli.BalanceAt(ctx, spAddr, nil)
	if err != nil {
		problems = append(problems, fmt.Sprintf("sp %s: cannot read tFIL balance: %v", spAddr.Hex(), err))
	} else if spFIL.Cmp(minCalibFIL) < 0 {
		problems = append(problems, fmt.Sprintf("sp %s: tFIL %s (need ≥ ~0.01 tFIL for settlement gas)",
			spAddr.Hex(), formatFIL(spFIL)))
	}

	fc, err := filpay.NewClient(ctx, CalibrationRPC(), "", keys.ClientKeyFile, "", "")
	if err != nil {
		problems = append(problems, fmt.Sprintf("client %s: Filecoin Pay client: %v", clientAddr.Hex(), err))
	} else {
		defer fc.Close()
		avail, err := fc.PayerTokenAvailable(ctx, clientAddr)
		if err != nil {
			problems = append(problems, fmt.Sprintf("client %s: Filecoin Pay available balance: %v", clientAddr.Hex(), err))
		} else if avail.Cmp(requiredUSDFC) < 0 {
			walletUSDFC, werr := fc.WalletUSDFCBalance(ctx, clientAddr)
			if werr != nil {
				problems = append(problems, fmt.Sprintf("client %s: USDFC wallet balance: %v", clientAddr.Hex(), werr))
			} else if walletUSDFC.Cmp(requiredUSDFC) >= 0 {
				t.Logf("client %s: Filecoin Pay available %s USDFC; wallet holds %s USDFC — fetch will deposit into Filecoin Pay",
					clientAddr.Hex(), formatUSDFC(avail), formatUSDFC(walletUSDFC))
			} else {
				problems = append(problems, fmt.Sprintf(
					"client %s: need ≥ %s USDFC for one paid piece — Filecoin Pay available %s, wallet %s (fund wallet at USDFC faucet, then re-run; fetch can deposit wallet USDFC into Filecoin Pay)",
					clientAddr.Hex(), calibStackPriceUSDFC, formatUSDFC(avail), formatUSDFC(walletUSDFC)))
			}
		}
	}

	if len(problems) > 0 {
		t.Fatal(formatFundingError(keys, clientAddr, spAddr, problems, ""))
	}
}

func addressFromKeyFile(path string) (common.Address, error) {
	hexKey, err := ReadKeyFile(path)
	if err != nil {
		return common.Address{}, err
	}
	pk, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(pk.PublicKey), nil
}

func formatFIL(wei *big.Int) string {
	if wei == nil {
		return "0 tFIL"
	}
	f := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.4f", f), "0"), ".") + " tFIL"
}

func formatUSDFC(baseUnits *big.Int) string {
	if baseUnits == nil {
		return "0"
	}
	f := new(big.Float).Quo(new(big.Float).SetInt(baseUnits), big.NewFloat(1e18))
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", f), "0"), ".")
}

func formatFundingError(keys CalibrationKeys, clientAddr, spAddr common.Address, problems []string, prefix string) string {
	var b strings.Builder
	if prefix != "" {
		b.WriteString(prefix)
		b.WriteString("\n\n")
	}
	b.WriteString("Calibration E2E wallets are not ready for paid retrieval.\n\n")
	b.WriteString("Use these exact 0x addresses (from your key files on this machine):\n")
	fmt.Fprintf(&b, "  client key file: %s\n", keys.ClientKeyFile)
	fmt.Fprintf(&b, "  client (payer):    %s\n", clientAddr.Hex())
	fmt.Fprintf(&b, "  sp key file:     %s\n", keys.SPKeyFile)
	fmt.Fprintf(&b, "  sp (settler):    %s\n", spAddr.Hex())
	b.WriteString("\nFund on Filecoin Calibration (chain ID 314159). Use the 0x address above — not a different key or a Lotus f1/f4 address.\n")
	b.WriteString("\nFaucets:\n")
	fmt.Fprintf(&b, "  tFIL (gas, both wallets):     %s\n", calibFaucetBeryx)
	fmt.Fprintf(&b, "                               %s\n", calibFaucetChainSafe)
	fmt.Fprintf(&b, "  USDFC (client wallet):        %s\n", calibFaucetUSDFC)
	b.WriteString("\nNotes:\n")
	b.WriteString("  - USDFC in the wallet is enough; fetch deposits into Filecoin Pay automatically.\n")
	b.WriteString("  - If you funded different addresses, copy keys into the paths above or set E2E_CLIENT_KEY_FILE / E2E_SP_KEY_FILE.\n")
	if len(problems) > 0 {
		b.WriteString("\nDetails:\n")
		for _, p := range problems {
			b.WriteString("  - ")
			b.WriteString(p)
			b.WriteString("\n")
		}
	}
	b.WriteString("\nRe-run: E2E_CALIBRATION=1 task test:e2e:stack:calibration")
	return b.String()
}

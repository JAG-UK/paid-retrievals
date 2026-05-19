package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

type filpayKeyOpts struct {
	privateKey     string
	privateKeyFile string
	privateKeyEnv  string
}

type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

type challengeItem struct {
	CID        string
	Base       *url.URL
	Free       bool
	SavedPath  string
	DealUUID   string
	PriceUSDFC string
	Payee0x    string
	Challenge  mpp.Challenge
}

func main() {
	if err := root().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	keyOpts := &filpayKeyOpts{}
	r := &cobra.Command{
		Use:   "retrieval-client",
		Short: "Client CLI for MPP + Filecoin Pay piece retrieval (EVM client key)",
	}
	addFilpayKeyFlags(r, keyOpts)
	r.AddCommand(cmdFetch(keyOpts))
	r.AddCommand(cmdRailCheck(keyOpts))
	return r
}

func cmdFetch(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		outDir             string
		cids               []string
		cidFile            string
		manifest           string
		yes                bool
		expiresIn          int
		verbose            bool
		payDebug           bool
		payRPCURL          string
		payPaymentsAddress string
	)
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch multiple piece CIDs: discover SP bases, MPP challenge (402), then EVM-signed paid retrieval",
		RunE: func(cmd *cobra.Command, args []string) error {
			evmPK, err := filpay.LoadPrivateKey(keyOpts.privateKey, keyOpts.privateKeyFile, keyOpts.privateKeyEnv)
			if err != nil {
				return fmt.Errorf("load client private key (--filpay-private-key* / %s): %w", keyOpts.privateKeyEnv, err)
			}
			client := crypto.PubkeyToAddress(evmPK.PublicKey).Hex()
			if verbose {
				fmt.Printf("Client 0x address (from private key): %s\n", client)
			}
			if payDebug {
				payClientLog("client 0x=%s (derived from private key)", client)
			}

			var allCIDs []string
			if strings.TrimSpace(manifest) != "" {
				if len(cids) > 0 || strings.TrimSpace(cidFile) != "" || len(args) > 0 {
					return errors.New("--manifest is mutually exclusive with positional CIDs, --cid, and --cid-file")
				}
				var err error
				allCIDs, err = extractPieceCIDsFromManifest(manifest)
				if err != nil {
					return err
				}
				if len(allCIDs) == 0 {
					return fmt.Errorf("manifest %q has no pieces[].piece_cid entries", manifest)
				}
			} else {
				var err error
				allCIDs, err = collectCIDs(cids, cidFile, args)
				if err != nil {
					return err
				}
				if len(allCIDs) == 0 {
					return errors.New("provide at least one CID via args, --cid, or --cid-file (or use --manifest)")
				}
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			// We don't set a timeout for the client as download of a payload can take a very long time
			// users can manually cancel if required
			cli := &http.Client{}
			discoverCli := &http.Client{Timeout: 90 * time.Second}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			probeLog := func(format string, args ...any) {
				if payDebug {
					payClientLog(format, args...)
				}
			}
			spOverride := strings.TrimSpace(spBaseURL)

			items := make([]challengeItem, 0, len(allCIDs))
			if verbose {
				fmt.Printf("Step 1/%d: probing discovered SP bases for %d CID(s)\n", 2, len(allCIDs))
			}

			for _, cid := range allCIDs {
				if verbose {
					fmt.Printf("  - discovering SP HTTP bases for CID %s (filecoin.tools + cid.contact / Lotus)\n", cid)
				}
				bases, derr := pieceurls.DiscoverPieceHTTPBases(ctx, discoverCli, cid, payRPCURL)
				if spOverride != "" {
					ob, perr := url.Parse(spOverride)
					if perr != nil {
						return fmt.Errorf("invalid --sp-base-url: %w", perr)
					}
					if ob.Scheme == "" || ob.Host == "" {
						return errors.New("invalid --sp-base-url: URL must include scheme and host (e.g. http://127.0.0.1:8787)")
					}
					u := *ob
					u.Path, u.RawQuery, u.Fragment = "", "", ""
					bases = []*url.URL{&u}
					if verbose {
						fmt.Printf("    --sp-base-url override: probing only %s\n", bases[0].String())
					}
				} else {
					if derr != nil {
						return fmt.Errorf("discover endpoints for CID %s: %w", cid, derr)
					}
					if len(bases) == 0 {
						return fmt.Errorf("discover: no HTTP endpoints for CID %s (empty filecoin.tools search or no resolvable multiaddrs); use --sp-base-url to force a proxy", cid)
					}
					if verbose {
						fmt.Printf("    found %d unique base URL(s); probing for free CAR or 402 MPP challenge\n", len(bases))
					}
				}

				sel, err := pieceurls.SelectBestPieceSource(ctx, cli, cid, client, outDir, bases, probeLog)
				if err != nil {
					return fmt.Errorf("dataset incomplete: no usable source for CID %s: %w", cid, err)
				}
				if payDebug && !sel.Free && strings.TrimSpace(sel.Payee0x) != "" {
					payClientLog("selected payee_0x=%s (fund/open rail payer=client → payee); SP settles on paid GET", sel.Payee0x)
				}
				if verbose {
					if sel.Free {
						fmt.Printf("    free CAR from %s -> %s\n", sel.Base.String(), sel.SavedPath)
					} else {
						line := fmt.Sprintf("    selected %s — CID %s costs %s USDFC (deal %s)", sel.Base.String(), cid, sel.PriceUSDFC, sel.DealUUID)
						if strings.TrimSpace(sel.Payee0x) != "" {
							line += fmt.Sprintf(" payee_0x=%s", sel.Payee0x)
						}
						fmt.Println(line)
					}
				}
				items = append(items, challengeItem{
					CID:        cid,
					Base:       sel.Base,
					Free:       sel.Free,
					SavedPath:  sel.SavedPath,
					DealUUID:   sel.DealUUID,
					PriceUSDFC: sel.PriceUSDFC,
					Payee0x:    strings.TrimSpace(sel.Payee0x),
					Challenge:  sel.Challenge,
				})
			}

			var prices []string
			for _, it := range items {
				if it.Free {
					continue
				}
				prices = append(prices, it.PriceUSDFC)
			}
			total, err := sumTokenValues(prices)
			if err != nil {
				return fmt.Errorf("sum token values: %w", err)
			}
			fmt.Printf("Total required amount: %s USDFC for %d piece(s).\n", total, len(items))

			var filpayLogger *slog.Logger
			if payDebug || verbose {
				level := slog.LevelInfo
				if verbose {
					level = slog.LevelDebug
				}
				filpayLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			}
			fc, err := filpay.NewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpay.WithPayLogging(filpayLogger, payDebug || verbose),
			)
			if err != nil {
				return fmt.Errorf("init filpay client for rail setup: %w", err)
			}
			defer fc.Close()
			if fc.SignerAddress().Hex() != client {
				return fmt.Errorf("derived client %s does not match filpay signer %s", client, fc.SignerAddress().Hex())
			}
			prepStart := time.Now()
			if err := prepareRailsForChallenges(context.Background(), fc, client, items, payDebug); err != nil {
				return err
			}
			if payDebug || verbose {
				payClientLog("prepare phase complete in %s", time.Since(prepStart).Round(time.Millisecond))
			}

			if !yes {
				ok, err := promptYesNo("Proceed with payment and download? [y/N]: ")
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}
			chargeStart := time.Now()
			if err := chargeRailsForChallenges(context.Background(), fc, client, items, payDebug); err != nil {
				return err
			}
			if payDebug || verbose {
				payClientLog("charge phase complete in %s", time.Since(chargeStart).Round(time.Millisecond))
			}
			if verbose {
				fmt.Printf("Step 2/%d: fetching paid pieces for %d CID(s)\n", 2, len(items))
			}

			for _, it := range items {
				if it.Free {
					if verbose {
						fmt.Printf("  - CID %s already stored (free): %s\n", it.CID, it.SavedPath)
					} else {
						fmt.Printf("stored %s (free)\n", it.SavedPath)
					}
					continue
				}
				if it.Base == nil {
					return fmt.Errorf("internal: missing base URL for paid CID %s", it.CID)
				}
				piecePath := "/piece/" + it.CID
				if verbose {
					fmt.Printf("  - creating MPP credential for CID %s (deal %s) via %s\n", it.CID, it.DealUUID, it.Base.String())
				}
				h := &mpp.ProofPayload{
					Version:       mpp.VersionV1,
					ChallengeID:   it.Challenge.ID,
					DealUUID:      it.DealUUID,
					ClientAddress: client,
					CID:           it.CID,
					Method:        http.MethodGet,
					Path:          piecePath,
					Host:          it.Base.Host,
					Nonce:         uuid.NewString(),
					ExpiresUnix:   time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
				}
				st, sig, err := mpp.SignEVM(evmPK, h.CanonicalMessage())
				if err != nil {
					return err
				}
				h.SigType = st
				h.Signature = sig
				if payDebug {
					payClientLog("signed mpp deal=%s cid=%s path=%s sig_type=%s sig_len=%d", it.DealUUID, it.CID, piecePath, st, len(sig))
				}
				cred, err := mpp.BuildCredential(it.Challenge, *h, client)
				if err != nil {
					return err
				}
				authz, err := cred.EncodeAuthorization()
				if err != nil {
					return err
				}
				outPath, err := downloadCAR(cli, it.Base, it.CID, piecePath, authz, outDir, payDebug)
				if err != nil {
					return err
				}
				if verbose {
					fmt.Printf("    piece stored: CID %s -> %s\n", it.CID, outPath)
				} else {
					fmt.Printf("stored %s\n", outPath)
				}
			}
			fmt.Println("Fetch complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "", "If set, skip using discovered endpoints and probe only this SP HTTP base (e.g. http://127.0.0.1:8787)")
	c.Flags().StringVar(&outDir, "out-dir", ".", "Output directory")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to fetch (repeatable)")
	c.Flags().StringVar(&cidFile, "cid-file", "", "File with CIDs (newline or comma separated)")
	c.Flags().StringVar(&manifest, "manifest", "", "Path to data-prep-standard super-manifest JSON (extract pieces[].piece_cid)")
	c.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	c.Flags().IntVar(&expiresIn, "expires-in-sec", 120, "Header expiry interval in seconds")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print detailed per-step progress output")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Log Filecoin Pay–related client steps to stderr ([filpay-client])")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.calibration.node.glif.io/rpc/v1"), "Filecoin JSON-RPC URL: FVM payments + Lotus StateMinerInfo for discovery")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	return c
}

func cmdRailCheck(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		cids               []string
		cidFile            string
		payees             []string
		requiredUSDFC      string
		payDebug           bool
		payRPCURL          string
		payPaymentsAddress string
	)
	c := &cobra.Command{
		Use:   "rail-check",
		Short: "Print detailed payer/payee Filecoin Pay rail readiness",
		RunE: func(cmd *cobra.Command, args []string) error {
			evmPK, err := filpay.LoadPrivateKey(keyOpts.privateKey, keyOpts.privateKeyFile, keyOpts.privateKeyEnv)
			if err != nil {
				return fmt.Errorf("load client private key (--filpay-private-key* / %s): %w", keyOpts.privateKeyEnv, err)
			}
			client := crypto.PubkeyToAddress(evmPK.PublicKey).Hex()
			fmt.Printf("Client (payer): %s\n", client)

			var filpayLogger *slog.Logger
			if payDebug {
				filpayLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			}
			fc, err := filpay.NewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpay.WithPayLogging(filpayLogger, payDebug),
			)
			if err != nil {
				return fmt.Errorf("init filpay client: %w", err)
			}
			defer fc.Close()
			fmt.Printf("Chain ID: %s\n", fc.ChainID().String())
			fmt.Printf("Payments contract: %s\n", fc.PaymentsAddress().Hex())
			fmt.Printf("Signer (from key): %s\n", fc.SignerAddress().Hex())
			if fc.SignerAddress().Hex() != client {
				return fmt.Errorf("derived client %s does not match filpay signer %s", client, fc.SignerAddress().Hex())
			}

			// Gather payees from manual flags and optional live MPP challenges (discovery or --sp-base-url).
			challenges := make([]challengeItem, 0)
			if len(cids) > 0 || strings.TrimSpace(cidFile) != "" || len(args) > 0 {
				allCIDs, err := collectCIDs(cids, cidFile, args)
				if err != nil {
					return err
				}
				cli := &http.Client{Timeout: 120 * time.Second}
				discoverCli := &http.Client{Timeout: 90 * time.Second}
				ctx := cmd.Context()
				if ctx == nil {
					ctx = context.Background()
				}
				probeLog := func(format string, args ...any) {
					if payDebug {
						payClientLog(format, args...)
					}
				}
				spOverride := strings.TrimSpace(spBaseURL)
				probeDir, err := os.MkdirTemp("", "retrieval-client-railcheck-*")
				if err != nil {
					return err
				}
				defer os.RemoveAll(probeDir)

				for _, cid := range allCIDs {
					var bases []*url.URL
					if spOverride != "" {
						ob, perr := url.Parse(spOverride)
						if perr != nil {
							return fmt.Errorf("invalid --sp-base-url: %w", perr)
						}
						if ob.Scheme == "" || ob.Host == "" {
							return errors.New("invalid --sp-base-url: URL must include scheme and host")
						}
						u := *ob
						u.Path, u.RawQuery, u.Fragment = "", "", ""
						bases = []*url.URL{&u}
					} else {
						var derr error
						bases, derr = pieceurls.DiscoverPieceHTTPBases(ctx, discoverCli, cid, payRPCURL)
						if derr != nil {
							return fmt.Errorf("discover endpoints for CID %s: %w", cid, derr)
						}
						if len(bases) == 0 {
							return fmt.Errorf("discover: no HTTP endpoints for CID %s; use --sp-base-url to force a proxy", cid)
						}
					}
					sel, err := pieceurls.SelectBestPieceSource(ctx, cli, cid, client, probeDir, bases, probeLog)
					if err != nil {
						return fmt.Errorf("no usable source for CID %s: %w", cid, err)
					}
					if sel.Free {
						continue
					}
					challenges = append(challenges, challengeItem{
						CID:        cid,
						Base:       sel.Base,
						Free:       false,
						DealUUID:   sel.DealUUID,
						PriceUSDFC: sel.PriceUSDFC,
						Payee0x:    strings.TrimSpace(sel.Payee0x),
						Challenge:  sel.Challenge,
					})
				}
			}

			byPayeeRequired := map[string]*big.Int{}
			if strings.TrimSpace(requiredUSDFC) != "" {
				reqWei, err := paymentheader.ParseTokenToWei(requiredUSDFC)
				if err != nil {
					return fmt.Errorf("invalid --required-fil %q: %w", requiredUSDFC, err)
				}
				for _, p := range payees {
					if !common.IsHexAddress(strings.TrimSpace(p)) {
						return fmt.Errorf("invalid --payee address %q", p)
					}
					byPayeeRequired[common.HexToAddress(strings.TrimSpace(p)).Hex()] = new(big.Int).Set(reqWei)
				}
			}
			for _, q := range challenges {
				if !common.IsHexAddress(strings.TrimSpace(q.Payee0x)) {
					return fmt.Errorf("challenge cid=%s deal=%s has invalid payee_0x %q", q.CID, q.DealUUID, q.Payee0x)
				}
				w, err := paymentheader.ParseTokenToWei(q.PriceUSDFC)
				if err != nil {
					return fmt.Errorf("challenge cid=%s deal=%s has bad price %q: %w", q.CID, q.DealUUID, q.PriceUSDFC, err)
				}
				key := common.HexToAddress(strings.TrimSpace(q.Payee0x)).Hex()
				if byPayeeRequired[key] == nil {
					byPayeeRequired[key] = big.NewInt(0)
				}
				byPayeeRequired[key].Add(byPayeeRequired[key], w)
			}
			if len(byPayeeRequired) == 0 {
				for _, p := range payees {
					if !common.IsHexAddress(strings.TrimSpace(p)) {
						return fmt.Errorf("invalid --payee address %q", p)
					}
					byPayeeRequired[common.HexToAddress(strings.TrimSpace(p)).Hex()] = big.NewInt(0)
				}
			}
			if len(byPayeeRequired) == 0 {
				return errors.New("no payees discovered. Provide --payee or paid MPP sources for CIDs (--cid/--cid-file/args, with discovery or --sp-base-url)")
			}

			if len(challenges) > 0 {
				fmt.Println("\nChallenge details:")
				for _, q := range challenges {
					fmt.Printf("- cid=%s deal=%s price_fil=%s payee_0x=%s\n", q.CID, q.DealUUID, q.PriceUSDFC, q.Payee0x)
				}
			}

			payer := common.HexToAddress(client)
			fundedUntil, currentFunds, availableFunds, currentLockupRate, err := fc.AccountInfoIfSettled(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Println("\nPayer account:")
			fmt.Printf("- funded_until_epoch=%s\n", fundedUntil.String())
			fmt.Printf("- current_funds_wei=%s\n", currentFunds.String())
			fmt.Printf("- available_funds_wei=%s\n", availableFunds.String())
			fmt.Printf("- current_lockup_rate=%s\n", currentLockupRate.String())

			rails, err := fc.ListTokenRailsAsPayer(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Printf("\nAll payer rails: %d\n", len(rails))
			for _, r := range rails {
				settled := "n/a"
				if r.SettledUpTo != nil {
					settled = r.SettledUpTo.String()
				}
				endEpoch := "nil"
				if r.EndEpoch != nil {
					endEpoch = r.EndEpoch.String()
				}
				fmt.Printf("- rail_id=%s from=%s to=%s operator=%s token=%s terminated=%t end_epoch=%s settled_up_to=%s\n",
					r.RailID.String(), r.From.Hex(), r.To.Hex(), r.Operator.Hex(), r.Token.Hex(), r.IsTerminated, endEpoch, settled)
			}

			keys := make([]string, 0, len(byPayeeRequired))
			for k := range byPayeeRequired {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Println("\nPer-payee readiness:")
			for _, payeeHex := range keys {
				requiredWei := byPayeeRequired[payeeHex]
				payee := common.HexToAddress(payeeHex)
				fmt.Printf("\nPayee %s\n", payeeHex)
				fmt.Printf("- required_wei=%s\n", requiredWei.String())
				approval, err := fc.OperatorApproval(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- operator_approval_error=%v\n", err)
				} else {
					fmt.Printf("- operator_approved=%t\n", approval.Approved)
					fmt.Printf("- rate_allowance=%s lockup_allowance=%s max_lockup_period=%s\n",
						approval.RateAllowance.String(), approval.LockupAllowance.String(), approval.MaxLockupPeriod.String())
					fmt.Printf("- rate_used=%s lockup_used=%s\n", approval.RateUsed.String(), approval.LockupUsed.String())
				}
				railID, err := fc.FindActiveTokenRail(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- active_rail=NO (%v)\n", err)
				} else {
					fmt.Printf("- active_rail=YES rail_id=%s\n", railID.String())
				}
				if availableFunds.Cmp(requiredWei) >= 0 {
					fmt.Printf("- available_vs_required=OK (%s >= %s)\n", availableFunds.String(), requiredWei.String())
				} else {
					fmt.Printf("- available_vs_required=INSUFFICIENT (%s < %s)\n", availableFunds.String(), requiredWei.String())
				}
			}
			fmt.Println("\nrail-check complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "", "If set, probe only this SP HTTP base for MPP challenges; empty uses piece URL discovery")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to probe for payee discovery (repeatable)")
	c.Flags().StringVar(&cidFile, "cid-file", "", "File with CIDs for payee discovery via MPP (newline/comma separated)")
	c.Flags().StringArrayVar(&payees, "payee", nil, "Explicit payee 0x address to check (repeatable)")
	c.Flags().StringVar(&requiredUSDFC, "required-usdfc", "", "Optional required USDFC amount per --payee when no challenges are used")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Enable detailed probe logs while discovering payees from challenges")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.calibration.node.glif.io/rpc/v1"), "Filecoin JSON-RPC URL: FVM payments + Lotus StateMinerInfo for discovery")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	return c
}

func payClientLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[filpay-client] "+format+"\n", args...)
}

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func addFilpayKeyFlags(c *cobra.Command, opts *filpayKeyOpts) {
	c.PersistentFlags().StringVar(&opts.privateKey, "filpay-private-key", "", "Hex private key: client 0x identity + MPP signing (prefer env or file)")
	c.PersistentFlags().StringVar(&opts.privateKeyFile, "filpay-private-key-file", "", "File with hex private key for client identity + MPP")
	c.PersistentFlags().StringVar(&opts.privateKeyEnv, "filpay-private-key-env", getenv("FILPAY_PRIVATE_KEY_ENV", "FILPAY_PRIVATE_KEY"), "Env var for hex client key")
}

func prepareRailsForChallenges(ctx context.Context, fc *filpay.Client, client string, items []challengeItem, payDebug bool) error {
	payer := common.HexToAddress(client)
	byPayee := map[string]*big.Int{}
	for _, it := range items {
		if it.Free {
			continue
		}
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceWei, err := paymentheader.ParseTokenToWei(it.PriceUSDFC)
		if err != nil {
			return fmt.Errorf("challenge %s has invalid price_fil=%q: %w", it.DealUUID, it.PriceUSDFC, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if byPayee[key] == nil {
			byPayee[key] = big.NewInt(0)
		}
		byPayee[key].Add(byPayee[key], priceWei)
	}
	payees := make([]string, 0, len(byPayee))
	for payee := range byPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	for _, payeeHex := range payees {
		requiredWei := byPayee[payeeHex]
		if payDebug {
			payClientLog("preparing payer for payee=%s required_wei=%s (check approval/balance/rail, then submit txs only if needed)", payeeHex, requiredWei.String())
			payeeAddr := common.HexToAddress(payeeHex)
			approval, aerr := fc.OperatorApproval(ctx, payer, payer)
			_, _, avail, _, berr := fc.AccountInfoIfSettled(ctx, payer)
			railID, rerr := fc.FindActiveTokenRail(ctx, payer, payeeAddr)
			approved := "unknown"
			if aerr == nil {
				approved = fmt.Sprintf("%t", approval.Approved)
			}
			availStr := "unknown"
			fundsOK := "unknown"
			if berr == nil && avail != nil {
				availStr = avail.String()
				if avail.Cmp(requiredWei) >= 0 {
					fundsOK = "yes"
				} else {
					fundsOK = "no"
				}
			}
			railState := "no"
			if rerr == nil && railID != nil {
				railState = "yes rail_id=" + railID.String()
			}
			payClientLog(
				"preflight payee=%s approved=%s available_wei=%s required_wei=%s funds_sufficient=%s active_rail=%s operator_check_err=%v balance_check_err=%v rail_check_err=%v",
				payeeHex, approved, availStr, requiredWei.String(), fundsOK, railState, aerr, berr, rerr,
			)
		}
		start := time.Now()
		if err := fc.PreparePayerForPayee(ctx, payer, common.HexToAddress(payeeHex), requiredWei); err != nil {
			return fmt.Errorf("prepare rail/account for payee %s failed: %w", payeeHex, err)
		}
		if payDebug {
			payClientLog("payer preparation complete for payee=%s duration=%s", payeeHex, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func chargeRailsForChallenges(ctx context.Context, fc *filpay.Client, client string, items []challengeItem, payDebug bool) error {
	payer := common.HexToAddress(client)
	byPayee := map[string]*big.Int{}
	for _, it := range items {
		if it.Free {
			continue
		}
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceWei, err := paymentheader.ParseTokenToWei(it.PriceUSDFC)
		if err != nil {
			return fmt.Errorf("challenge %s has invalid price_fil=%q: %w", it.DealUUID, it.PriceUSDFC, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if byPayee[key] == nil {
			byPayee[key] = big.NewInt(0)
		}
		byPayee[key].Add(byPayee[key], priceWei)
	}
	payees := make([]string, 0, len(byPayee))
	for payee := range byPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	for _, payeeHex := range payees {
		amountWei := byPayee[payeeHex]
		if payDebug {
			payClientLog("charging rail one-time payment payee=%s amount_wei=%s", payeeHex, amountWei.String())
		}
		start := time.Now()
		txHash, err := fc.ChargeRailOneTime(ctx, payer, common.HexToAddress(payeeHex), amountWei)
		if err != nil {
			return fmt.Errorf("charge rail for payee %s failed: %w", payeeHex, err)
		}
		if payDebug {
			payClientLog("modifyRailPayment submitted payee=%s tx=%s duration=%s", payeeHex, txHash, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func downloadCAR(cli *http.Client, base *url.URL, cid, piecePath, authorization, outDir string, payDebug bool) (string, error) {
	u := *base
	u.Path = piecePath
	fullURL := u.String()
	if payDebug {
		payClientLog("paid GET %s (Authorization: Payment len=%d)", fullURL, len(authorization))
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authorization)
	res, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if payDebug {
		payClientLog("paid GET response status=%d for cid=%s", res.StatusCode, cid)
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if payDebug {
			payClientLog("paid GET error body (truncated): %s", truncateForLog(string(b), 512))
		}
		trimmed := strings.TrimSpace(string(b))
		var pd problemDetails
		if err := json.Unmarshal(b, &pd); err == nil && pd.Type != "" {
			msg := fmt.Sprintf("download %s failed: %s", cid, res.Status)
			if pd.Title != "" {
				msg += " - " + pd.Title
			}
			if pd.Detail != "" {
				msg += ": " + pd.Detail
			}
			msg += fmt.Sprintf(" (type=%s)", pd.Type)
			return "", errors.New(msg)
		}
		return "", fmt.Errorf("download %s failed: %s %s", cid, res.Status, trimmed)
	}
	outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, res.Body); err != nil {
		return "", err
	}
	return outPath, nil
}

func collectCIDs(flagCIDs []string, cidFile string, args []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	appendCID := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, c := range flagCIDs {
		for _, p := range strings.Split(c, ",") {
			appendCID(p)
		}
	}
	for _, c := range args {
		for _, p := range strings.Split(c, ",") {
			appendCID(p)
		}
	}
	if cidFile != "" {
		b, err := os.ReadFile(cidFile)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			for _, p := range strings.Split(line, ",") {
				appendCID(p)
			}
		}
	}
	return out, nil
}

func extractPieceCIDsFromManifest(manifestPath string) ([]string, error) {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", manifestPath, err)
	}

	var m struct {
		Pieces []struct {
			PieceCID string `json:"piece_cid"`
		} `json:"pieces"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %q: %w", manifestPath, err)
	}

	// Deduplicate while preserving order.
	seen := make(map[string]struct{}, len(m.Pieces))
	out := make([]string, 0, len(m.Pieces))
	for _, p := range m.Pieces {
		piece := strings.TrimSpace(p.PieceCID)
		if piece == "" {
			continue
		}
		if _, ok := seen[piece]; ok {
			continue
		}
		seen[piece] = struct{}{}
		out = append(out, piece)
	}
	return out, nil
}

func promptYesNo(prompt string) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func sumTokenValues(prices []string) (string, error) {
	var total float64
	for _, price := range prices {
		var x float64
		_, err := fmt.Sscanf(price, "%f", &x)
		if err != nil {
			return "0", fmt.Errorf("parse token value %q: %w", price, err)
		}
		total += x
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", total), "0"), "."), nil
}

func sanitizeFilename(v string) string {
	if v == "" {
		return "piece"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, v)
}

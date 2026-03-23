package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/x402"
)

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	r := &cobra.Command{
		Use:   "retrieval-client",
		Short: "Client CLI for minimal x402 retrieval flow",
	}
	r.AddCommand(cmdFetch())
	return r
}

func cmdFetch() *cobra.Command {
	var (
		spBaseURL string
		outDir    string
		cids      []string
		cidFile   string
		client    string
		yes       bool
		lotusBin  string
		expiresIn int
		verbose   bool
	)
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch multiple CIDs in two phases: quote (402) then paid retrieval",
		RunE: func(cmd *cobra.Command, args []string) error {
			allCIDs, err := collectCIDs(cids, cidFile, args)
			if err != nil {
				return err
			}
			if len(allCIDs) == 0 {
				return errors.New("provide at least one CID via args, --cid, or --cid-file")
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			base, err := url.Parse(strings.TrimSpace(spBaseURL))
			if err != nil {
				return fmt.Errorf("invalid --sp-base-url: %w", err)
			}
			cli := &http.Client{Timeout: 120 * time.Second}

			type quoteItem struct {
				CID      string
				DealUUID string
				PriceFIL string
			}
			items := make([]quoteItem, 0, len(allCIDs))
			if verbose {
				fmt.Printf("Step 1/%d: fetching quotes for %d CID(s)\n", 2, len(allCIDs))
			}

			for _, cid := range allCIDs {
				if verbose {
					fmt.Printf("  - requesting quote for CID %s\n", cid)
				}
				q, err := requestQuote(cli, base, cid, client)
				if err != nil {
					return fmt.Errorf("dataset incomplete: quote request failed for CID %s: %w", cid, err)
				}
				if verbose {
					fmt.Printf("    received quote: CID %s costs %s FIL (deal %s)\n", cid, q.PriceFIL, q.DealUUID)
				}
				items = append(items, quoteItem{CID: cid, DealUUID: q.DealUUID, PriceFIL: q.PriceFIL})
			}

			var prices []string
			for _, it := range items {
				prices = append(prices, it.PriceFIL)
			}
			total := sumFILValues(prices)
			fmt.Printf("Total required amount: %s FIL for %d piece(s).\n", total, len(items))
			if !yes {
				ok, err := promptYesNo("Proceed with payment headers and download? [y/N]: ")
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}
			if verbose {
				fmt.Printf("Step 2/%d: fetching paid pieces for %d CID(s)\n", 2, len(items))
			}

			for _, it := range items {
				piecePath := "/piece/" + it.CID
				if verbose {
					fmt.Printf("  - creating payment header for CID %s (deal %s)\n", it.CID, it.DealUUID)
				}
				h := &x402.PaymentHeader{
					DealUUID:      it.DealUUID,
					ClientAddress: client,
					CID:           it.CID,
					Method:        http.MethodGet,
					Path:          piecePath,
					Host:          base.Host,
					Nonce:         uuid.NewString(),
					ExpiresUnix:   time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
					SigType:       "lotus",
				}
				signer := x402.LotusSigner{Binary: lotusBin}
				sigType, sig, err := signer.Sign(client, h.CanonicalMessage())
				if err != nil {
					return err
				}
				h.SigType = sigType
				h.Signature = sig
				raw, err := h.EncodeHTTP()
				if err != nil {
					return err
				}
				outPath, err := downloadCAR(cli, base, it.CID, piecePath, raw, outDir)
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
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "http://127.0.0.1:8787", "SP proxy base URL")
	c.Flags().StringVar(&outDir, "out-dir", ".", "Output directory")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to fetch (repeatable)")
	c.Flags().StringVar(&cidFile, "cid-file", "", "File with CIDs (newline or comma separated)")
	c.Flags().StringVar(&client, "client", "", "Client Filecoin wallet address (must match signer)")
	c.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	c.Flags().StringVar(&lotusBin, "lotus-binary", "lotus", "Lotus binary used for wallet signing")
	c.Flags().IntVar(&expiresIn, "expires-in-sec", 120, "Header expiry interval in seconds")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print detailed per-step progress output")
	_ = c.MarkFlagRequired("client")
	return c
}

func requestQuote(cli *http.Client, base *url.URL, cid, client string) (*x402.QuoteResponse, error) {
	u := *base
	u.Path = "/piece/" + cid
	q := u.Query()
	q.Set("client", client)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		return nil, fmt.Errorf("expected 402 got %d", res.StatusCode)
	}
	var payload struct {
		X402 x402.QuoteResponse `json:"x402"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.X402.DealUUID == "" || payload.X402.PriceFIL == "" {
		return nil, errors.New("invalid quote payload")
	}
	return &payload.X402, nil
}

func downloadCAR(cli *http.Client, base *url.URL, cid, piecePath, paymentHeader, outDir string) (string, error) {
	u := *base
	u.Path = piecePath
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(x402.HeaderName, paymentHeader)
	res, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return "", fmt.Errorf("download %s failed: %s %s", cid, res.Status, strings.TrimSpace(string(b)))
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

func sumFILValues(prices []string) string {
	// Keep it simple for first commit: decimal string math with fixed precision is
	// overkill here; prices are expected to be uniform and human-readable.
	var total float64
	for _, price := range prices {
		var x float64
		fmt.Sscanf(price, "%f", &x)
		total += x
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", total), "0"), ".")
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

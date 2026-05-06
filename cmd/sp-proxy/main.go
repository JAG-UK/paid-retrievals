package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/filpay"
	piecepayment "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

const MaxHeaderSize = 4096

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	var (
		listen       string
		dbPath       string
		priceFIL     string
		clientQuery  string
		clientHeader string
		maxSkewSec   int
		verbose      bool

		payRPCURL          string
		payPrivateKey      string
		payPrivateKeyFile  string
		payPrivateKeyEnv   string
		payPaymentsAddress string
		payPayeeAddress    string
		payDebug           bool
	)
	c := &cobra.Command{
		Use:   "sp-proxy",
		Short: "Internet-facing /piece/<cid> MPP challenge + paid retrieval (Filecoin Pay + EVM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := sqlitestore.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			ctx := context.Background()
			filTrace := payDebug || verbose
			fc, err := filpay.NewClient(ctx, payRPCURL, payPrivateKey, payPrivateKeyFile, payPrivateKeyEnv, payPaymentsAddress,
				filpay.WithPayLogging(logger, filTrace))
			if err != nil {
				return fmt.Errorf("filecoin pay: %w", err)
			}
			defer fc.Close()

			payee := strings.TrimSpace(payPayeeAddress)
			if payee == "" {
				payee = fc.SignerAddress().Hex()
			}
			if !common.IsHexAddress(payee) {
				return fmt.Errorf("invalid --pay-payee-address %q (use 0x… FVM address or leave empty to use settlement wallet)", payee)
			}

			svcConfig := piecepayment.Config{
				PriceFIL:     priceFIL,
				ClientQuery:  clientQuery,
				ClientHeader: clientHeader,
				MaxClockSkew: time.Duration(maxSkewSec) * time.Second,
				QuotePayee0x: payee,
				PayDebug:     filTrace,
				FilecoinPay:  fc,
				Logger:       logger,
				Store:        store,
			}
			svc := piecepayment.NewRetrievalService(svcConfig)

			pieceHandler := svc.PiecePaymentMiddleware(MaxHeaderSize)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authCtx, ok := piecepayment.PieceAuthFromContext(r.Context())
				if !ok {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				body := dummyCAR(authCtx.CID, authCtx.DealUUID)
				w.Header().Set("Content-Type", "application/vnd.ipld.car")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.car\"", authCtx.CID))
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			}))

			logger.Info("filecoin pay", "payments", fc.PaymentsAddress().Hex(), "payee_0x", payee, "settler", fc.SignerAddress().Hex(),
				"pay_debug_flag", payDebug, "filpay_trace", filTrace, "pay_http_trace", filTrace)

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.Debug("incoming request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				if r.Method != http.MethodGet {
					logger.Warn("method not allowed", "method", r.Method, "path", r.URL.Path)
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if r.URL.Path == "/health" {
					logger.Debug("health check")
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte("ok"))
					return
				}
				if strings.HasPrefix(r.URL.Path, "/piece/") {
					pieceHandler.ServeHTTP(w, r)
					return
				}
				http.NotFound(w, r)
			})

			logger.Info("sp-proxy listening", "listen", listen, "db", dbPath, "price_fil", priceFIL, "verbose", verbose)
			return http.ListenAndServe(listen, h)
		},
	}
	c.Flags().StringVar(&listen, "listen", ":8787", "Listen address")
	c.Flags().StringVar(&dbPath, "db", "./sp-proxy.db", "SQLite deals database path")
	c.Flags().StringVar(&priceFIL, "price-fil", "0.01", "Challenge price (FIL) per requested CID")
	c.Flags().StringVar(&clientQuery, "client-query", "client", "Query key used to identify client on challenge requests")
	c.Flags().StringVar(&clientHeader, "client-header", "X-Client-Address", "Header key used to identify client on challenge requests")
	c.Flags().IntVar(&maxSkewSec, "max-clock-skew-sec", 30, "Allowed clock skew in seconds for header expiry")
	c.Flags().BoolVar(&verbose, "verbose", false, "Enable debug-level structured logs")

	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.calibration.node.glif.io/rpc/v1"), "Filecoin RPC (FVM) for payments contract")
	c.Flags().StringVar(&payPrivateKey, "pay-private-key", "", "Hex private key for settleRail txs (prefer env or file)")
	c.Flags().StringVar(&payPrivateKeyFile, "pay-private-key-file", "", "File containing hex private key for settleRail")
	c.Flags().StringVar(&payPrivateKeyEnv, "pay-private-key-env", getenv("SP_PROXY_PAY_PRIVATE_KEY_ENV", "SP_PROXY_PAY_PRIVATE_KEY"), "Env var for settleRail private key")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty = built-in address for chain")
	c.Flags().StringVar(&payPayeeAddress, "pay-payee-address", getenv("SP_PROXY_PAY_PAYEE_ADDRESS", ""), "FVM address clients should open/fund rails to; empty = settlement wallet address")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Log Filecoin Pay steps (HTTP + on-chain); Info level. Implied filpay trace; use with --verbose for more RPC detail")
	return c
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func dummyCAR(cid, deal string) []byte {
	// Placeholder payload for first-commit integration testing.
	return []byte("DUMMY-CAR\nCID=" + cid + "\nDEAL=" + deal + "\n")
}

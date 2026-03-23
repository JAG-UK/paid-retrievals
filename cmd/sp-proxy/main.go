package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/spproxy"
)

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
		verifyBinary string
		maxSkewSec   int
		verbose      bool
	)
	c := &cobra.Command{
		Use:   "sp-proxy",
		Short: "Internet-facing /piece/<cid> quote + paid retrieval service",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := spproxy.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			h := spproxy.NewHandler(spproxy.Config{
				PriceFIL:      priceFIL,
				ClientQuery:   clientQuery,
				ClientHeader:  clientHeader,
				MaxHeaderSize: 4096,
				MaxClockSkew:  time.Duration(maxSkewSec) * time.Second,
				VerifyBinary:  verifyBinary,
				Logger:        logger,
			}, store)

			logger.Info("sp-proxy listening", "listen", listen, "db", dbPath, "price_fil", priceFIL, "verbose", verbose)
			return http.ListenAndServe(listen, h)
		},
	}
	c.Flags().StringVar(&listen, "listen", ":8787", "Listen address")
	c.Flags().StringVar(&dbPath, "db", "./sp-proxy.db", "SQLite deals database path")
	c.Flags().StringVar(&priceFIL, "price-fil", "0.01", "Quoted price (FIL) per requested CID")
	c.Flags().StringVar(&clientQuery, "client-query", "client", "Query key used to identify client on quote requests")
	c.Flags().StringVar(&clientHeader, "client-header", "X-Client-Address", "Header key used to identify client on quote requests")
	c.Flags().StringVar(&verifyBinary, "lotus-binary", "lotus", "Lotus binary used for signature verification")
	c.Flags().IntVar(&maxSkewSec, "max-clock-skew-sec", 30, "Allowed clock skew in seconds for header expiry")
	c.Flags().BoolVar(&verbose, "verbose", false, "Enable debug-level structured logs")
	return c
}

package spproxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/fidlabs/paid-retrievals/internal/x402"
	"github.com/ethereum/go-ethereum/common"
)

var cidPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,256}$`)

type Config struct {
	PriceFIL      string
	ClientQuery   string
	ClientHeader  string
	MaxHeaderSize int
	MaxClockSkew  time.Duration
	Logger        *slog.Logger

	// FilecoinPay (native FIL) is required: quotes include payee_0x; paid downloads require EVM-signed x402 + on-chain settleRail.
	FilecoinPay  FilecoinPaySettler
	QuotePayee0x string
	// PayDebug emits extra Info-level logs for Filecoin Pay (HTTP + use with filpay --pay-debug on settler).
	PayDebug bool
}

func NewHandler(cfg Config, store *Store) http.Handler {
	if cfg.PriceFIL == "" {
		cfg.PriceFIL = "0.01"
	}
	if cfg.ClientQuery == "" {
		cfg.ClientQuery = "client"
	}
	if cfg.ClientHeader == "" {
		cfg.ClientHeader = "X-Client-Address"
	}
	if cfg.MaxHeaderSize <= 0 {
		cfg.MaxHeaderSize = 4096
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	if cfg.FilecoinPay == nil {
		panic("spproxy: Config.FilecoinPay is required")
	}
	payee := strings.TrimSpace(cfg.QuotePayee0x)
	if payee == "" || !common.IsHexAddress(payee) {
		panic("spproxy: Config.QuotePayee0x must be a non-empty 0x FVM address")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		cid, ok := parsePiecePath(r.URL.Path)
		if !ok {
			logger.Warn("invalid piece path", "path", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		rawHdr := strings.TrimSpace(r.Header.Get(x402.HeaderName))
		if rawHdr == "" {
			handleQuote(w, r, store, cfg, cid, logger)
			return
		}
		if len(rawHdr) > cfg.MaxHeaderSize {
			logger.Warn("payment header too large", "path", r.URL.Path, "size", len(rawHdr), "max", cfg.MaxHeaderSize)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		handlePaid(w, r, store, cfg, cid, rawHdr, logger)
	})
}

func parsePiecePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/piece/") {
		return "", false
	}
	cid := strings.TrimPrefix(path, "/piece/")
	if cid == "" || strings.Contains(cid, "/") || !cidPattern.MatchString(cid) {
		return "", false
	}
	return cid, true
}

func handleQuote(w http.ResponseWriter, r *http.Request, store *Store, cfg Config, cid string, logger *slog.Logger) {
	client := identifyClient(r, cfg)
	if !common.IsHexAddress(strings.TrimSpace(client)) {
		logger.Warn("bad request: client must be 0x FVM address", "client", client)
		http.Error(w, "bad request: client must be a 0x FVM address", http.StatusBadRequest)
		return
	}
	dealID := uuid.NewString()
	payee := strings.TrimSpace(cfg.QuotePayee0x)
	if err := store.InsertQuote(r.Context(), dealID, client, cid, cfg.PriceFIL, payee); err != nil {
		logger.Error("failed to insert quote", "error", err, "deal_uuid", dealID, "client", client, "cid", cid)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("quote created", "deal_uuid", dealID, "client", client, "cid", cid, "price_fil", cfg.PriceFIL)
	if cfg.PayDebug {
		logger.Info("filecoin pay quote", "scope", "filpay-http", "deal_uuid", dealID, "client_0x", client,
			"cid", cid, "price_fil", cfg.PriceFIL, "payee_0x", payee, "filecoin_pay", true)
	}

	resp := x402.QuoteResponse{DealUUID: dealID, CID: cid, PriceFIL: cfg.PriceFIL, Payee0x: payee}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"x402":            resp,
		"payment_header":  x402.HeaderName,
		"payment_required": true,
	})
}

func handlePaid(w http.ResponseWriter, r *http.Request, store *Store, cfg Config, cid, rawHdr string, logger *slog.Logger) {
	hdr, err := x402.DecodeHTTP(rawHdr)
	if err != nil {
		logger.Warn("forbidden: decode payment header", "error", err, "cid", cid, "path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	now := time.Now()
	if err := hdr.ValidateAt(now); err != nil {
		logger.Warn("forbidden: invalid header", "error", err, "deal_uuid", hdr.DealUUID, "cid", cid)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if hdr.ExpiresUnix > now.Add(10*time.Minute).Unix()+int64(cfg.MaxClockSkew.Seconds()) {
		logger.Warn("forbidden: expiry too far in future", "deal_uuid", hdr.DealUUID, "cid", cid, "expires_unix", hdr.ExpiresUnix)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if strings.ToUpper(hdr.Method) != http.MethodGet {
		logger.Warn("forbidden: bad method in header", "deal_uuid", hdr.DealUUID, "header_method", hdr.Method, "expected", http.MethodGet)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if hdr.Path != r.URL.Path {
		logger.Warn("forbidden: path mismatch", "deal_uuid", hdr.DealUUID, "header_path", hdr.Path, "request_path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !hostMatches(hdr.Host, r.Host) {
		logger.Warn("forbidden: host mismatch", "deal_uuid", hdr.DealUUID, "header_host", hdr.Host, "request_host", r.Host)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	deal, err := store.GetDeal(r.Context(), hdr.DealUUID)
	if err != nil {
		logger.Warn("forbidden: unknown deal", "deal_uuid", hdr.DealUUID, "error", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !sameHexAddress(hdr.ClientAddress, deal.Client) {
		logger.Warn("forbidden: client mismatch", "deal_uuid", hdr.DealUUID, "header_client", hdr.ClientAddress, "deal_client", deal.Client)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if deal.CID != cid {
		logger.Warn("forbidden: cid mismatch", "deal_uuid", hdr.DealUUID, "header_cid", cid, "deal_cid", deal.CID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if hdr.CID != "" && hdr.CID != cid {
		logger.Warn("forbidden: explicit header cid mismatch", "deal_uuid", hdr.DealUUID, "header_cid", hdr.CID, "request_cid", cid)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(hdr.SigType), x402.SigTypeEVM) {
		logger.Warn("forbidden: x402 signatures must be evm (secp256k1 / 0x client)", "deal_uuid", hdr.DealUUID, "sig_type", hdr.SigType)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	verifier := x402.EVMVerifier{}
	if err := verifier.Verify(hdr.ClientAddress, hdr.CanonicalMessage(), hdr.Signature); err != nil {
		logger.Warn("forbidden: signature verify failed", "deal_uuid", hdr.DealUUID, "client", hdr.ClientAddress, "error", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if cfg.PayDebug {
		logger.Info("filecoin pay x402 signature ok", "scope", "filpay-http", "deal_uuid", hdr.DealUUID,
			"sig_type", hdr.SigType, "client_0x", hdr.ClientAddress, "cid", cid)
	}
	if strings.TrimSpace(deal.Payee0x) == "" || !common.IsHexAddress(strings.TrimSpace(deal.Payee0x)) {
		logger.Error("internal: deal missing payee_0x", "deal_uuid", deal.DealUUID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	priceWei, err := paymentheader.ParseFILToWei(deal.PriceFIL)
	if err != nil {
		logger.Error("internal: bad price_fil on deal", "deal_uuid", deal.DealUUID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	payer := common.HexToAddress(strings.TrimSpace(deal.Client))
	payeeAddr := common.HexToAddress(strings.TrimSpace(deal.Payee0x))
	if cfg.PayDebug {
		logger.Info("filecoin pay calling SettleIfFunded", "scope", "filpay-http", "deal_uuid", hdr.DealUUID,
			"payer", payer.Hex(), "payee", payeeAddr.Hex(), "price_wei", priceWei.String(), "price_fil", deal.PriceFIL)
	}
	txHash, err := cfg.FilecoinPay.SettleIfFunded(r.Context(), payer, payeeAddr, priceWei)
	if err != nil {
		logger.Warn("payment required: filecoin pay settle failed", "deal_uuid", hdr.DealUUID, "error", err)
		http.Error(w, "payment required: filecoin pay rail or balance not satisfied", http.StatusPaymentRequired)
		return
	}
	logger.Info("filecoin pay rail settled", "deal_uuid", deal.DealUUID, "settle_tx", txHash, "payer", payer.Hex(), "payee", payeeAddr.Hex())
	if err := store.ConsumeNonce(r.Context(), deal.DealUUID, hdr.Nonce, hdr.ExpiresUnix); err != nil {
		if err == ErrReplayNonce {
			logger.Warn("forbidden: replay nonce", "deal_uuid", deal.DealUUID, "nonce", hdr.Nonce)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		logger.Error("failed to consume nonce", "deal_uuid", deal.DealUUID, "nonce", hdr.Nonce, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := store.MarkPaid(r.Context(), deal.DealUUID); err != nil {
		logger.Error("failed to mark paid", "deal_uuid", deal.DealUUID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("paid retrieval authorized", "deal_uuid", deal.DealUUID, "client", deal.Client, "cid", cid)

	body := dummyCAR(cid, deal.DealUUID)
	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.car\"", cid))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func identifyClient(r *http.Request, cfg Config) string {
	if v := strings.TrimSpace(r.URL.Query().Get(cfg.ClientQuery)); v != "" {
		return sanitizeClient(v)
	}
	if v := strings.TrimSpace(r.Header.Get(cfg.ClientHeader)); v != "" {
		return sanitizeClient(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return sanitizeClient(r.RemoteAddr)
	}
	return sanitizeClient(host)
}

func sanitizeClient(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	if len(v) > 256 {
		v = v[:256]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.', r == ':', r == '@':
			return r
		default:
			return -1
		}
	}, v)
}

func hostMatches(hdrHost, reqHost string) bool {
	return strings.EqualFold(strings.TrimSpace(hdrHost), strings.TrimSpace(reqHost))
}

func dummyCAR(cid, deal string) []byte {
	// Placeholder payload for first-commit integration testing.
	return []byte("DUMMY-CAR\nCID=" + cid + "\nDEAL=" + deal + "\n")
}

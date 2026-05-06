package piecepayment

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

type pieceAuthContextKey struct{}

type PieceAuthContext struct {
	DealUUID string
	CID      string
	TxHash   string
}

func PieceAuthFromContext(ctx context.Context) (PieceAuthContext, bool) {
	v, ok := ctx.Value(pieceAuthContextKey{}).(PieceAuthContext)
	return v, ok
}

func (svc *RetrievalService) PiecePaymentMiddleware(MaxHeaderSize int) func(http.Handler) http.Handler {
	if svc == nil {
		panic("piecepayment: RetrievalService is required")
	}
	logger := svc.logger
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cid, ok := parsePiecePath(r.URL.Path)
			if !ok {
				http.NotFound(w, r)
				return
			}

			rawHdr := strings.TrimSpace(r.Header.Get("Authorization"))
			if rawHdr == "" {
				outcome, err := svc.IssueQuote(r, cid)
				if err != nil {
					var badReq *BadRequestError
					if errors.As(err, &badReq) {
						http.Error(w, badReq.Message, http.StatusBadRequest)
						return
					}
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if err := mpp.WritePaymentRequired(w, outcome.Challenge); err != nil {
					logger.Error("failed to write payment challenge", "deal_uuid", outcome.Challenge.ID, "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}
			if len(rawHdr) > MaxHeaderSize {
				logger.Warn("payment header too large", "path", r.URL.Path, "size", len(rawHdr), "max", MaxHeaderSize)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			outcome, err := svc.AuthorizeAndSettle(r, cid, rawHdr)
			if err != nil {
				var payErr *PaymentRequiredError
				if errors.As(err, &payErr) {
					failPaymentRequired(w, r, payErr.Deal, logger, payErr.Code, payErr.Detail)
					return
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(r.Context(), pieceAuthContextKey{}, PieceAuthContext{
				DealUUID: outcome.Deal.DealUUID,
				CID:      outcome.CID,
				TxHash:   outcome.TxHash,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

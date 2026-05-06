package piecepayment

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

var cidPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,256}$`)

const problemBase = "https://paymentauth.org/problems/"

type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func issueChallengeForDeal(w http.ResponseWriter, r *http.Request, deal *Deal, logger *slog.Logger) {
	if deal == nil {
		return
	}
	challenge := mpp.Challenge{
		ID:          deal.DealUUID,
		Realm:       mpp.RealmPrefix + r.Host,
		Method:      mpp.MethodID,
		Intent:      mpp.IntentID,
		Description: "Filecoin piece retrieval charge",
		Opaque: map[string]string{
			"deal_uuid": deal.DealUUID,
			"cid":       deal.CID,
		},
		Request: mpp.PaymentRequest{
			DealUUID: deal.DealUUID,
			CID:      deal.CID,
			PriceFIL: deal.PriceFIL,
			Payee0x:  deal.Payee0x,
			Method:   http.MethodGet,
			Path:     "/piece/" + deal.CID,
			Host:     r.Host,
		},
		Expires: time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339),
	}
	wa, err := challenge.WWWAuthenticateValue()
	if err != nil {
		logger.Warn("failed to write fresh challenge", "deal_uuid", deal.DealUUID, "error", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", wa)
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	title := "Payment Error"
	switch code {
	case "payment-required":
		title = "Payment Required"
	case "payment-insufficient":
		title = "Payment Insufficient"
	case "payment-expired":
		title = "Payment Expired"
	case "verification-failed":
		title = "Payment Verification Failed"
	case "method-unsupported":
		title = "Payment Method Unsupported"
	case "malformed-credential":
		title = "Malformed Payment Credential"
	case "invalid-challenge":
		title = "Invalid Payment Challenge"
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetail{
		Type:   problemBase + code,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

func failPaymentRequired(w http.ResponseWriter, r *http.Request, deal *Deal, logger *slog.Logger, code, detail string) {
	if deal != nil {
		issueChallengeForDeal(w, r, deal, logger)
	} else {
		w.Header().Set("WWW-Authenticate", mpp.AuthScheme+` realm="`+mpp.RealmPrefix+r.Host+`", method="`+mpp.MethodID+`", intent="`+mpp.IntentID+`"`)
	}
	writeProblem(w, http.StatusPaymentRequired, code, detail)
}

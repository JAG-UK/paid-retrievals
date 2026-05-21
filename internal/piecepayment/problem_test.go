package piecepayment

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteProblemTitles(t *testing.T) {
	codes := []string{
		"payment-required",
		"payment-insufficient",
		"payment-expired",
		"verification-failed",
		"method-unsupported",
		"malformed-credential",
		"invalid-challenge",
		"unknown-code",
	}
	for _, code := range codes {
		rec := httptest.NewRecorder()
		writeProblem(rec, 402, code, "detail for "+code)
		if rec.Code != 402 {
			t.Fatalf("%s status %d", code, rec.Code)
		}
		var p problemDetail
		if err := json.NewDecoder(rec.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
		if p.Type != problemBase+code || p.Status != 402 || p.Detail == "" {
			t.Fatalf("%s: %+v", code, p)
		}
		if p.Title == "" {
			t.Fatalf("%s empty title", code)
		}
	}
}

package x402

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestCanonicalMessageStable(t *testing.T) {
	h := &PaymentHeader{
		DealUUID:      "d1",
		ClientAddress: "f1client",
		CID:           "bafy123",
		Method:        "GET",
		Path:          "/piece/bafy123",
		Host:          "example.com",
		Nonce:         "n1",
		ExpiresUnix:   1700000000,
		SigType:       "lotus",
		Signature:     "abc",
	}
	m1 := string(h.CanonicalMessage())
	m2 := string(h.CanonicalMessage())
	if m1 != m2 {
		t.Fatalf("canonical message not stable")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	h := &PaymentHeader{
		DealUUID:      "d1",
		ClientAddress: "f1client",
		CID:           "bafy123",
		Method:        "GET",
		Path:          "/piece/bafy123",
		Host:          "example.com",
		Nonce:         "n1",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		SigType:       "lotus",
		Signature:     "abc",
	}
	raw, err := h.EncodeHTTP()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeHTTP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.DealUUID != h.DealUUID || d.ClientAddress != h.ClientAddress || d.CID != h.CID {
		t.Fatalf("decoded mismatch")
	}
}

func TestValidateAtExpired(t *testing.T) {
	h := &PaymentHeader{
		DealUUID:      "d1",
		ClientAddress: "f1client",
		CID:           "bafy123",
		Method:        "GET",
		Path:          "/piece/bafy123",
		Host:          "example.com",
		Nonce:         "n1",
		ExpiresUnix:   time.Now().Add(-time.Second).Unix(),
		SigType:       "lotus",
		Signature:     "abc",
	}
	if err := h.ValidateAt(time.Now()); err == nil {
		t.Fatalf("expected expiry failure")
	}
}

func TestDecodeHTTPBadInput(t *testing.T) {
	if _, err := DecodeHTTP(base64.StdEncoding.EncodeToString([]byte("{"))); err == nil {
		t.Fatalf("expected decode error")
	}
}

package spproxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/x402"
)

type mockVerifier struct{ ok bool }

func (m mockVerifier) Verify(clientAddr string, msg []byte, signature string) error {
	if m.ok {
		return nil
	}
	return os.ErrPermission
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQuoteThenPaidSuccess(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := NewHandler(Config{PriceFIL: "0.1", Verifier: mockVerifier{ok: true}}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	client := "f1abc"
	quoteReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyquote?client="+client, nil)
	quoteRes, err := http.DefaultClient.Do(quoteReq)
	if err != nil {
		t.Fatal(err)
	}
	defer quoteRes.Body.Close()
	if quoteRes.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 got %d", quoteRes.StatusCode)
	}
	var payload struct {
		X402 x402.QuoteResponse `json:"x402"`
	}
	if err := json.NewDecoder(quoteRes.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	hdr := &x402.PaymentHeader{
		DealUUID:      payload.X402.DealUUID,
		ClientAddress: client,
		CID:           "bafyquote",
		Method:        http.MethodGet,
		Path:          "/piece/bafyquote",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-1",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		SigType:       "lotus",
		Signature:     "sig",
	}
	raw, _ := hdr.EncodeHTTP()
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyquote", nil)
	paidReq.Header.Set(x402.HeaderName, raw)
	paidRes, err := http.DefaultClient.Do(paidReq)
	if err != nil {
		t.Fatal(err)
	}
	defer paidRes.Body.Close()
	if paidRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", paidRes.StatusCode)
	}
}

func TestTamperedCIDRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := NewHandler(Config{PriceFIL: "0.1", Verifier: mockVerifier{ok: true}}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	client := "f1abc"
	qres, err := http.Get(ts.URL + "/piece/bafyone1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	var payload struct {
		X402 x402.QuoteResponse `json:"x402"`
	}
	_ = json.NewDecoder(qres.Body).Decode(&payload)

	hdr := map[string]any{
		"deal_uuid":    payload.X402.DealUUID,
		"client":       client,
		"cid":          "bafyone1",
		"method":       "GET",
		"path":         "/piece/bafytwo2",
		"host":         mustHostFromURL(t, ts.URL),
		"nonce":        "n-2",
		"expires_unix": time.Now().Add(time.Minute).Unix(),
		"sig_type":     "lotus",
		"sig":          "sig",
	}
	b, _ := json.Marshal(hdr)
	raw := base64.StdEncoding.EncodeToString(b)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafytwo2", nil)
	req.Header.Set(x402.HeaderName, raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", res.StatusCode)
	}
}

func TestReplayNonceRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := NewHandler(Config{PriceFIL: "0.1", Verifier: mockVerifier{ok: true}}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	client := "f1abc"
	qres, err := http.Get(ts.URL + "/piece/bafyrepl1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	var payload struct {
		X402 x402.QuoteResponse `json:"x402"`
	}
	_ = json.NewDecoder(qres.Body).Decode(&payload)

	hdr := &x402.PaymentHeader{
		DealUUID:      payload.X402.DealUUID,
		ClientAddress: client,
		CID:           "bafyrepl1",
		Method:        http.MethodGet,
		Path:          "/piece/bafyrepl1",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "same-nonce",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		SigType:       "lotus",
		Signature:     "sig",
	}
	raw, _ := hdr.EncodeHTTP()

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req1.Header.Set(x402.HeaderName, raw)
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req2.Header.Set(x402.HeaderName, raw)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected replay 403 got %d", res2.StatusCode)
	}
}

func mustHostFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

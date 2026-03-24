package spproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/fidlabs/paid-retrievals/internal/x402"
)

const testQuotePayee0x = "0x2222222222222222222222222222222222222222"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustHostFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

type mockPaySettler struct {
	called int
}

func (m *mockPaySettler) SettleIfFunded(ctx context.Context, payer, payee common.Address, priceWei *big.Int) (string, error) {
	m.called++
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", os.ErrInvalid
	}
	if priceWei.Sign() <= 0 {
		return "", os.ErrInvalid
	}
	return "0xsettle", nil
}

func TestQuoteThenPaidSuccess(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	cid := "bafyquote"
	quoteReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid+"?client="+client, nil)
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
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-1",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := x402.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw, _ := hdr.EncodeHTTP()
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	paidReq.Header.Set(x402.HeaderName, raw)
	paidRes, err := http.DefaultClient.Do(paidReq)
	if err != nil {
		t.Fatal(err)
	}
	defer paidRes.Body.Close()
	if paidRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", paidRes.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}
}

func TestTamperedCIDRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

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
		"sig_type":     x402.SigTypeEVM,
		"sig":          "00",
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

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

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
	}
	st, sig, err := x402.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
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

func TestFilecoinPayEVMSettleBeforeServe(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	dealID := uuid.NewString()
	cid := "bafyfpayevm1"
	if err := s.InsertQuote(context.Background(), dealID, client, cid, "0.01", testQuotePayee0x); err != nil {
		t.Fatal(err)
	}

	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.01",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	piecePath := "/piece/" + cid
	hdr := &x402.PaymentHeader{
		DealUUID:      dealID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          piecePath,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-filpay",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := x402.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw, err := hdr.EncodeHTTP()
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+piecePath, nil)
	req.Header.Set(x402.HeaderName, raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}
}

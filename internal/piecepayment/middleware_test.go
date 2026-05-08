package piecepayment_test

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

const testQuotePayee0x = "0x2222222222222222222222222222222222222222"

func newTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "sp.db")
	s, err := sqlitestore.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestHandler(cfg pp.Config) http.Handler {
	if cfg.PriceFIL == "" {
		cfg.PriceFIL = "0.01"
	}
	if cfg.ClientQuery == "" {
		cfg.ClientQuery = "client"
	}
	if cfg.ClientHeader == "" {
		cfg.ClientHeader = "X-Client-Address"
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	svc := pp.NewRetrievalService(cfg)
	pieceHandler := svc.PiecePaymentMiddleware(4096)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte("DUMMY-CAR\nPATH=" + r.URL.Path + "\n")
		w.Header().Set("Content-Type", "application/vnd.ipld.car")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health" {
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
}

func mustHostFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func mustChallengeFromResponse(t *testing.T, res *http.Response) *mpp.Challenge {
	t.Helper()
	h := res.Header.Get("WWW-Authenticate")
	ch, err := mpp.ParseWWWAuthenticate(h)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func mustAuthorization(t *testing.T, ch mpp.Challenge, p *mpp.ProofPayload) string {
	t.Helper()
	cred, err := mpp.BuildCredential(ch, *p, p.ClientAddress)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cred.EncodeAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type mockPaySettler struct {
	called int
	fail   error
}

func (m *mockPaySettler) SettleIfFunded(ctx context.Context, payer, payee common.Address, priceWei *big.Int) (string, error) {
	m.called++
	if m.fail != nil {
		return "", m.fail
	}
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", os.ErrInvalid
	}
	if priceWei.Sign() <= 0 {
		return "", os.ErrInvalid
	}
	return "0xsettle", nil
}

func mustProblemType(t *testing.T, res *http.Response) string {
	t.Helper()
	var p struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Type == "" {
		t.Fatal("missing problem type")
	}
	return p.Type
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
	h := newTestHandler(pp.Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
		Store:        s,
	})
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
	challenge := mustChallengeFromResponse(t, quoteRes)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-1",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	paidReq.Header.Set("Authorization", raw)
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

func TestReplayNonceRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
		Store:        s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	qres, err := http.Get(ts.URL + "/piece/bafyrepl1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           "bafyrepl1",
		Method:        http.MethodGet,
		Path:          "/piece/bafyrepl1",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "same-nonce",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req1.Header.Set("Authorization", raw)
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req2.Header.Set("Authorization", raw)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected replay 402 got %d", res2.StatusCode)
	}
	pt := mustProblemType(t, res2)
	if pt != "https://paymentauth.org/problems/invalid-challenge" {
		t.Fatalf("expected invalid-challenge type, got %s", pt)
	}
}

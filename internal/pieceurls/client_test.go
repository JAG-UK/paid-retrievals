package pieceurls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewClientRequiresHTTP(t *testing.T) {
	if _, err := NewClient(nil).DiscoverPieceHTTPBases(context.Background(), "bafy1"); err == nil {
		t.Fatal("expected error for nil HTTP client")
	}
	if _, err := NewClient(nil).SelectBestPieceSource(context.Background(), "bafy", "0x1", t.TempDir(), nil, nil); err == nil {
		t.Fatal("expected error for nil HTTP client on select")
	}
}

func TestClientOptions(t *testing.T) {
	c := NewClient(&http.Client{},
		WithLotusRPC("http://lotus"),
		WithFilecoinToolsAPI("http://tools/api"),
		WithCIDContactBaseURL("http://cid"),
	)
	if c.LotusRPC != "http://lotus" || c.FilecoinToolsAPI != "http://tools/api" || c.CIDContactBaseURL != "http://cid" {
		t.Fatalf("opts: lotus=%q tools=%q cid=%q", c.LotusRPC, c.FilecoinToolsAPI, c.CIDContactBaseURL)
	}
}

func TestPackageFuncsDelegateToClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/piece/bafywrap" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	cli := srv.Client()
	if _, err := DiscoverPieceHTTPBases(context.Background(), cli, "", srv.URL); err == nil {
		t.Fatal("expected empty CID error")
	}
	sel, err := SelectBestPieceSource(context.Background(), cli,
		"bafkreieuudnwcbsdc4aknumlx2hkj3c5ipq5ixhb2gbi4n35phf4cara6i",
		"0x3333333333333333333333333333333333333333",
		t.TempDir(),
		[]*url.URL{mustParseURL(t, srv.URL)},
		nil,
	)
	if err != nil || !sel.Free {
		t.Fatalf("select wrapper: err=%v sel=%+v", err, sel)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

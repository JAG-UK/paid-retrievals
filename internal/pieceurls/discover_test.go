package pieceurls

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestNormalizeProviderID(t *testing.T) {
	if got := normalizeProviderID("f01234"); got != "f01234" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeProviderID("12345"); got != "f012345" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeProviderID(""); got != "" {
		t.Fatal("empty")
	}
	if got := normalizeProviderID("f0abc"); got != "" {
		t.Fatalf("non-numeric: %q", got)
	}
}

func TestWalkCollectAddrs(t *testing.T) {
	root := map[string]interface{}{
		"nested": map[string]interface{}{
			"Addrs": []interface{}{"/ip4/1.2.3.4/tcp/80/http", "  "},
		},
		"Addrs": []interface{}{"/dns/x/tcp/443/https"},
	}
	var out []string
	walkCollectAddrs(root, &out)
	if len(out) != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestDiscoverPieceHTTPBases_EmptyCID(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := discoveryTestClient(t, srv)
	if _, err := c.DiscoverPieceHTTPBases(context.Background(), "  "); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiscoverPieceHTTPBases_NoProviders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := discoveryTestClient(t, srv)
	bases, err := c.DiscoverPieceHTTPBases(context.Background(), "bafytest")
	if err != nil {
		t.Fatal(err)
	}
	if bases != nil {
		t.Fatalf("got %v", bases)
	}
}

func TestDiscoverPieceHTTPBases_ViaCIDContact(t *testing.T) {
	const peerID = "12D3KooWTestPeer"
	srv := httptest.NewServer(http.HandlerFunc(discoveryHandler(peerID, "")))
	defer srv.Close()
	c := discoveryTestClient(t, srv)

	bases, err := c.DiscoverPieceHTTPBases(context.Background(), "bafytestdiscover")
	if err != nil {
		t.Fatal(err)
	}
	if len(bases) != 1 {
		t.Fatalf("got %v", bases)
	}
	if bases[0].Host != "127.0.0.1:19999" {
		t.Fatalf("host %s", bases[0].Host)
	}
}

func TestDiscoverPieceHTTPBases_ViaLotusMultiaddrsFallback(t *testing.T) {
	maddr, err := ma.NewMultiaddr("/ip4/10.1.2.3/tcp/7070/http")
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(maddr.Bytes())

	srv := httptest.NewServer(http.HandlerFunc(discoveryHandler("", enc)))
	defer srv.Close()
	c := discoveryTestClient(t, srv)

	bases, err := c.DiscoverPieceHTTPBases(context.Background(), "bafytestlotus")
	if err != nil {
		t.Fatal(err)
	}
	if len(bases) != 1 || bases[0].Host != "10.1.2.3:7070" {
		t.Fatalf("got %+v", bases)
	}
}

func TestDiscoverPieceHTTPBases_SearchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search") {
			http.Error(w, "fail", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := discoveryTestClient(t, srv)
	if _, err := c.DiscoverPieceHTTPBases(context.Background(), "bafy"); err == nil {
		t.Fatal("expected search error")
	}
}

func TestDiscoverPieceHTTPBases_LotusEmptyRPC(t *testing.T) {
	c := NewClient(http.DefaultClient, WithLotusRPC(""))
	c.FilecoinToolsAPI = "http://unused"
	if _, err := c.resolveProviderHTTPBases(context.Background(), "f01234"); err == nil {
		t.Fatal("expected empty RPC error")
	}
}

func discoveryTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	return NewClient(srv.Client(),
		WithLotusRPC(srv.URL),
		WithFilecoinToolsAPI(srv.URL+"/api"),
		WithCIDContactBaseURL(srv.URL),
	)
}

func discoveryHandler(peerID string, lotusMultiaddrB64 string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"providerId":"12345"}]}`))
		case r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "Filecoin.StateMinerInfo") {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			res := map[string]interface{}{
				"result": map[string]interface{}{
					"PeerId":     peerID,
					"Multiaddrs": []string{lotusMultiaddrB64},
				},
			}
			_ = json.NewEncoder(w).Encode(res)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/providers/"):
			if peerID == "" {
				http.Error(w, "no peer", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Addrs": []string{"/ip4/127.0.0.1/tcp/19999/http"},
			})
		default:
			http.NotFound(w, r)
		}
	}
}

package pieceurls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestProbeHEADContentLength(t *testing.T) {
	const wantLen = 8192
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "want HEAD", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(wantLen))
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewClient(ts.Client())
	got := c.probeHEAD(context.Background(), ts.URL+"/piece/bafytest", nil)
	if got != int64(wantLen) {
		t.Fatalf("got %d want %d", got, wantLen)
	}
}

func TestProbeHEADNonOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := NewClient(ts.Client())
	if got := c.probeHEAD(context.Background(), ts.URL+"/piece/bafy", nil); got != -1 {
		t.Fatalf("got %d want -1", got)
	}
}

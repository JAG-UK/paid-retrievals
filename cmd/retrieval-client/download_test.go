package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type captureDownloadProgress struct {
	noopProgress
	headersTotal int64
}

func (captureDownloadProgress) Enabled() bool { return true }

func (c *captureDownloadProgress) DownloadHeaders(_ string, totalBytes int64) {
	c.headersTotal = totalBytes
}

func TestDownloadCARSuccess(t *testing.T) {
	const cid = "bafyDownloadOk"
	body := []byte("CAR-DATA-HERE")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Payment test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Length", "13")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	path, err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "Payment test", outDir, -1, noopProgress{}, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body %q", got)
	}
	if filepath.Base(path) != sanitizeFilename(cid)+".car" {
		t.Fatalf("path %s", path)
	}
}

func TestDownloadCARUsesProbeTotalWhenResponseHasNoLength(t *testing.T) {
	const cid = "bafyProbeTotal"
	const probeTotal = int64(8 << 30)
	body := []byte("car-chunk-data")
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	prog := &captureDownloadProgress{}
	_, err = downloadCAR(cli, base, cid, "/piece/"+cid, "", t.TempDir(), probeTotal, prog, false)
	if err != nil {
		t.Fatal(err)
	}
	if prog.headersTotal != probeTotal {
		t.Fatalf("headersTotal=%d want probe %d", prog.headersTotal, probeTotal)
	}
}

type roundTripNoContentLength []byte

func (b roundTripNoContentLength) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader(b)),
		Header:        make(http.Header),
		ContentLength: -1,
		Request:       req,
	}, nil
}

func TestDownloadCARReportsContentLengthHeader(t *testing.T) {
	const cid = "bafyDownloadLen"
	const wantLen = int64(1 << 20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, wantLen))
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	prog := &captureDownloadProgress{}
	_, err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", t.TempDir(), 99, prog, false)
	if err != nil {
		t.Fatal(err)
	}
	if prog.headersTotal != wantLen {
		t.Fatalf("headersTotal=%d want GET Content-Length %d", prog.headersTotal, wantLen)
	}
}

func TestDownloadCARPlainErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer ts.Close()
	base, _ := url.Parse(ts.URL)
	_, err := downloadCAR(http.DefaultClient, base, "bafy1", "/piece/bafy1", "", t.TempDir(), -1, noopProgress{}, false)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("got %v", err)
	}
}

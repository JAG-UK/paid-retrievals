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
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "Payment test", outDir, -1, noopProgress{}, true)
	if err != nil {
		t.Fatal(err)
	}
	carPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	got, err := os.ReadFile(carPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body %q", got)
	}
	if filepath.Base(carPath) != sanitizeFilename(cid)+".car" {
		t.Fatalf("path %s", carPath)
	}
}

func TestDownloadCARUsesProbeTotalWhenResponseHasNoLength(t *testing.T) {
	const cid = "bafyProbeTotal"
	body := []byte("car-chunk-data")
	probeTotal := int64(len(body))
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	prog := &captureDownloadProgress{}
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", t.TempDir(), probeTotal, prog, false)
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
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", t.TempDir(), 99, prog, false)
	if err != nil {
		t.Fatal(err)
	}
	if prog.headersTotal != wantLen {
		t.Fatalf("headersTotal=%d want GET Content-Length %d", prog.headersTotal, wantLen)
	}
}

func TestGetShortOfExpectedSize(t *testing.T) {
	if getShortOfExpectedSize(100, -1) {
		t.Fatal("unknown probe HEAD size should not count as short GET")
	}
	if getShortOfExpectedSize(100, 100) {
		t.Fatal("full GET should not be short")
	}
	if !getShortOfExpectedSize(10, 100) {
		t.Fatal("expected short GET vs probe HEAD")
	}
}

func TestDownloadCARWarnsWhenGETShortOfProbeHEAD(t *testing.T) {
	const cid = "bafyIncomplete"
	const probeTotal = int64(1024)
	body := []byte("short")
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	outDir := t.TempDir()
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", outDir, probeTotal, noopProgress{}, false)
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car")); err == nil {
		t.Fatal("incomplete file should not be committed")
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car.partial")); !os.IsNotExist(err) {
		t.Fatal("partial path should be removed")
	}
}

func TestDownloadCARPlainErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer ts.Close()
	base, _ := url.Parse(ts.URL)
	err := downloadCAR(http.DefaultClient, base, "bafy1", "/piece/bafy1", "", t.TempDir(), -1, noopProgress{}, false)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("got %v", err)
	}
}

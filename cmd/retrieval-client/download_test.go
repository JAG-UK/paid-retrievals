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
	"sync/atomic"
	"testing"
	"time"
)

type captureDownloadProgress struct {
	noopProgress
	headersTotal int64
}

func (captureDownloadProgress) Enabled() bool { return true }

func (c *captureDownloadProgress) DownloadHeaders(_ string, totalBytes int64) {
	c.headersTotal = totalBytes
}

func withDownloadRetryConfig(t *testing.T, attempts int, delay time.Duration) {
	t.Helper()
	prevAttempts := downloadMaxAttempts
	prevDelay := downloadRetryDelay
	downloadMaxAttempts = attempts
	downloadRetryDelay = delay
	t.Cleanup(func() {
		downloadMaxAttempts = prevAttempts
		downloadRetryDelay = prevDelay
	})
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
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "Payment test", outDir, -1, noopProgress{}, true)
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
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", "", t.TempDir(), probeTotal, prog, false)
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
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", t.TempDir(), 99, prog, false)
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

func TestDownloadCARRetriesWhenGETShortOfProbeHEAD(t *testing.T) {
	withDownloadRetryConfig(t, 3, 1*time.Millisecond)

	const cid = "bafyIncomplete"
	const probeTotal = int64(1024)
	body := []byte("short")
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	outDir := t.TempDir()
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", "", outDir, probeTotal, noopProgress{}, false)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v, want incomplete error", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car")); err == nil {
		t.Fatal("incomplete file should not be committed")
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car.partial")); !os.IsNotExist(err) {
		t.Fatal("partial path should be removed")
	}
}

func TestDownloadCARRetriesIncompleteThenSucceeds(t *testing.T) {
	const cid = "bafyRetryShort"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Length", "13")
		w.WriteHeader(http.StatusOK)
		if n < 3 {
			_, _ = w.Write(full[:3])
			return
		}
		_, _ = w.Write(full)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d want 3", got)
	}
}

func TestDownloadCARRetriesWithRangeResume(t *testing.T) {
	const cid = "bafyRangeResume"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			if got := r.Header.Get("Range"); got != "" {
				t.Fatalf("first attempt should not send Range, got %q", got)
			}
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:3])
		case 2:
			if got := r.Header.Get("Range"); got != "bytes=3-" {
				t.Fatalf("second attempt should resume with range bytes=3-, got %q", got)
			}
			remain := full[3:]
			w.Header().Set("Content-Length", "10")
			w.Header().Set("Content-Range", "bytes 3-12/13")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(remain)
		default:
			t.Fatalf("unexpected extra attempt %d", n)
		}
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("hits=%d want 2", got)
	}
	got, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Fatalf("resumed body %q", got)
	}
}

func TestDownloadCARContentRangeMismatchRestartsFromZero(t *testing.T) {
	const cid = "bafyRangeMismatch"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:3])
		case 2:
			if got := r.Header.Get("Range"); got != "bytes=3-" {
				t.Fatalf("second attempt range=%q", got)
			}
			// Mismatched Content-Range: claims to start at 0 while body is the full object.
			w.Header().Set("Content-Length", "13")
			w.Header().Set("Content-Range", "bytes 0-12/13")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(full)
		default:
			t.Fatalf("unexpected extra attempt %d", n)
		}
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("hits=%d want 2", got)
	}
	got, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Fatalf("body %q", got)
	}
}

func TestDownloadCARPlainErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer ts.Close()
	base, _ := url.Parse(ts.URL)
	err := downloadCAR(http.DefaultClient, base, "bafy1", "/piece/bafy1", "", "", t.TempDir(), -1, noopProgress{}, false)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("got %v", err)
	}
}

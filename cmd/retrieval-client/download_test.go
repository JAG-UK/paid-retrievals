package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadCARSuccess(t *testing.T) {
	const cid = "bafyDownloadOk"
	body := []byte("CAR-DATA-HERE")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Payment test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	path, err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "Payment test", outDir, true)
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

func TestDownloadCARPlainErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer ts.Close()
	base, _ := url.Parse(ts.URL)
	_, err := downloadCAR(http.DefaultClient, base, "bafy1", "/piece/bafy1", "", t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("got %v", err)
	}
}

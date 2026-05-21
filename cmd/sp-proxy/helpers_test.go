package main

import "testing"

func TestGetenv(t *testing.T) {
	const key = "SP_PROXY_TEST_GETENV"
	t.Setenv(key, "  from-env  ")
	if got := getenv(key, "fallback"); got != "from-env" {
		t.Fatalf("got %q", got)
	}
	t.Setenv(key, "")
	if got := getenv(key, "fallback"); got != "fallback" {
		t.Fatalf("empty env: got %q", got)
	}
}

func TestMustParsePort(t *testing.T) {
	if mustParsePort("9090") != 9090 {
		t.Fatal("9090")
	}
	if mustParsePort(" 8789 ") != 8789 {
		t.Fatal("trimmed")
	}
	if mustParsePort("not-a-port") != 8788 {
		t.Fatal("invalid defaults to 8788")
	}
}

func restoreProxyHooks(t *testing.T) func() {
	t.Helper()
	prevOpen := proxyOpenStore
	prevFilpay := proxyNewFilpayClient
	prevListen := proxyListenAndServe
	return func() {
		proxyOpenStore = prevOpen
		proxyNewFilpayClient = prevFilpay
		proxyListenAndServe = prevListen
	}
}

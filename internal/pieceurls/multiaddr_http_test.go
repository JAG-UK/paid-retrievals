package pieceurls

import (
	"encoding/base64"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestHTTPBaseFromMultiaddrString(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"", ""},
		{"/ip4/127.0.0.1/tcp/8787/http", "http://127.0.0.1:8787"},
		{"/ip4/10.0.0.2/tcp/443/https", "https://10.0.0.2:443"},
		{"/dns/sp.example.com/tcp/8080/http", "http://sp.example.com:8080"},
		{"/dns/host/tcp/443/https/", "https://host:443"},
		{"/ip6/::1/tcp/80/http", ""},
		{"not-a-multiaddr", ""},
	}
	for _, tc := range tests {
		if got := HTTPBaseFromMultiaddrString(tc.addr); got != tc.want {
			t.Fatalf("HTTPBaseFromMultiaddrString(%q) = %q want %q", tc.addr, got, tc.want)
		}
	}
}

func TestHTTPBasesFromLotusMultiaddrsBase64(t *testing.T) {
	if got := HTTPBasesFromLotusMultiaddrsBase64(nil); len(got) != 0 {
		t.Fatal("nil")
	}
	raw, err := ma.NewMultiaddr("/ip4/192.168.1.1/tcp/9999/http")
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(raw.Bytes())
	bases := HTTPBasesFromLotusMultiaddrsBase64([]string{enc, enc, "not-base64", ""})
	if len(bases) != 1 || bases[0] != "http://192.168.1.1:9999" {
		t.Fatalf("got %v", bases)
	}
}

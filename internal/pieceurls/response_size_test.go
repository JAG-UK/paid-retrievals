package pieceurls

import (
	"net/http"
	"testing"
)

func TestResponseTotalBytes(t *testing.T) {
	t.Run("contentLength field", func(t *testing.T) {
		res := &http.Response{ContentLength: 42}
		if got := ResponseTotalBytes(res); got != 42 {
			t.Fatalf("got %d", got)
		}
	})

	t.Run("header when contentLength unknown", func(t *testing.T) {
		res := &http.Response{
			Header:        http.Header{"Content-Length": []string{"9876543210"}},
			ContentLength: -1,
		}
		if got := ResponseTotalBytes(res); got != 9876543210 {
			t.Fatalf("got %d", got)
		}
	})

	t.Run("missing", func(t *testing.T) {
		res := &http.Response{ContentLength: -1}
		if got := ResponseTotalBytes(res); got != -1 {
			t.Fatalf("got %d", got)
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		res := &http.Response{
			Header:        http.Header{"Content-Length": []string{"not-a-number"}},
			ContentLength: -1,
		}
		if got := ResponseTotalBytes(res); got != -1 {
			t.Fatalf("got %d", got)
		}
	})
}

package pieceurls

import (
	"net/http"
	"strconv"
	"strings"
)

// ResponseTotalBytes returns the response body size when known, or -1.
// res.ContentLength is often -1 for chunked transfers even when Content-Length was sent.
func ResponseTotalBytes(res *http.Response) int64 {
	if res.ContentLength >= 0 {
		return res.ContentLength
	}
	cl := strings.TrimSpace(res.Header.Get("Content-Length"))
	if cl == "" {
		return -1
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

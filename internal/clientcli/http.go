package clientcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
)

// FetchQuote calls an optional market HTTP endpoint for a structured quote.
func FetchQuote(marketURL string, pieces []string, spAddress string) (*paymentheader.QuoteResponse, error) {
	body, err := json.Marshal(map[string]any{
		"pieces":     pieces,
		"sp_address": spAddress,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, marketURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 30 * time.Second}
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("market %s: %s", res.Status, string(raw))
	}
	var q paymentheader.QuoteResponse
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, err
	}
	return &q, nil
}

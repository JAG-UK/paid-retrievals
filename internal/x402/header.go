package x402

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const HeaderName = "X-Payment-Header"

var ErrInvalidHeader = errors.New("invalid x402 payment header")

type PaymentHeader struct {
	DealUUID      string `json:"deal_uuid"`
	ClientAddress string `json:"client"`
	CID           string `json:"cid"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Host          string `json:"host"`
	Nonce         string `json:"nonce"`
	ExpiresUnix   int64  `json:"expires_unix"`
	SigType       string `json:"sig_type"`
	Signature     string `json:"sig"`
}

func (h *PaymentHeader) Validate() error {
	if h.DealUUID == "" || h.ClientAddress == "" || h.CID == "" {
		return ErrInvalidHeader
	}
	if h.Method == "" || h.Path == "" || h.Host == "" || h.Nonce == "" || h.SigType == "" || h.Signature == "" {
		return ErrInvalidHeader
	}
	if h.ExpiresUnix <= 0 {
		return ErrInvalidHeader
	}
	if strings.ContainsAny(h.DealUUID, "\n\r\t") || strings.ContainsAny(h.ClientAddress, "\n\r\t") {
		return ErrInvalidHeader
	}
	if strings.ContainsAny(h.CID, "\n\r\t") || strings.ContainsAny(h.Method, "\n\r\t") || strings.ContainsAny(h.Path, "\n\r\t") {
		return ErrInvalidHeader
	}
	if strings.ContainsAny(h.Host, "\n\r\t") || strings.ContainsAny(h.Nonce, "\n\r\t") || strings.ContainsAny(h.SigType, "\n\r\t") {
		return ErrInvalidHeader
	}
	return nil
}

func (h *PaymentHeader) ValidateAt(now time.Time) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if now.Unix() > h.ExpiresUnix {
		return fmt.Errorf("%w: expired", ErrInvalidHeader)
	}
	return nil
}

func (h *PaymentHeader) CanonicalMessage() []byte {
	var b bytes.Buffer
	b.WriteString("x402-v1\n")
	b.WriteString("deal_uuid=" + h.DealUUID + "\n")
	b.WriteString("cid=" + h.CID + "\n")
	b.WriteString("client=" + strings.ToLower(h.ClientAddress) + "\n")
	b.WriteString("method=" + strings.ToUpper(h.Method) + "\n")
	b.WriteString("path=" + h.Path + "\n")
	b.WriteString("host=" + strings.ToLower(h.Host) + "\n")
	b.WriteString("nonce=" + h.Nonce + "\n")
	b.WriteString(fmt.Sprintf("expires_unix=%d\n", h.ExpiresUnix))
	return b.Bytes()
}

func (h *PaymentHeader) EncodeHTTP() (string, error) {
	if err := h.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func DecodeHTTP(raw string) (*PaymentHeader, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidHeader
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: base64", ErrInvalidHeader)
	}
	var h PaymentHeader
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("%w: json", ErrInvalidHeader)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

type QuoteResponse struct {
	DealUUID string `json:"deal_uuid"`
	CID      string `json:"cid"`
	PriceFIL string `json:"price_fil"`
}

// Package paymentheader defines the X-Payment-Header wire format and
// Ethereum-style signatures over a canonical payload. Production should align
// this with Filecoin Pay rail IDs, deal objects, and preferred signature
// schemes (e.g. FVM / delegated signatures).
package paymentheader

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// HeaderName is the HTTP header carrying a base64-encoded JSON PaymentHeader.
	HeaderName = "X-Payment-Header"
	// Version is the current wire format version.
	Version = 1
)

// PaymentHeader proves a client funded a rail for a specific deal and authorizes
// a single logical retrieval attempt identified by RequestID (nonce).
type PaymentHeader struct {
	Version       int      `json:"v"`
	DealID        string   `json:"deal_id"`
	RailID        string   `json:"rail_id"`
	RequestID     string   `json:"request_id"`
	Pieces        []string `json:"pieces"`
	AmountWei     string   `json:"amount_wei"` // decimal string; matches on-chain uint256
	DeadlineUnix  int64    `json:"deadline_unix"`
	ClientAddress string   `json:"client"` // 0x-prefixed hex checksummed EVM address (skeleton)
	Signature     string   `json:"sig"`      // 0x-prefixed hex: sign(keccak256(canonical))
}

var (
	ErrInvalidHeader   = errors.New("invalid payment header")
	ErrSignatureMismatch = errors.New("signature does not match client address")
	ErrExpired         = errors.New("payment header expired")
)

// CanonicalHash returns keccak256 over a deterministic encoding of the fields
// that must be covered by the signature (excluding Signature itself).
func (p *PaymentHeader) CanonicalHash() common.Hash {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", p.Version)
	fmt.Fprintf(&b, "%s\n", p.DealID)
	fmt.Fprintf(&b, "%s\n", p.RailID)
	fmt.Fprintf(&b, "%s\n", p.RequestID)
	pieces := append([]string(nil), p.Pieces...)
	sort.Strings(pieces)
	for _, x := range pieces {
		fmt.Fprintf(&b, "%s\n", x)
	}
	fmt.Fprintf(&b, "%s\n", p.AmountWei)
	fmt.Fprintf(&b, "%d\n", p.DeadlineUnix)
	fmt.Fprintf(&b, "%s\n", strings.ToLower(p.ClientAddress))
	return crypto.Keccak256Hash([]byte(b.String()))
}

// Sign fills p.Signature using the given ECDSA private key. The caller must set
// all fields except Signature.
func (p *PaymentHeader) Sign(privateKeyHex string) error {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	p.ClientAddress = addr.Hex()

	hash := p.CanonicalHash()
	sig, err := crypto.Sign(hash.Bytes(), key)
	if err != nil {
		return err
	}
	p.Signature = common.Bytes2Hex(sig)
	return nil
}

// Verify checks expiry, parses addresses, and recovers the signer from the
// signature.
func (p *PaymentHeader) Verify(nowUnix int64) error {
	if p.Version != Version {
		return fmt.Errorf("%w: bad version", ErrInvalidHeader)
	}
	if p.RequestID == "" || p.DealID == "" || p.RailID == "" {
		return fmt.Errorf("%w: missing ids", ErrInvalidHeader)
	}
	if p.DeadlineUnix > 0 && nowUnix > p.DeadlineUnix {
		return ErrExpired
	}
	if _, ok := new(big.Int).SetString(p.AmountWei, 10); !ok || p.AmountWei == "" {
		return fmt.Errorf("%w: amount_wei", ErrInvalidHeader)
	}
	if !common.IsHexAddress(p.ClientAddress) {
		return fmt.Errorf("%w: client address", ErrInvalidHeader)
	}
	sig := common.FromHex(p.Signature)
	if len(sig) != 65 {
		return fmt.Errorf("%w: signature length", ErrInvalidHeader)
	}
	hash := p.CanonicalHash()
	// crypto.Ecrecover expects uncompressed sig; Sign returns 65-byte with recovery id
	pub, err := crypto.Ecrecover(hash.Bytes(), sig)
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return err
	}
	recovered := crypto.PubkeyToAddress(*pubKey)
	expected := common.HexToAddress(p.ClientAddress)
	if recovered != expected {
		return ErrSignatureMismatch
	}
	return nil
}

// EncodeHTTP serializes to base64(JSON) for the X-Payment-Header value.
func (p *PaymentHeader) EncodeHTTP() (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeHTTP parses X-Payment-Header.
func DecodeHTTP(s string) (*PaymentHeader, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrInvalidHeader
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrInvalidHeader, err)
	}
	var p PaymentHeader
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: json: %w", ErrInvalidHeader, err)
	}
	return &p, nil
}

// Summary is a compact human-readable line for logging (no secrets).
func (p *PaymentHeader) Summary() string {
	return fmt.Sprintf("deal=%s rail=%s req=%s pieces=%d", p.DealID, p.RailID, p.RequestID, len(p.Pieces))
}

// MustParseWei parses AmountWei for comparisons (skeleton helpers).
func (p *PaymentHeader) MustParseWei() *big.Int {
	v, ok := new(big.Int).SetString(p.AmountWei, 10)
	if !ok {
		return big.NewInt(0)
	}
	return v
}

// BuildQuoteFingerprint returns a stable string for a quote id (offline use).
func BuildQuoteFingerprint(dealHint string, pieces []string) string {
	var b bytes.Buffer
	b.WriteString(dealHint)
	b.WriteByte(0)
	sort.Strings(pieces)
	for _, x := range pieces {
		b.WriteString(x)
		b.WriteByte(0)
	}
	return crypto.Keccak256Hash(b.Bytes()).Hex()
}

// ParseFILToWei parses a decimal FIL string like "1.5" into wei (18 decimals).
func ParseFILToWei(fil string) (*big.Int, error) {
	fil = strings.TrimSpace(fil)
	if fil == "" {
		return nil, errors.New("empty amount")
	}
	parts := strings.SplitN(fil, ".", 2)
	whole := parts[0]
	if whole == "" {
		whole = "0"
	}
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	}
	if len(frac) > 18 {
		frac = frac[:18]
	}
	for len(frac) < 18 {
		frac += "0"
	}
	s := whole + frac
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("parse %q", fil)
	}
	return v, nil
}

// WeiString returns base-10 wei string.
func WeiString(w *big.Int) string {
	if w == nil {
		return "0"
	}
	return w.String()
}

// FormatFIL approximates FIL from wei for display (not for chain submission).
func FormatFIL(wei *big.Int) string {
	if wei == nil {
		return "0"
	}
	r := new(big.Rat).SetInt(wei)
	d := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	r.Quo(r, d)
	return r.FloatString(6)
}

// QuoteResponse is returned by the optional market quote HTTP API (skeleton).
type QuoteResponse struct {
	DealHint   string   `json:"deal_hint"`
	Pieces     []string `json:"pieces"`
	PriceWei   string   `json:"price_wei"`
	QuoteID    string   `json:"quote_id"`
	SPAddress  string   `json:"sp_address,omitempty"`
	ValidUntil int64    `json:"valid_until_unix,omitempty"`
}

// EstimateStubPriceWei is a local fallback when no market URL is configured:
// price_wei = perPieceWei * len(pieces).
func EstimateStubPriceWei(perPieceWei *big.Int, pieceCount int) *big.Int {
	if perPieceWei == nil {
		perPieceWei = big.NewInt(0)
	}
	return new(big.Int).Mul(perPieceWei, big.NewInt(int64(pieceCount)))
}

// ParsePerPieceWei parses wei from a flag like "1000000000000000" or "0.001" FIL.
func ParsePerPieceWei(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), nil
	}
	if strings.Contains(s, ".") {
		return ParseFILToWei(s)
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid wei: %q", s)
	}
	return v, nil
}

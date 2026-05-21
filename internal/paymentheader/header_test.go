package paymentheader

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func testPaymentHeader(t *testing.T) (*PaymentHeader, string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := common.Bytes2Hex(crypto.FromECDSA(key))
	ph := &PaymentHeader{
		Version:         Version,
		DealID:          "deal-1",
		RailID:          "rail-1",
		RequestID:       "req-1",
		Pieces:          []string{"bafy1", "bafy2"},
		AmountBaseUnits: "42",
		DeadlineUnix:    time.Now().Add(time.Hour).Unix(),
	}
	if err := ph.Sign(pk); err != nil {
		t.Fatal(err)
	}
	return ph, pk
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ph, _ := testPaymentHeader(t)
	if err := ph.Verify(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	s, err := ph.EncodeHTTP()
	if err != nil {
		t.Fatal(err)
	}
	ph2, err := DecodeHTTP(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := ph2.Verify(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}

func TestReplayDifferentCanonical(t *testing.T) {
	key, _ := crypto.GenerateKey()
	pk := common.Bytes2Hex(crypto.FromECDSA(key))
	ph := &PaymentHeader{
		Version:         Version,
		DealID:          "deal-1",
		RailID:          "rail-1",
		RequestID:       "req-1",
		Pieces:          []string{"a", "b"},
		AmountBaseUnits: "1",
		DeadlineUnix:    time.Now().Add(time.Hour).Unix(),
	}
	if err := ph.Sign(pk); err != nil {
		t.Fatal(err)
	}
	ph.Pieces = []string{"a", "c"}
	if err := ph.Verify(time.Now().Unix()); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestCanonicalHashPieceOrderStable(t *testing.T) {
	a := &PaymentHeader{
		Version: Version, DealID: "d", RailID: "r", RequestID: "q",
		Pieces: []string{"z", "a"}, AmountBaseUnits: "1", DeadlineUnix: 1, ClientAddress: "0x1",
	}
	b := &PaymentHeader{
		Version: Version, DealID: "d", RailID: "r", RequestID: "q",
		Pieces: []string{"a", "z"}, AmountBaseUnits: "1", DeadlineUnix: 1, ClientAddress: "0x1",
	}
	if a.CanonicalHash() != b.CanonicalHash() {
		t.Fatal("canonical hash should sort pieces")
	}
}

func TestSignBadPrivateKey(t *testing.T) {
	ph := &PaymentHeader{Version: Version, DealID: "d", RailID: "r", RequestID: "q", AmountBaseUnits: "1"}
	if err := ph.Sign("not-a-key"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestVerifyErrors(t *testing.T) {
	ph, _ := testPaymentHeader(t)
	now := time.Now().Unix()

	cases := []struct {
		name string
		mut  func(*PaymentHeader)
		want error
	}{
		{
			name: "bad version",
			mut:  func(p *PaymentHeader) { p.Version = 99 },
			want: ErrInvalidHeader,
		},
		{
			name: "missing request id",
			mut:  func(p *PaymentHeader) { p.RequestID = "" },
			want: ErrInvalidHeader,
		},
		{
			name: "missing deal id",
			mut:  func(p *PaymentHeader) { p.DealID = "" },
			want: ErrInvalidHeader,
		},
		{
			name: "expired",
			mut:  func(p *PaymentHeader) { p.DeadlineUnix = now - 10 },
			want: ErrExpired,
		},
		{
			name: "bad amount",
			mut:  func(p *PaymentHeader) { p.AmountBaseUnits = "not-a-number" },
			want: ErrInvalidHeader,
		},
		{
			name: "empty amount",
			mut:  func(p *PaymentHeader) { p.AmountBaseUnits = "" },
			want: ErrInvalidHeader,
		},
		{
			name: "bad client address",
			mut:  func(p *PaymentHeader) { p.ClientAddress = "not-an-address" },
			want: ErrInvalidHeader,
		},
		{
			name: "short signature",
			mut:  func(p *PaymentHeader) { p.Signature = "0x0102" },
			want: ErrInvalidHeader,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *ph
			tc.mut(&cp)
			err := cp.Verify(now)
			if err == nil || !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}

	t.Run("signature mismatch", func(t *testing.T) {
		cp := *ph
		cp.ClientAddress = "0x1111111111111111111111111111111111111111"
		if err := cp.Verify(now); !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestVerifyZeroDeadlineSkipsExpiry(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := common.Bytes2Hex(crypto.FromECDSA(key))
	ph := &PaymentHeader{
		Version: Version, DealID: "d", RailID: "r", RequestID: "q",
		Pieces: []string{"p1"}, AmountBaseUnits: "1", DeadlineUnix: 0,
	}
	if err := ph.Sign(pk); err != nil {
		t.Fatal(err)
	}
	if err := ph.Verify(time.Now().Add(24 * time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeHTTPErrors(t *testing.T) {
	if _, err := DecodeHTTP(""); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := DecodeHTTP("%%%"); err == nil {
		t.Fatal("expected base64 error")
	}
	if _, err := DecodeHTTP(base64.StdEncoding.EncodeToString([]byte("{"))); err == nil {
		t.Fatal("expected json error")
	}
}

func TestSummary(t *testing.T) {
	ph := &PaymentHeader{DealID: "d1", RailID: "r1", RequestID: "req", Pieces: []string{"a", "b", "c"}}
	got := ph.Summary()
	if !strings.Contains(got, "deal=d1") || !strings.Contains(got, "pieces=3") {
		t.Fatalf("got %q", got)
	}
}

func TestMustParseBaseUnits(t *testing.T) {
	ph := &PaymentHeader{AmountBaseUnits: "12345"}
	if ph.MustParseBaseUnits().Cmp(big.NewInt(12345)) != 0 {
		t.Fatal("expected 12345")
	}
	ph.AmountBaseUnits = "bad"
	if ph.MustParseBaseUnits().Sign() != 0 {
		t.Fatal("invalid should return 0")
	}
}

func TestBuildQuoteFingerprint(t *testing.T) {
	a := BuildQuoteFingerprint("deal-hint", []string{"b", "a"})
	b := BuildQuoteFingerprint("deal-hint", []string{"a", "b"})
	if a != b {
		t.Fatalf("order should not matter: %s vs %s", a, b)
	}
	if a == BuildQuoteFingerprint("other", []string{"a", "b"}) {
		t.Fatal("hint should change fingerprint")
	}
	if !strings.HasPrefix(a, "0x") {
		t.Fatalf("expected hex hash, got %q", a)
	}
}

func TestParseTokenToBaseUnits(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"", "", true},
		{"1", "1000000000000000000", false},
		{"0.5", "500000000000000000", false},
		{".25", "250000000000000000", false},
		{"1.5", "1500000000000000000", false},
		{"0.000000000000000001", "1", false},
		{"1.123456789012345678901234567890", "1123456789012345678", false}, // frac truncated to 18 digits
		{"not-a-number", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTokenToBaseUnits(tc.in)
			if tc.err {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestBaseUnitsString(t *testing.T) {
	if BaseUnitsString(nil) != "0" {
		t.Fatal("nil")
	}
	if BaseUnitsString(big.NewInt(99)) != "99" {
		t.Fatal("value")
	}
}

func TestFormatTokenValue(t *testing.T) {
	if FormatTokenValue(nil) != "0" {
		t.Fatal("nil")
	}
	one := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if FormatTokenValue(one) != "1.000000" {
		t.Fatalf("got %q", FormatTokenValue(one))
	}
	half := new(big.Int).Div(one, big.NewInt(2))
	if FormatTokenValue(half) != "0.500000" {
		t.Fatalf("got %q", FormatTokenValue(half))
	}
}

func TestEstimateStubPriceBaseUnits(t *testing.T) {
	per := big.NewInt(1000)
	if EstimateStubPriceBaseUnits(per, 3).Cmp(big.NewInt(3000)) != 0 {
		t.Fatal("3 pieces")
	}
	if EstimateStubPriceBaseUnits(nil, 2).Sign() != 0 {
		t.Fatal("nil per-piece")
	}
}

func TestParsePerPieceBaseUnits(t *testing.T) {
	got, err := ParsePerPieceBaseUnits("")
	if err != nil || got.Sign() != 0 {
		t.Fatalf("empty: %v %s", err, got)
	}
	got, err = ParsePerPieceBaseUnits("1000000000000000")
	if err != nil || got.Cmp(big.NewInt(1000000000000000)) != 0 {
		t.Fatalf("integer: %v %s", err, got)
	}
	got, err = ParsePerPieceBaseUnits("0.001")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(1000000000000000)) != 0 {
		t.Fatalf("decimal 0.001: got %s", got)
	}
	if _, err := ParsePerPieceBaseUnits("abc"); err == nil {
		t.Fatal("expected invalid")
	}
}

func TestEncodeHTTPRoundTripPreservesFields(t *testing.T) {
	ph, _ := testPaymentHeader(t)
	enc, err := ph.EncodeHTTP()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeHTTP(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.DealID != ph.DealID || dec.RailID != ph.RailID || dec.Signature != ph.Signature {
		t.Fatalf("mismatch: %+v vs %+v", dec, ph)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["v"] != float64(Version) {
		t.Fatalf("version %v", m["v"])
	}
}

package paymentheader

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := crypto.FromECDSA(key)

	ph := &PaymentHeader{
		Version:      Version,
		DealID:       "deal-1",
		RailID:       "rail-1",
		RequestID:    "req-1",
		Pieces:       []string{"bafy1", "bafy2"},
		AmountWei:    "42",
		DeadlineUnix: time.Now().Add(time.Hour).Unix(),
	}
	if err := ph.Sign(common.Bytes2Hex(pk)); err != nil {
		t.Fatal(err)
	}
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
		Version:      Version,
		DealID:       "deal-1",
		RailID:       "rail-1",
		RequestID:    "req-1",
		Pieces:       []string{"a", "b"},
		AmountWei:    "1",
		DeadlineUnix: time.Now().Add(time.Hour).Unix(),
	}
	if err := ph.Sign(pk); err != nil {
		t.Fatal(err)
	}
	ph.Pieces = []string{"a", "c"}
	if err := ph.Verify(time.Now().Unix()); err == nil {
		t.Fatal("expected tamper failure")
	}
}

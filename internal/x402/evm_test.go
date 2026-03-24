package x402

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestEVMSignVerifyRoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey).Hex()
	msg := []byte("hello filecoin pay x402")
	st, sig, err := SignEVM(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if st != SigTypeEVM {
		t.Fatalf("sig type %q", st)
	}
	if err := (EVMVerifier{}).Verify(addr, msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestEVMVerifierWrongKey(t *testing.T) {
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(k1.PublicKey).Hex()
	msg := []byte("payload")
	_, sig, err := SignEVM(k2, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := (EVMVerifier{}).Verify(addr, msg, sig); err == nil {
		t.Fatal("expected verify error")
	}
}

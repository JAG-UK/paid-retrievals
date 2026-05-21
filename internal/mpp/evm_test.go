package mpp

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSignEVMVerifyRoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(key.PublicKey).Hex()
	msg := []byte("mpp-canonical-message")

	sigType, sig, err := SignEVM(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sigType != SigTypeEVM {
		t.Fatalf("sigType = %q, want %q", sigType, SigTypeEVM)
	}

	var v EVMVerifier
	if err := v.Verify(client, msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignEVMNilKey(t *testing.T) {
	_, _, err := SignEVM(nil, []byte("msg"))
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestEVMVerifierErrors(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(key.PublicKey).Hex()
	msg := []byte("msg")
	_, sig, err := SignEVM(key, msg)
	if err != nil {
		t.Fatal(err)
	}

	var v EVMVerifier

	tests := []struct {
		name    string
		client  string
		sig     string
		wantErr string
	}{
		{
			name:    "invalid client address",
			client:  "not-an-address",
			sig:     sig,
			wantErr: "invalid 0x client address",
		},
		{
			name:    "short signature",
			client:  client,
			sig:     "0x01",
			wantErr: "evm signature must be 65 bytes",
		},
		{
			name:    "wrong signer",
			client:  "0x1111111111111111111111111111111111111111",
			sig:     sig,
			wantErr: "signature does not match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Verify(tc.client, msg, tc.sig)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestEVMVerifierInvalidSignatureBytes(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(key.PublicKey).Hex()

	var v EVMVerifier
	badSig := common.Bytes2Hex(make([]byte, 65))
	if err := v.Verify(client, []byte("msg"), badSig); err == nil {
		t.Fatal("expected ecrecover error")
	}
}

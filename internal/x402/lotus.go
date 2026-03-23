package x402

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// LotusSigner calls lotus CLI to sign canonical message bytes.
type LotusSigner struct {
	Binary string
}

// LotusVerifier calls lotus CLI to verify signature against a Filecoin address.
type LotusVerifier struct {
	Binary string
}

func (s LotusSigner) Sign(clientAddr string, msg []byte) (sigType string, signature string, err error) {
	bin := strings.TrimSpace(s.Binary)
	if bin == "" {
		bin = "lotus"
	}
	msgHex := hex.EncodeToString(msg)
	cmd := exec.Command(bin, "wallet", "sign", clientAddr, msgHex)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("lotus sign: %w: %s", err, strings.TrimSpace(string(out)))
	}
	sigType, signature, err = parseLotusSignatureOutput(out)
	if err != nil {
		return "", "", err
	}
	return sigType, signature, nil
}

func (v LotusVerifier) Verify(clientAddr string, msg []byte, signature string) error {
	bin := strings.TrimSpace(v.Binary)
	if bin == "" {
		bin = "lotus"
	}
	msgHex := hex.EncodeToString(msg)
	cmd := exec.Command(bin, "wallet", "verify", clientAddr, msgHex, signature)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("lotus verify: %w: %s", err, strings.TrimSpace(string(out)))
	}
	res := strings.ToLower(strings.TrimSpace(string(out)))
	if strings.Contains(res, "false") || strings.Contains(res, "invalid") {
		return fmt.Errorf("invalid signature")
	}
	if !strings.Contains(res, "true") && !strings.Contains(res, "valid") {
		return fmt.Errorf("unable to confirm lotus verify output: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func parseLotusSignatureOutput(out []byte) (sigType, sig string, err error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return "", "", fmt.Errorf("empty lotus signature output")
	}
	// Newer lotus output can be JSON object like {"Type":1,"Data":"..."}.
	var obj struct {
		Type any    `json:"Type"`
		Data string `json:"Data"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &obj) == nil && obj.Data != "" {
		typeName := "lotus"
		switch fmt.Sprint(obj.Type) {
		case "1":
			typeName = "secp256k1"
		case "2":
			typeName = "bls"
		}
		return typeName, obj.Data, nil
	}
	// Fallback: plain signature line
	return "lotus", trimmed, nil
}

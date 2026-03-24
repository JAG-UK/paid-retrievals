package spproxy

import (
	"context"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// FilecoinPaySettler checks rails / payer balance and submits settleRail (native FIL).
type FilecoinPaySettler interface {
	SettleIfFunded(ctx context.Context, payer, payee common.Address, priceWei *big.Int) (txHash string, err error)
}

func sameHexAddress(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if !common.IsHexAddress(a) || !common.IsHexAddress(b) {
		return false
	}
	return common.HexToAddress(a) == common.HexToAddress(b)
}

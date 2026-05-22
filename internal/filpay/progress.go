package filpay

import "time"

// TxProgress receives Filecoin Pay transaction lifecycle updates for CLI progress.
type TxProgress interface {
	TxSubmitted(op, txHash string)
	TxWaiting(op, txHash string, elapsed time.Duration)
	TxConfirmed(op, txHash string, elapsed time.Duration, block string)
}

// WithTxProgress attaches a reporter invoked from waitTxMined.
func WithTxProgress(p TxProgress) Option {
	return func(c *Client) {
		c.txProgress = p
	}
}

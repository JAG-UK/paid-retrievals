package filpay

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// paymentsRailsTransactor submits payments-contract writes that are otherwise issued via
// bind.NewBoundContract (createRail, modifyRailPayment, modifyRailLockup, withdraw).
type paymentsRailsTransactor interface {
	CreateTokenRail(ctx context.Context, opts *bind.TransactOpts, payer, payee common.Address) (*types.Transaction, error)
	ModifyRailPayment(ctx context.Context, opts *bind.TransactOpts, railID, oneTimePayment *big.Int) (*types.Transaction, error)
	ModifyRailLockup(ctx context.Context, opts *bind.TransactOpts, railID, period, lockupFixed *big.Int) (*types.Transaction, error)
	WithdrawToken(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error)
}

// ethBoundRails uses the connected eth client and payments contract address.
type ethBoundRails struct {
	c *Client
}

func (c *Client) railsTransactor() (paymentsRailsTransactor, error) {
	if c.rails != nil {
		return c.rails, nil
	}
	if c.eth == nil {
		return nil, errors.New("filpay: no eth client for payments transacts")
	}
	return &ethBoundRails{c: c}, nil
}

func (c *Client) transactOpts(ctx context.Context) (*bind.TransactOpts, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return nil, fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	return opts, nil
}

func (r *ethBoundRails) boundContract(abiJSON string) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(r.c.paymentsAddr, parsed, r.c.eth, r.c.eth, r.c.eth), nil
}

func (r *ethBoundRails) CreateTokenRail(ctx context.Context, opts *bind.TransactOpts, payer, payee common.Address) (*types.Transaction, error) {
	bound, err := r.boundContract(createRailABIJSON)
	if err != nil {
		return nil, fmt.Errorf("filpay: parse createRail ABI: %w", err)
	}
	return bound.Transact(opts, "createRail", r.c.paymentToken, payer, payee, common.Address{}, big.NewInt(0), common.Address{})
}

func (r *ethBoundRails) ModifyRailPayment(ctx context.Context, opts *bind.TransactOpts, railID, oneTimePayment *big.Int) (*types.Transaction, error) {
	bound, err := r.boundContract(modifyRailPaymentABIJSON)
	if err != nil {
		return nil, fmt.Errorf("filpay: parse modifyRailPayment ABI: %w", err)
	}
	return bound.Transact(opts, "modifyRailPayment", railID, big.NewInt(0), oneTimePayment)
}

func (r *ethBoundRails) ModifyRailLockup(ctx context.Context, opts *bind.TransactOpts, railID, period, lockupFixed *big.Int) (*types.Transaction, error) {
	bound, err := r.boundContract(modifyRailLockupABIJSON)
	if err != nil {
		return nil, fmt.Errorf("filpay: parse modifyRailLockup ABI: %w", err)
	}
	return bound.Transact(opts, "modifyRailLockup", railID, period, lockupFixed)
}

func (r *ethBoundRails) WithdrawToken(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	bound, err := r.boundContract(withdrawABIJSON)
	if err != nil {
		return nil, fmt.Errorf("filpay: parse withdraw ABI: %w", err)
	}
	return bound.Transact(opts, "withdraw", r.c.paymentToken, amount)
}

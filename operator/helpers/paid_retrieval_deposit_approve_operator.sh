#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RPC_URL="https://api.calibration.node.glif.io/rpc/v1"
PRIVATE_KEY=""
FILECOIN_PAY="0x09a0fDc2723fAd1A7b8e3e00eE5DF73841df55a0"
TOKEN="0xb3042734b608a1B16e9e86B374A3f3e389B4cDf0"
TOKEN_DECIMALS="18"
OPERATOR=""

DEPOSIT_AMOUNT_INPUT="${1:-2}"

CLIENT_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")
MAX_UINT256=$(cast max-uint uint256)

BALANCE=$(cast call \
  --rpc-url "$RPC_URL" \
  "$TOKEN" \
  "balanceOf(address)(uint256)" \
  "$CLIENT_ADDR" | awk '{print $1}')

read -r V R S DEPOSIT_AMOUNT PERMIT_DEADLINE < <(
  node "$SCRIPT_DIR/sign_permit.js" "$RPC_URL" "$PRIVATE_KEY" "$TOKEN" "$FILECOIN_PAY" "$DEPOSIT_AMOUNT_INPUT" "$TOKEN_DECIMALS" \
  | jq -r '[.v, .r, .s, .amount, .deadline] | @tsv'
)

if node -e "process.exit(BigInt(process.argv[1]) < BigInt(process.argv[2]) ? 0 : 1)" "$BALANCE" "$DEPOSIT_AMOUNT"; then
    echo "ERROR: insufficient token balance — need $DEPOSIT_AMOUNT, have $BALANCE" >&2
    exit 1
fi

echo "=== Paid Retrievals: Deposit + Operator Approval ==="
echo "  RPC=$RPC_URL"
echo "  Client=$CLIENT_ADDR"
echo "  Token=$TOKEN ($TOKEN_DECIMALS decimals)"
echo "  FilecoinPay=$FILECOIN_PAY"
echo "  Operator=$OPERATOR"
echo "  Balance=$BALANCE"
echo "  Deposit=$DEPOSIT_AMOUNT  Deadline=$PERMIT_DEADLINE"
echo "  Permit sig: v=$V r=$R s=$S"

cast send \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --gas-limit 9000000000 \
  --timeout 300 \
  "$FILECOIN_PAY" \
  "depositWithPermitAndApproveOperator(address,address,uint256,uint256,uint8,bytes32,bytes32,address,uint256,uint256,uint256)" \
  "$TOKEN" \
  "$CLIENT_ADDR" \
  "$DEPOSIT_AMOUNT" \
  "$PERMIT_DEADLINE" \
  "$V" "$R" "$S" \
  "$OPERATOR" \
  "$MAX_UINT256" \
  "$MAX_UINT256" \
  "$MAX_UINT256"

echo "=== Transaction completed ==="

ACCT_FUNDS=$(cast call \
  --rpc-url "$RPC_URL" \
  "$FILECOIN_PAY" \
  "accounts(address,address)(uint256,uint256,uint256,uint256)" \
  "$TOKEN" "$CLIENT_ADDR" | head -1)

APPROVAL_RESULT=$(cast call \
  --rpc-url "$RPC_URL" \
  "$FILECOIN_PAY" \
  "operatorApprovals(address,address,address)(bool,uint256,uint256,uint256,uint256,uint256)" \
  "$TOKEN" "$CLIENT_ADDR" "$OPERATOR")

echo "  Funds=$ACCT_FUNDS"
echo "  Approved=$(echo "$APPROVAL_RESULT" | sed -n '1p')"
echo "  RateAllowance=$(echo "$APPROVAL_RESULT" | sed -n '2p')"
echo "  LockupAllowance=$(echo "$APPROVAL_RESULT" | sed -n '3p')"
echo "  MaxLockup=$(echo "$APPROVAL_RESULT" | sed -n '6p')"

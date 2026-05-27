# Local stack E2E (black-box)

Builds and runs real `sp-proxy` and `retrieval-client` binaries against **Docker nginx** as the upstream piece server.

## Prerequisites

- Go 1.22+
- Docker (daemon running)
- Network access to Calibration RPC (`https://api.calibration.node.glif.io/rpc/v1`) for tests that start `sp-proxy` or run non–dry-run `fetch`

## Run

```bash
# HTTP + dry-run stack (ephemeral keys; no faucet)
go test -v -tags=e2e_stack -count=1 -timeout=15m ./test/e2e/stack/...

# or
task test:e2e:stack
```

Stream subprocess logs live (sp-proxy and retrieval-client):

```bash
E2E_DEBUG=1 task test:e2e:stack
```

Optional: use pre-built binaries:

```bash
export RETRIEVAL_CLIENT_BIN=./bin/retrieval-client
export SP_PROXY_BIN=./bin/sp-proxy
task test:e2e:stack
```

## Test tiers

| Test | Funding required |
|------|------------------|
| Proxy health, HEAD, 402 challenge | No (ephemeral SP key) |
| Client `fetch --dry-run` via proxy | No |
| Client free download direct to nginx | No (RPC only) |
| **Calibration paid fetch** (`TestStack_Calibration*`) | Yes — see below |

## Paid fetch on Calibration

Full black-box flow: nginx → `sp-proxy` (402 + settle) → `retrieval-client` (`rail-check`, then `fetch --yes` with Filecoin Pay on Calibration).

```bash
export E2E_CALIBRATION=1
task test:e2e:stack:calibration
```

On first run, missing keys under `test/e2e/.keys/` are created automatically (`openssl rand -hex 32`, same as the repo README). The test then fails with **faucet links and `0x` addresses** until both wallets are funded.

To reuse existing keys instead:

```bash
mkdir -p test/e2e/.keys
cp /path/to/client.key test/e2e/.keys/client.key
cp /path/to/sp.key test/e2e/.keys/sp.key
```

Or run only the Calibration tests while still running the default stack suite:

```bash
export E2E_CALIBRATION=1
go test -v -tags=e2e_stack -count=1 -timeout=25m -run 'TestStack_Calibration' ./test/e2e/stack/...
```

### Calibration tests

| Test | What it does |
|------|----------------|
| `TestStack_CalibrationRailCheck` | `rail-check` against live proxy; fails if USDFC balance insufficient |
| `TestStack_CalibrationPaidFetchFull` | Full `fetch --yes`: on-chain prepare/charge/settle + download CAR |

Override key paths:

```bash
export E2E_CLIENT_KEY_FILE=/path/to/client.key
export E2E_SP_KEY_FILE=/path/to/sp.key
```

Override RPC (default Glif Calibration):

```bash
export E2E_CALIBRATION_RPC=https://api.calibration.node.glif.io/rpc/v1
```

If balances are too low, tests **fail** with wallet `0x` addresses and faucet URLs (keys are auto-created if absent).

Fund wallets manually (FIL + USDFC on client) using the faucets in the repo root [README](../../../README.md).

The client needs **tFIL** (gas) and **USDFC in its EVM wallet** (≥ ~0.01 USDFC per piece). USDFC in the wallet is enough — `fetch` deposits into Filecoin Pay automatically; you do not need to pre-deposit into Filecoin Pay.

**Use the exact `0x` addresses from the test failure** (keys in `test/e2e/.keys/`). Funding a Lotus `f1`/`f4` address or a different key file will not help.

The SP key used for `sp-proxy` must be the settler/payee wallet advertised in 402 challenges (default: proxy derives payee from that key).

## Fixture

Upstream serves a small CAR body (`DUMMY-CAR-DATA`, 14 bytes) for any `/piece/<cid>` path. CID used in tests: `bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e`.

## CI

Stack tests are **not** run in GitHub Actions (no Docker faucet flow). Fast client-only E2E remains at `task test:e2e`.

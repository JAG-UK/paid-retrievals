# retrieval-client black-box E2E tests

These tests build `cmd/retrieval-client` and run it as a subprocess (`os/exec`). They live in package `retrievalclient_test` so they cannot import `main` or use in-process hooks.

## Run

```bash
go test -v -count=1 ./test/e2e/retrievalclient/...
# or
task test:e2e
```

To stream retrieval-client subprocess stdout/stderr during tests:

```bash
E2E_DEBUG=1 task test:e2e
```

Set `RETRIEVAL_CLIENT_BIN` to skip the build step and use an existing binary.

## Scope

| Scenario | Notes |
|----------|--------|
| `--help`, flag validation | No network |
| `fetch --dry-run` + `--sp-base-url` | Local `httptest` SP; no Filecoin Pay RPC |
| Prompt abort (`n`) | Stops before chain prep |

Full paid fetch (Filecoin Pay + download) on Calibration is in `test/e2e/stack` (`task test:e2e:stack`, requires Docker; funded keys optional). Gray-box tests with stubs remain in `cmd/retrieval-client`.

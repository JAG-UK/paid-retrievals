# Retrieval client UX improvement plan

Plan for improving CLI UX of `retrieval-client` when Filecoin Pay transactions typically take ~30 seconds and CAR downloads are large and long-running.

## Current experience

| Phase | Typical duration | Default feedback |
|-------|------------------|------------------|
| Discovery + SP probing | Seconds–minutes (many bases) | Nothing |
| Quote | Instant | One line: total USDFC |
| **Prepare rails** (approve, deposit, createRail, …) | Often **~30s per tx** | Nothing |
| Confirm (`[y/N]`) | — | **After prepare** |
| Charge (`modifyRailPayment`) | ~30s per payee | Nothing |
| Download (`io.Copy`) | Minutes–hours for large CARs | `stored <path>` only at end |

Notes on today’s implementation:

- Default output is minimal; detail is mostly behind `--verbose` and `--pay-debug`.
- `downloadCAR` uses `io.Copy` with no progress reporting.
- `waitTxMined` in `internal/filpay` logs operation and tx hash only when filpay logging is enabled.
- `prepareRailsForChallenges` runs **before** the interactive prompt (see `cmd/retrieval-client/main.go` around the prepare → `promptYesNo` sequence).

---

## Goals

1. Users always know **which slow phase** is running (discovery, chain, download).
2. No on-chain work before explicit confirmation (unless `--yes`).
3. Long waits show **elapsed time**, **tx identity**, and **download bytes/rate** where possible.
4. Automation-friendly output without breaking human TTY use.

---

## High impact (do first)

### 1. Confirm before any on-chain writes

**Problem:** First-time users can wait through several ~30s calibration txs during prepare, then answer “no” at the prompt.

**Target flow:**

1. Probe → build quote (payees, per-CID price, free vs paid, chosen SP).
2. **Prompt** (or require `--yes` for non-interactive).
3. Prepare → charge → download.

**Also add:** `--dry-run` or `fetch --quote-only` that stops after step 1 (richer than `rail-check` for manifests: prices and endpoints without mutating chain state).

### 2. One default progress mode on TTY (not three flags)

Keep `--verbose` and `--pay-debug` for support, but add **`--progress`** (default **on** when stdout/stderr is a terminal):

| Phase | Example message |
|-------|-----------------|
| Discover | `Discovering SP bases for CID …` |
| Quote | `Quoting N pieces…` |
| Prepare | `Preparing payment (payee 1/2)…` |
| Charge | `Charging rail for payee …` |
| Download | `Downloading CID … (2/5)…` |

**Chain sub-status:** after each submit, e.g. `waiting for createRail (tx 0xabc…, ~30s on calibration)`.

**Download sub-status:** if `Content-Length` is present: percent, bytes, rate, ETA; otherwise indeterminate progress + bytes written.

Use a small progress-bar library only when `term.IsTerminal`; use plain line logs when piped or in CI.

### 3. Surface tx wait in `filpay`, not only in debug

`waitTxMined` already knows `op` and `tx_hash` but only emits at `payInfo` when logging is configured.

**Proposal:** `filpay.ProgressReporter` (or slog handler) wired from the CLI to stderr:

- `submitted createRail tx=0x…`
- `waiting for confirmation (15s)…`
- `confirmed in 28s block=…`

Fixes the ~30s “black hole” without requiring `--pay-debug`.

### 4. Download progress in `downloadCAR`

Replace bare `io.Copy` with a counting writer:

- Show path, host, and expected size when known.
- Periodic updates (e.g. every 2s or 1%) for multi‑GiB runs.
- On failure: bytes written and whether a partial file remains.

**Optional:** write to `outPath.partial` then rename on success so retries are obvious.

### 5. Richer quote before commit

Before prompt, print a small table (human) or JSON (automation):

| CID | Source | Price | Payee |
|-----|--------|-------|-------|
| `bafk…` | `http://…` | 0.01 USDFC | `0x…` |
| `bafk…` | free | — | — |

Include:

- Estimated chain steps (“up to 3 txs, ~1–2 min”).
- Download summary when manifest exposes piece size (count / total bytes if known).

---

## Medium impact

### 6. Multi-piece overall progress

For manifests and many `--cid` values:

- `Piece 2/17: probing…`
- Running totals: paid vs free, USDFC so far, bytes downloaded.
- Start with **sequential** downloads; consider `--parallel-downloads` later.

### 7. Discovery / probe visibility

When probing many bases:

- `CID bafk…: 4 endpoints, probing 2/4…`
- On success: `selected free from …` or `selected paid 0.01 USDFC from …`

### 8. Machine-readable output

`--json-lines` or `--output json` for scripts and CI, e.g.:

```json
{"event":"tx_submitted","op":"createRail","hash":"0x…"}
{"event":"download_progress","cid":"…","bytes":1073741824,"total":34359738368}
{"event":"complete","path":"…"}
```

Keep human TTY UX separate from automation (no progress bars on non-TTY).

### 9. Timeouts and cancel

| Area | Approach |
|------|----------|
| Discovery | Keep bounded timeout (e.g. 90s) — already reasonable |
| Download | No global timeout for large CARs; honor **Ctrl+C** with clear message: CID, bytes on disk, whether payment already charged |
| Chain | Show elapsed vs `waitTxMined` timeout (~90s) so users can tell RPC stall from normal calibration delay |

### 10. Align `rail-check` and `fetch`

Reuse the same progress reporter and quote vocabulary so `rail-check` feels like “phase 0 of fetch.”

---

## Larger bets (when worth it)

| Idea | Benefit |
|------|---------|
| **Resume downloads** | Large win for 32 GiB+ if SP supports Range or safe restart from `.partial` |
| **`fetch plan` / `fetch run`** | Plan = probe + quote only; run = pay + download (ops-friendly) |
| **`--log-file`** | Full detail for tmux/CI without flooding TTY |
| **Web dashboard** | Only if CLI users are rare; prefer CLI progress first |

---

## What not to do

- **Web UI inside the client binary** — stderr progress + optional JSON is enough.
- **More overlapping debug flags** — prefer `--progress` (default on TTY) + `--debug` over asking users to choose `verbose` vs `pay-debug`.
- **Spinner-only with no phase labels** — users must know whether chain or download is slow.

---

## Implementation order

1. Move prompt before `prepareRailsForChallenges`; add optional `--dry-run` / quote-only. **Done**
2. TTY progress for phases + `waitTxMined` callbacks in `filpay`. **Done** (`--no-progress` to disable; default on TTY stderr)
3. Download byte progress + optional partial-file handling. **Done** (`.partial` rename; progress when TTY)
4. Quote table + multi-CID counters. **Done** (quote table; per-piece probe lines when progress on)
5. JSON output for automation. **Not started**

---

## Suggested interfaces (sketch)

```go
// cmd/retrieval-client — UI facade
type ProgressUI interface {
    Phase(msg string)
    TxSubmitted(op, txHash string)
    TxWaiting(op, txHash string, elapsed time.Duration)
    TxConfirmed(op, txHash string, elapsed time.Duration, block string)
    DownloadStart(cid, url string, totalBytes int64) // totalBytes < 0 if unknown
    DownloadProgress(cid string, written, total int64, rate float64)
    DownloadDone(cid, path string)
}

// internal/filpay — optional callback on Client
type TxProgress func(op, txHash string, state string, elapsed time.Duration)
```

Wire `ProgressUI` from `fetch` / `rail-check`; use `term.IsTerminal` to pick bar vs line mode; no-op implementation for tests and `--output json`.

---

## Success criteria

- Interactive fetch: user sees phase + progress within 2s of starting any step longer than ~5s.
- No chain txs before confirm unless `--yes` or non-interactive CI.
- 32 GiB download: periodic byte/rate updates without reading the whole file into memory.
- CI / integration tests: progress disabled or JSON-only; existing tests unchanged aside from prompt ordering.

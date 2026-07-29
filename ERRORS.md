# Errors: otfabric/go-otfp

How go-otfp reports detection failures. Type fields and API surface:
[API.md — Errors](API.md#errors). Definitions live in package `core`.

Fingerprinting has two distinct outcomes — do not treat them as interchangeable:

1. **No match** — the probe completed (or was skipped) and the target did not look
   like this protocol. Reported as a `Result` with `Matched=false` / low confidence,
   **not** as an `error`.
2. **Transport / detection error** — dial, timeout, or I/O failed while probing.
   Reported as a typed Go `error` (often also attached on `Result.Error`).

## Quick reference

| Situation | How it is reported |
|-----------|--------------------|
| Wrong / unknown protocol on the port | `Result` with `Matched=false` (`NoMatch`) — not an error |
| Dial timeout / deadline | `*TimeoutError` (`ClassifyDial`) |
| Dial refused / unreachable | `*ConnectionError` (`ClassifyDial`) |
| Send/receive timeout | `*TimeoutError` (`ClassifyIO`) |
| Other send/receive failure | `*DetectError` with `Op` (`ClassifyIO`) |
| Named protocol missing from registry | `*ProtocolNotFoundError` (`Engine.DetectProtocol`) |
| Malformed response (optional) | `*InvalidResponseError` — detectors usually prefer `NoMatch` |

Prefer:

```go
import (
    "errors"

    "github.com/otfabric/go-otfp/core"
)

result, err := engine.DetectProtocol(ctx, target, core.ProtocolModbus)
if err != nil {
    var pnf *core.ProtocolNotFoundError
    if errors.As(err, &pnf) {
        // protocol not registered
        return err
    }
}

if result.Error != nil {
    var te *core.TimeoutError
    var ce *core.ConnectionError
    var de *core.DetectError
    switch {
    case errors.As(result.Error, &te):
        // deadline / i/o timeout
    case errors.As(result.Error, &ce):
        // refused, unreachable, …
    case errors.As(result.Error, &de):
        // send/receive failure (see de.Op)
    }
}

if !result.Matched {
    // probed successfully; not this protocol
}
```

## Typed errors

| Type | Fields | Unwrap | Produced by |
|------|--------|--------|-------------|
| `TimeoutError` | `Protocol`, `Addr`, `Err` | ✓ | `ClassifyDial` / `ClassifyIO` on timeout |
| `ConnectionError` | `Protocol`, `Addr`, `Err` | ✓ | `ClassifyDial` on non-timeout dial failure |
| `DetectError` | `Protocol`, `Op`, `Err` | ✓ | `ClassifyIO` on non-timeout I/O (`Op`: `"sendreceive"`, `"phase1"`, …) |
| `ProtocolNotFoundError` | `Protocol` | — | `Engine.DetectProtocol` |
| `InvalidResponseError` | `Protocol`, `Reason` | — | Optional; not used by current detectors for mismatches |

## Classification helpers

Detectors call these instead of wrapping with `fmt.Errorf`:

```go
func ClassifyDial(protocol Protocol, addr string, err error) error
func ClassifyIO(protocol Protocol, addr, op string, err error) error
```

Timeouts are detected via `context.DeadlineExceeded`, `os.ErrDeadlineExceeded`,
and `net.Error` with `Timeout() == true`.

## CLI (`otprobe`)

JSON output maps typed errors to a short `error.type` string:
`timeout`, `connection`, `invalid_response`, `detection`, or `unknown`.
See `cmd/otprobe` `classifyError`.

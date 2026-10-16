# Changelog

## 0.2.0

### Added

- Hold for approval (Park). A request that a rule holds now waits for a person to approve it in Aarvion,
  then runs once and its response is saved, so an identical retry replays the response instead of running
  again. Same behaviour as the Python SDK.
- `ActionParked` (with `Wait`), `ActionInProgress` and `ActionAlreadyExecuted` errors, and the ticket on
  `PolicyDenied`, the `x-aarvion-park-ticket` header and `ticket` in blocked response bodies.
- `WithHold`, `WithHoldUntilDecision`, `AARVION_PARK_HOLD`, the agent's "Approval hold" in the dashboard and
  `hold` in `.aarvion.toml`, in that order. Default 50 seconds.
- An approved request that is sent, and a replayed one, each add an allowed row to the audit log naming the
  approval ticket.
- The request fingerprint and the approver summary match the control plane's shared test vectors.
- Every decision row now carries `sdk_version`, so the dashboard can tell this SDK can hold requests. The
  row hash is unchanged.

### Changed

- `Version` is now `0.2.0` (it still said `0.0.1` in 0.1.0).
- Bedrock keeps blocking a held request, because the AWS client cannot wait.

## 0.1.0

First public release of the Aarvion SDK for Go.

### Included

- `github.com/Aarvion-AI/aarvion-sdk-go`: config, local OPA with the signed policy bundle, PII masking, the
  provenance hash chain, `net/http` governance (`Wrap` and `Transport`) and the `aarvion` CLI (`init`,
  `whoami`, `check`, `status`). Go 1.22 or newer.
- `bedrock`: AWS SDK for Go v2 Bedrock Runtime middleware. Requests are checked and masked before SigV4
  signing. Go 1.24 or newer.
- `openai`: governed HTTP client for `openai-go`. Go 1.25 or newer.
- `anthropic`: governed HTTP client for `anthropic-sdk-go`. Go 1.24 or newer.

### Masking

- Masking uses the same patterns as the policy, with whole-value boundaries and ASCII digits, so parts of
  longer numbers or words are not masked.
- JSON bodies stay valid: only text values are rewritten, and a sensitive number becomes a quoted string.
- The output matches the Java SDK on the shared 6000-case test corpus.

### Known limits

See the [Known limits](README.md#known-limits) section of the README.

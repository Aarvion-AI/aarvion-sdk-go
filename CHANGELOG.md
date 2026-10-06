# Changelog

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

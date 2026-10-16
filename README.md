# Aarvion SDK for Go

The Aarvion developer data plane for Go. It governs your agent's LLM and HTTP calls locally,
against the same signed policies your production sidecar enforces.

This follows the Python SDK (`aarvion-sdk-python`). It makes the same server calls, uses the same
defaults, environment variables and messages, and writes the same provenance chain. The places where it
behaves differently are listed under [Differences from the Python SDK](#differences-from-the-python-sdk).

The SDK is dev, test and CI tooling. Production enforcement stays with the sidecar. SDK decisions are
tagged `source: sdk` (dp_id `sdk`).

## Status

Alpha, version 0.2.0.

## Modules

| Module | Go | What it is |
|---|---|---|
| `github.com/Aarvion-AI/aarvion-sdk-go` | 1.22 | Core: config, local OPA runtime, enforcement, provenance, `net/http` governance, CLI |
| `github.com/Aarvion-AI/aarvion-sdk-go/bedrock` | 1.24 | AWS SDK for Go v2 Bedrock Runtime middleware |
| `github.com/Aarvion-AI/aarvion-sdk-go/openai` | 1.25 | Governed HTTP client for `openai-go` |
| `github.com/Aarvion-AI/aarvion-sdk-go/anthropic` | 1.24 | Governed HTTP client for `anthropic-sdk-go` |
| `github.com/Aarvion-AI/aarvion-sdk-go/examples` | 1.25 | Small runnable examples |

The core only needs `BurntSushi/toml` and `modernc.org/sqlite` (pure Go, no cgo). The add-on modules
need newer Go versions because the AWS, OpenAI and Anthropic SDKs do.

## Install

```bash
go get github.com/Aarvion-AI/aarvion-sdk-go@v0.2.0
go install github.com/Aarvion-AI/aarvion-sdk-go/cmd/aarvion@v0.2.0
```

Add the module for each client you use:

```bash
go get github.com/Aarvion-AI/aarvion-sdk-go/bedrock@v0.2.0
go get github.com/Aarvion-AI/aarvion-sdk-go/openai@v0.2.0
go get github.com/Aarvion-AI/aarvion-sdk-go/anthropic@v0.2.0
```

## Quickstart

Connect an agent once. This writes `.aarvion.toml` (mode 0600) in the current folder:

```bash
aarvion init --api-key aav_org_... --agent my-agent
```

Then in your agent:

```go
session, err := aarvion.Init()
if err != nil {
	log.Fatal(err)
}
defer session.Close()

client, err := aarvion.Wrap(&http.Client{})
if err != nil {
	log.Fatal(err)
}
resp, err := client.Post(url, "application/json", body)
```

`Init` resolves the config, starts a local OPA with your agent's signed bundle, opens the local
provenance queue and makes the session active. `Wrap` puts the governance step in front of the
client's transport. To govern an existing transport instead, use `aarvion.Transport(inner)`.

### Always call Close

Python flushes the decision queue at exit with an `atexit` hook. Go has no exit hook, so call
`session.Close()` before your program ends (a `defer` in `main` is enough). `Close` flushes queued
decisions, stops OPA and closes the queue. If you only want to push decisions, call
`session.Flush()`. A background flush also runs every 5 seconds while the session is open.

## What happens to a request

1. The SDK builds the same `ext_authz` input the sidecar uses (method, host, path without the
   query string, headers, whole body) and asks the local OPA for `data.envoy.authz.allow`.
2. Deny: the request is not sent. Your client gets a `403` response with the same headers and JSON
   body the sidecar returns (`x-policy-violated`, `x-policy-reason`, `x-aarvion-policies-violated`).
   When the rule says "hold for approval", the request waits for a person instead (see
   [Hold for approval](#hold-for-approval-park)).
3. Allow with redactions: PII in the body is replaced or masked before it leaves your process.
4. Every decision is written to a local hash chain (`provenance.db`) and pushed to the control plane.

Bodies larger than `AARVION_MAX_BODY_BYTES` (16 MiB by default) are denied with policy
`sdk.body_inspection_limit` and status 413.

### Monitor mode

```go
session, err := aarvion.Init(aarvion.WithMonitor(true))
```

Denies are recorded with `enforced=false` and the request is sent. Allowed requests are still
redacted, the same as in Python.

## Hold for approval (Park)

Some rules hold a request for a person to approve instead of blocking it. The SDK then:

1. Makes a fingerprint of the exact request (method, host, path, query and body).
2. Asks the control plane whether it is already approved, or already ran.
3. If not, opens an approval ticket and waits (the agent's "Approval hold" in the dashboard, 50 seconds by default).
4. When a person approves it in the dashboard, sends the request once and saves the response.
   An identical later call gets the saved response with header `x-aarvion-replayed`, so it never runs twice.

| Outcome | What your code sees |
|---|---|
| Approved | The normal response |
| Denied, expired or cancelled | A `403` response with `x-aarvion-park-ticket` and `ticket` in the body |
| Still waiting when the hold ends | `*aarvion.ActionParked` error from `client.Do` |
| An identical approved call is running | `*aarvion.ActionInProgress` error |
| It already ran, response too large to keep | `*aarvion.ActionAlreadyExecuted` error |
| Control plane unreachable | A `503` response; nothing is sent |

```go
resp, err := client.Do(req)
var parked *aarvion.ActionParked
if errors.As(err, &parked) {
    ok, err := parked.Wait(ctx)
    if ok && err == nil {
        resp, err = client.Do(sameReq)
    }
}
```

The hold time comes from `WithHold(d)` or `WithHoldUntilDecision()`, then `AARVION_PARK_HOLD`, then the
agent's "Approval hold" in the dashboard, then `hold` in `.aarvion.toml`, then 50 seconds. The dashboard
value is read for every held request, so a change there applies about a minute later. `0` only opens the
ticket; `until_decision` waits until a person decides. Park must be turned on for the tenant in Aarvion.
Monitor mode never holds.

The audit log gets a row when a request is held (shown as Blocked). When the approved request is then sent,
a second row is written as allowed with "approved under ticket ..., sent (HTTP status)". A replay is written
as allowed with "replayed the saved result of approval ticket ..., not sent again".

## Init options

| Option | Python argument | Default |
|---|---|---|
| `WithAPIKey(key)` + `WithAgent(name)` | `api_key`, `agent` | not set: config is loaded instead |
| `WithAPIURL(url)` | `api_url` | `https://api.aarvion.ai` |
| `WithEvaluatorURL(url)` | `evaluator_url` | `AARVION_EVALUATOR_URL` |
| `WithPersist(bool)` | `persist` | `true` |
| `WithMonitor(bool)` | `monitor` | `false` |
| `WithStateDir(dir)` | `state_dir` | `~/.aarvion/<agent_id>` |
| `WithStartRuntime(bool)` | `start_runtime` | `true` |
| `WithHold(d)` / `WithHoldUntilDecision()` | `hold` | `AARVION_PARK_HOLD`, then the dashboard "Approval hold", then `hold` in the config, then 50 seconds |

## Configuration

The config is resolved in this order:

1. `AARVION_RUNTIME_KEY` is set: the key is resolved through the control plane at
   `AARVION_CP_URL` (default `https://cp.aarvion.ai`).
2. Otherwise the file at `AARVION_CONFIG`, or `.aarvion.toml` in the current folder.

Other environment variables:

| Variable | Meaning |
|---|---|
| `AARVION_OPA_PATH` | Use this OPA binary |
| `AARVION_OPA_AUTODOWNLOAD=0` | Do not download OPA when it is not on `PATH` |
| `AARVION_OPA_PORT` | Fixed port for the local OPA (default: a free port) |
| `AARVION_MAX_BODY_BYTES` | Body inspection limit |
| `AARVION_EVALUATOR_URL` | Evaluator for `GovernReply` |
| `AARVION_API_KEY` | Used by `aarvion init` when `--api-key` is not given |
| `AARVION_PARK_HOLD` | Seconds a held request waits for approval, or `until_decision` |

When OPA is not found, the SDK downloads OPA 1.17.1, checks its SHA-256 and keeps it in
`~/.aarvion/opa/1.17.1/`.

## Conversation and voice turns

```go
session, err := aarvion.Init(aarvion.WithEvaluatorURL("http://localhost:8090"))
reply, err := aarvion.GovernReply("call-42", 1, userText, draftReply, aarvion.WithIntent("balance"))
```

The reply you get back is the text to speak or show. If the evaluator cannot be reached, the draft
is returned unchanged (fail open), the same as Python.

## AWS Bedrock

```go
govern, err := aarvionbedrock.Govern()
client := bedrockruntime.NewFromConfig(cfg, govern)
```

`InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream` are governed before
the request is signed, so SigV4 covers the redacted body. A deny returns an error that holds an
`*aarvion.PolicyDenied`:

```go
var denied *aarvion.PolicyDenied
if errors.As(err, &denied) {
	fmt.Println(denied.PolicyID, denied.Reason)
}
```

## OpenAI and Anthropic

```go
client, err := aarvionopenai.NewClient(option.WithAPIKey(key))
client, err := aarvionanthropic.NewClient(option.WithAPIKey(key))
```

Both use the SDK's own `option.WithHTTPClient` with a governed `*http.Client`. You can also pass
`aarvionopenai.Option()` or `aarvionanthropic.Option()` to a client you build yourself.

A denied call comes back as a 403. `anthropic-sdk-go` turns it into its normal API error.
`openai-go` cannot read the sidecar's error body, so you get an error and can read the 403 status and
the policy headers with `option.WithResponseInto`.

## CLI

```bash
aarvion init --api-key aav_org_... [--agent NAME] [--api-url URL]
aarvion whoami
aarvion check --host api.openai.com [--method POST] [--path /] [--body TEXT | --body @file]
aarvion status [--state-dir DIR]
```

`check` exits with 3 when the request would be denied, so you can use it as a CI gate. The output,
exit codes and the written `.aarvion.toml` match the Python CLI.

## Differences from the Python SDK

These are the places where Go works differently:

- Masking uses the same patterns as the policy that detects the data, so only whole values are masked. For
  example, `25000` inside `250000` is not treated as a postal code, and only ASCII digits and spaces count.
  In a JSON body only text values are rewritten, and a sensitive number becomes a quoted string, so the body
  always stays valid JSON. This matches the Java SDK. The Python and Node SDKs and the sidecar still use
  looser patterns that can mask parts of longer numbers.

- No exit hook. Call `Close()` or `Flush()` yourself.
- `Wrap` governs a `*http.Client` (or `Transport` a `http.RoundTripper`). Go clients have no
  shared base type like `httpx.Client`, so OpenAI, Anthropic and Bedrock have their own modules.
- Bedrock clients cannot be changed after they are built, so you pass `Govern()` when you build the
  client (or per call). A deny comes back wrapped in the AWS operation error. A hold for approval is
  blocked the same way, as in Python's boto3 support, because the AWS client cannot wait for a person.
- `ActionParked.Wait` takes a `context.Context` instead of a timeout in seconds.
- The policy input headers are the headers set on the Go request. Python's `httpx` adds its own
  default headers (host, accept, user-agent and so on); Go adds those later in the transport.
- The call site is the first stack frame outside this SDK and `net/http`, as `file:line`.
- Strings in Go cannot hold some values Python can (for example lone surrogates), and an empty
  string is treated like Python's `None` for optional text such as `evaluator_url`.
- Files are read as UTF-8. Python reads them with the system code page on Windows.
- TOML errors come from `BurntSushi/toml`. Common messages are mapped to Python's wording, but the
  position can differ.
- Uncaught errors in the CLI print a short `Traceback` line, not a full Python traceback.

## Known limits

- The policy's postal code pattern matches any separate 5-digit number, so values such as a budget of `60000`
  are masked as postal codes.
- Path rules compare the path as sent, so changes in case, `//`, `%xx` encoding or `./` can get past a rule.
  This is the same in every SDK and the sidecar.
- Monitor mode on the dashboard records nothing for SDK agents. Use the `aarvion.WithMonitor(true)` init option instead.
- Use one running program per runtime key. Two programs on the same key write two provenance chains, and the
  dashboard then reports the chain as altered.

## Development

```bash
go vet ./... && go test ./...
```

Run this in the root and in `bedrock`, `openai`, `anthropic` and `examples`. The `go.work` file links the
folders, so the add-on modules use the local core while you work. Tests use local mock servers only. The
`go.mod` files list indirect dependencies without the `// indirect` marker, so `go mod tidy` will add those
markers back.

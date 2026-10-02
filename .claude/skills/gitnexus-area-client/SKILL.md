---
name: gitnexus-area-client
description: "Skill for the Client area of firmware_happymining. 30 symbols across 6 files."
---

# Client

30 symbols | 6 files | Cohesion: 83%

## When to Use

- Working with code in `agent/`
- Understanding how Classify, New, ValidateBaseURL work
- Modifying client-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/client/client.go` | Classify, New, ValidateBaseURL, isLoopbackHost, Heartbeat (+9) |
| `agent/internal/client/client_test.go` | TestErrorEnvelopeAndClassification, TestMalformedAndOversizedResponsesAreErrors, TestNetworkErrorsAndTimeoutsAreRetryable, TestOversizedResponseIsNotBuffered, TestRedirectsAreNotFollowed (+7) |
| `agent/internal/backoff/backoff.go` | ParseRetryAfter |
| `agent/internal/backoff/backoff_test.go` | TestParseRetryAfter |
| `agent/internal/credential/credential.go` | ValidToken |
| `agent/internal/credential/credential_test.go` | TestValidToken |

## Entry Points

Start here when exploring this area:

- **`Classify`** (Function) — `agent/internal/client/client.go:384`
- **`New`** (Function) — `agent/internal/client/client.go:134`
- **`ValidateBaseURL`** (Function) — `agent/internal/client/client.go:92`
- **`TestErrorEnvelopeAndClassification`** (Function) — `agent/internal/client/client_test.go:201`
- **`TestMalformedAndOversizedResponsesAreErrors`** (Function) — `agent/internal/client/client_test.go:143`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Classify` | Function | `agent/internal/client/client.go` | 384 |
| `New` | Function | `agent/internal/client/client.go` | 134 |
| `ValidateBaseURL` | Function | `agent/internal/client/client.go` | 92 |
| `TestErrorEnvelopeAndClassification` | Function | `agent/internal/client/client_test.go` | 201 |
| `TestMalformedAndOversizedResponsesAreErrors` | Function | `agent/internal/client/client_test.go` | 143 |
| `TestNetworkErrorsAndTimeoutsAreRetryable` | Function | `agent/internal/client/client_test.go` | 250 |
| `TestOversizedResponseIsNotBuffered` | Function | `agent/internal/client/client_test.go` | 179 |
| `TestRedirectsAreNotFollowed` | Function | `agent/internal/client/client_test.go` | 280 |
| `TestRequestBounds` | Function | `agent/internal/client/client_test.go` | 301 |
| `TestRequestShape` | Function | `agent/internal/client/client_test.go` | 118 |
| `TestTLSVerificationAndCAFile` | Function | `agent/internal/client/client_test.go` | 78 |
| `TestURLPolicy` | Function | `agent/internal/client/client_test.go` | 36 |
| `ParseRetryAfter` | Function | `agent/internal/backoff/backoff.go` | 91 |
| `TestParseRetryAfter` | Function | `agent/internal/backoff/backoff_test.go` | 67 |
| `ValidOperationID` | Function | `agent/internal/client/client.go` | 306 |
| `TestEnrollValidatesTheResponse` | Function | `agent/internal/client/client_test.go` | 333 |
| `ValidToken` | Function | `agent/internal/credential/credential.go` | 42 |
| `TestValidToken` | Function | `agent/internal/credential/credential_test.go` | 18 |
| `Heartbeat` | Method | `agent/internal/client/client.go` | 287 |
| `Self` | Method | `agent/internal/client/client.go` | 338 |

## How to Explore

1. `context({name: "Classify"})` — see callers and callees
2. `query({search_query: "client"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`

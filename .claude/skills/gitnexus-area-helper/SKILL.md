---
name: gitnexus-area-helper
description: "Skill for the Helper area of firmware_happymining. 27 symbols across 4 files."
---

# Helper

27 symbols | 4 files | Cohesion: 70%

## When to Use

- Working with code in `agent/`
- Understanding how TestClientReportsUnavailableHelper, TestEverythingIsDisabledByDefault, TestInvalidRequestsNeverReachACommand work
- Modifying helper-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/helper/helper_test.go` | TestClientReportsUnavailableHelper, TestEverythingIsDisabledByDefault, TestInvalidRequestsNeverReachACommand, TestSocketRefusesMalformedRequests, TestSocketRefusesOtherUsers (+10) |
| `agent/internal/helper/helper.go` | Execute, RebootMinutes, run, audit, DecodeRequest (+2) |
| `agent/internal/helper/socket.go` | Do, Invoke, ServeConn, reply |
| `agent/internal/execx/execx.go` | CallLog |

## Entry Points

Start here when exploring this area:

- **`TestClientReportsUnavailableHelper`** (Function) — `agent/internal/helper/helper_test.go:354`
- **`TestEverythingIsDisabledByDefault`** (Function) — `agent/internal/helper/helper_test.go:94`
- **`TestInvalidRequestsNeverReachACommand`** (Function) — `agent/internal/helper/helper_test.go:146`
- **`TestSocketRefusesMalformedRequests`** (Function) — `agent/internal/helper/helper_test.go:326`
- **`TestSocketRefusesOtherUsers`** (Function) — `agent/internal/helper/helper_test.go:312`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `TestClientReportsUnavailableHelper` | Function | `agent/internal/helper/helper_test.go` | 354 |
| `TestEverythingIsDisabledByDefault` | Function | `agent/internal/helper/helper_test.go` | 94 |
| `TestInvalidRequestsNeverReachACommand` | Function | `agent/internal/helper/helper_test.go` | 146 |
| `TestSocketRefusesMalformedRequests` | Function | `agent/internal/helper/helper_test.go` | 326 |
| `TestSocketRefusesOtherUsers` | Function | `agent/internal/helper/helper_test.go` | 312 |
| `TestSocketRoundTrip` | Function | `agent/internal/helper/helper_test.go` | 289 |
| `TestSwitchesAreIndependent` | Function | `agent/internal/helper/helper_test.go` | 113 |
| `Execute` | Function | `agent/internal/helper/helper.go` | 174 |
| `RebootMinutes` | Function | `agent/internal/helper/helper.go` | 171 |
| `TestCommandFailureIsReported` | Function | `agent/internal/helper/helper_test.go` | 230 |
| `TestRebootMinutesNeverEarlierThanAsked` | Function | `agent/internal/helper/helper_test.go` | 138 |
| `TestSwitchFileMustBeTrustworthy` | Function | `agent/internal/helper/helper_test.go` | 168 |
| `ServeConn` | Function | `agent/internal/helper/socket.go` | 39 |
| `DecodeRequest` | Function | `agent/internal/helper/helper.go` | 227 |
| `ParseArgs` | Function | `agent/internal/helper/helper.go` | 97 |
| `TestDecodeRequestIsStrict` | Function | `agent/internal/helper/helper_test.go` | 239 |
| `TestParseArgsAcceptsOnlyTheTwoShapes` | Function | `agent/internal/helper/helper_test.go` | 46 |
| `CallLog` | Method | `agent/internal/execx/execx.go` | 148 |
| `Do` | Method | `agent/internal/helper/socket.go` | 83 |
| `Invoke` | Method | `agent/internal/helper/socket.go` | 126 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Audit` | cross_community | 4 |
| `Run → Validate` | cross_community | 3 |
| `Run → Request` | cross_community | 3 |

## How to Explore

1. `context({name: "TestClientReportsUnavailableHelper"})` — see callers and callees
2. `query({search_query: "helper"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
